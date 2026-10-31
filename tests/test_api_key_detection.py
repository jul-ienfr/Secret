import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import github_audit_scanner as scanner


PROVIDER_SAMPLES = [
    ("openai_api_key", "OPENAI_API_KEY=sk-proj-AbCdEf1234567890GhIjKlMn"),
    ("anthropic_api_key", "sk-ant-api03-AbCdEf1234567890GhIjKlMnOpQr"),
    ("google_api_key", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"),
    ("github_classic_token", "ghp_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"),
    ("gitlab_token", "glpat-" + "AbCdEf1234567890GhIj"),
    ("aws_access_key_id", "AKIAFAKEFAKEFAKEFAKE"),
    ("aws_secret_access_key",
     "AWS_SECRET_ACCESS_KEY=0123456789abcdef0123456789abcdef01234567"),
    ("stripe_secret_key", "sk_live_" + "FAKEFAKEFAKEFAKEFAKE1234"),
    ("sendgrid_api_key",
     "SG.FAKEFAKEFAKEFAKEFAKE12.FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE123"),
    ("slack_token", "xoxb-FAKEFAKEFAKE-FAKEFAKEFAKE-FAKEFAKEFAKE"),
    ("twilio_api_key", "SK" + "0123456789abcdef0123456789abcdef"),
    ("jwt_token",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmYWtlIn0.FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"),
    ("private_key_block", "-----BEGIN RSA PRIVATE KEY-----"),
    ("database_url_credentials",
     "postgresql://demo:FAKEPASSWORD123@db.example.local:5432/demo"),
]

OAUTH_SAMPLES = [
    ("google_oauth_client_secret",
     "CLIENT_SECRET=GOCSPX-AbCdEf1234567890GhIjKlMnOpQr"),
    ("google_oauth_refresh_token",
     "GOOGLE_REFRESH_TOKEN=1//AbCdEf1234567890GhIjKlMnOpQrStUvWxYz0123456789"),
    ("github_oauth_token",
     "GITHUB_OAUTH_TOKEN=gho_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"),
    ("gitlab_oauth_secret",
     "GITLAB_OAUTH_SECRET=gloas-AbCdEf1234567890GhIjKlMn"),
    ("azure_ad_client_secret",
     "AZURE_CLIENT_SECRET=Abc8Q~AbCdEf1234567890GhIjKlMnOpQrStUvW"),
    ("okta_api_token",
     "OKTA_API_TOKEN=00AbCdEf1234567890GhIjKlMnOpQrStUvWxYz1234"),
    ("auth0_client_secret",
     "AUTH0_CLIENT_SECRET=AbCdEf1234567890GhIjKlMnOpQrStUv"),
    ("facebook_app_secret",
     "FACEBOOK_APP_SECRET=0123456789abcdef0123456789abcdef"),
    ("oauth_client_secret",
     "MY_OAUTH_CLIENT_SECRET=AbCdEf1234567890GhIjKlMn"),
    ("oauth_refresh_token",
     "MY_REFRESH_TOKEN=AbCdEf1234567890GhIjKlMn"),
    ("oauth_access_token",
     "MY_ACCESS_TOKEN=AbCdEf1234567890GhIjKlMn"),
    ("oauth1_token_secret",
     "MY_OAUTH_TOKEN_SECRET=AbCdEf1234567890GhIjKlMn"),
    ("oauth_id_token",
     "MY_ID_TOKEN=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJmYWtlIn0."
     "AbCdEf1234567890GhIjKlMn"),
    ("oauth_camel_tokens",
     'const myAccessToken = "AbCdEf1234567890GhIjKlMn";'),
    ("oauth_authorization_code",
     "MY_AUTH_CODE=AbCdEf1234567890GhIjKlMn"),
    ("oauth_code_verifier",
     "MY_CODE_VERIFIER=AbCdEf1234567890GhIjKlMn"),
]

PLACEHOLDERS = [
    "OPENAI_API_KEY=your_openai_api_key_here",
    "API_KEY=changeme",
    "TOKEN=${GITHUB_TOKEN}",
    "SECRET_KEY=config.secret_key",
    'PASSWORD=os.getenv("DB_PASSWORD")',
    "API_KEY = get_api_key()",
    "PASSWORD = generate_password(12)",
    '"password": "{password}"',
    'json={"address": address, "password": password}',
    'SHORT_KEY="short"',
    "LOW_ENTROPY_TOKEN=aaaaaaaaaaaaaaaaaaaa",
    'api_key = "YOUR_API_KEY"',
]


class SecretDetectionTest(unittest.TestCase):
    def setUp(self):
        self._old_opts = dict(scanner.OPTS)
        self._old_custom = list(scanner.CUSTOM_SECRET_RULES)
        scanner.CUSTOM_SECRET_RULES.clear()
        scanner.OPTS.update({
            "secret_rule_categories": set(),
            "secret_skip_categories": set(),
            "secret_min_severity": "info",
            "secret_no_generic": False,
            "context": 0,
            "entropy": False,
        })

    def tearDown(self):
        scanner.OPTS.clear()
        scanner.OPTS.update(self._old_opts)
        scanner.CUSTOM_SECRET_RULES.clear()
        scanner.CUSTOM_SECRET_RULES.extend(self._old_custom)

    def rule_ids(self, line):
        return [hit["id"] for hit in scanner.detect_secrets(line)]

    def test_provider_formats_are_detected(self):
        for expected, line in PROVIDER_SAMPLES:
            with self.subTest(rule=expected):
                self.assertIn(expected, self.rule_ids(line))

    def test_oauth_formats_are_detected(self):
        for expected, line in OAUTH_SAMPLES:
            with self.subTest(rule=expected):
                self.assertEqual(
                    [h["id"] for h in scanner.detect_secrets(line)],
                    [expected])

    def test_oauth_category_filter(self):
        scanner.OPTS["secret_rule_categories"] = {"oauth"}
        self.assertIn(
            "github_oauth_token",
            self.rule_ids("GITHUB_OAUTH_TOKEN=gho_AbCdEf1234567890"
                          "GhIjKlMnOpQrStUvWxYz"))
        self.assertEqual(
            self.rule_ids("OPENAI_API_KEY=sk-proj-AbCdEf1234567890GhIjKlMn"),
            [])
        self.assertEqual(self.rule_ids('CLIENT_SECRET="your_client_secret"'), [])

    def test_placeholders_and_references_are_ignored(self):
        for line in PLACEHOLDERS:
            with self.subTest(line=line):
                self.assertEqual(self.rule_ids(line), [])

    def test_generic_assignments(self):
        cases = [
            ('API_KEY = "ma-cle-factice-de-test-12345"',
             "generic_api_key_assignment"),
            ('const apiKey = "a1b2c3d4e5f6g7h8";',
             "generic_camelcase_assignment"),
            ('DB_PASSWORD="S3cr3tP@ssw0rd"',
             "generic_password_assignment"),
            ('"client_secret": "AbC123xYz987QwE456"',
             "generic_api_key_assignment"),
            ("X-API-Key: AbC123xYz987QwE456",
             "generic_api_key_assignment"),
        ]
        for line, expected in cases:
            with self.subTest(line=line):
                self.assertIn(expected, self.rule_ids(line))

    def test_specific_rule_wins_over_generic(self):
        hits = scanner.detect_secrets(
            "OPENAI_API_KEY=sk-proj-AbCdEf1234567890GhIjKlMn")
        self.assertEqual([h["id"] for h in hits], ["openai_api_key"])

    def test_no_generic_option(self):
        scanner.OPTS["secret_no_generic"] = True
        self.assertEqual(self.rule_ids('API_KEY="AbC123xYz987QwE456"'), [])
        self.assertIn("openai_api_key",
                      self.rule_ids("sk-proj-AbCdEf1234567890GhIjKlMn"))

    def test_only_category(self):
        scanner.OPTS["secret_rule_categories"] = {"ai"}
        self.assertEqual(self.rule_ids("AKIAFAKEFAKEFAKEFAKE"), [])
        self.assertIn("openai_api_key",
                      self.rule_ids("sk-proj-AbCdEf1234567890GhIjKlMn"))

    def test_skip_category(self):
        scanner.OPTS["secret_skip_categories"] = {"payments"}
        self.assertEqual(self.rule_ids("sk_live_" + "FAKEFAKEFAKEFAKEFAKE1234"), [])
        self.assertIn("openai_api_key",
                      self.rule_ids("sk-proj-AbCdEf1234567890GhIjKlMn"))

    def test_min_severity(self):
        scanner.OPTS["secret_min_severity"] = "critical"
        self.assertEqual(self.rule_ids("AC" + "0123456789abcdef0123456789abcdef"), [])
        self.assertIn("github_classic_token",
                      self.rule_ids("ghp_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"))

    def test_entropy_respects_secret_filters(self):
        token = "Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lm"
        scanner.OPTS["entropy"] = True
        self.assertTrue(scanner.entropy_hits_for_line(
            token, respect_filters=True))
        scanner.OPTS["secret_no_generic"] = True
        self.assertEqual(scanner.entropy_hits_for_line(
            token, respect_filters=True), [])
        scanner.OPTS["secret_no_generic"] = False
        scanner.OPTS["secret_rule_categories"] = {"ai"}
        self.assertEqual(scanner.entropy_hits_for_line(
            token, respect_filters=True), [])
        scanner.OPTS["secret_rule_categories"] = set()
        scanner.OPTS["secret_min_severity"] = "high"
        self.assertEqual(scanner.entropy_hits_for_line(
            token, respect_filters=True), [])

    def test_custom_rules_file(self):
        payload = {
            "rules": [{
                "id": "acme_test_key",
                "provider": "ACME",
                "category": "custom",
                "severity": "critical",
                "regex": r"\bacme_[A-Za-z0-9]{20,}\b",
            }]
        }
        with tempfile.NamedTemporaryFile(
                "w", suffix=".json", delete=False, encoding="utf-8") as fh:
            json.dump(payload, fh)
            path = fh.name
        try:
            scanner.load_custom_secret_rules(path)
            self.assertIn("acme_test_key",
                          self.rule_ids("acme_AbCdEf1234567890GhIjKl"))
        finally:
            Path(path).unlink(missing_ok=True)

    def test_scan_file_masks_secret(self):
        secret = "sk-proj-AbCdEf1234567890GhIjKlMn"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            path.write_text(f"OPENAI_API_KEY={secret}\n", encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(secret, findings[0]["detail"])
        self.assertNotIn(secret, findings[0]["match_preview"])

    def test_context_is_masked(self):
        secret = "sk-proj-AbCdEf1234567890GhIjKlMn"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            path.write_text(
                f"OPENAI_API_KEY={secret}\nCOPY={secret}\n",
                encoding="utf-8")
            scanner.OPTS["context"] = 1
            findings = scanner.scan_file(path)
        self.assertEqual(len(findings), 2)
        for finding in findings:
            self.assertNotIn(secret, json.dumps(finding["context"]))

    def test_context_masks_filtered_secrets_too(self):
        openai = "sk-proj-AbCdEf1234567890GhIjKlMn"
        github = "ghp_AbCdEf1234567890GhIjKlMnOpQrStUvWxYz"
        scanner.OPTS["secret_rule_categories"] = {"ai"}
        scanner.OPTS["context"] = 1
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.env"
            path.write_text(
                f"OPENAI_API_KEY={openai}\nGITHUB_TOKEN={github}\n",
                encoding="utf-8")
            findings = scanner.scan_file(path)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(github, json.dumps(findings[0]["context"]))
        self.assertIn("MASKED", json.dumps(findings[0]["context"]))

    def test_history_line_masks_secret(self):
        secret = "sk-proj-AbCdEf1234567890GhIjKlMn"
        parts = scanner.check_line_secrets(f"OPENAI_API_KEY={secret}")
        self.assertEqual(len(parts), 1)
        self.assertNotIn(secret, parts[0]["detail"])
        self.assertNotIn(secret, parts[0]["match_preview"])

    def test_secret_targets_always_authorized(self):
        args = SimpleNamespace(authorized=False, reveal=False, token="x")
        self.assertTrue(scanner.authorize_secret_targets(
            args, ["alissawu/jevcaptcha"]))
        self.assertTrue(scanner.authorize_secret_targets(args, []))
        authorized = SimpleNamespace(authorized=True, reveal=False, token="x")
        self.assertTrue(scanner.authorize_secret_targets(
            authorized, ["owner/repo"]))
        reveal = SimpleNamespace(authorized=True, reveal=True, token="x")
        self.assertTrue(scanner.authorize_secret_targets(
            reveal, ["owner/repo"]))

    def test_reveal_defaults_true_and_config_can_disable(self):
        ap = argparse.ArgumentParser()
        ap.add_argument("--reveal", action=argparse.BooleanOptionalAction,
                        default=True)
        cfg_path = Path("_test_reveal.ini")
        cfg_path.write_text("[audit]\nreveal = false\n", encoding="utf-8")
        old_argv = sys.argv
        try:
            args = ap.parse_args([])
            self.assertTrue(args.reveal)
            sys.argv = ["scanner", "--config", str(cfg_path)]
            scanner.apply_config_file(args, ap, str(cfg_path))
            self.assertFalse(args.reveal)
            args_cli = ap.parse_args([])
            sys.argv = ["scanner", "--config", str(cfg_path), "--reveal"]
            scanner.apply_config_file(args_cli, ap, str(cfg_path))
            self.assertTrue(args_cli.reveal)
        finally:
            sys.argv = old_argv
            cfg_path.unlink(missing_ok=True)

    def test_sarif_and_csv_metadata(self):
        findings = scanner.detect_secrets(
            "OPENAI_API_KEY=sk-proj-AbCdEf1234567890GhIjKlMn")
        self.assertTrue(findings)
        finding = scanner._secret_finding(
            findings[0], "demo:app.env", repo="demo", source="remote")
        with tempfile.TemporaryDirectory() as tmp:
            sarif_path = Path(tmp) / "report.sarif"
            csv_path = Path(tmp) / "report.csv"
            scanner.write_sarif_report(sarif_path, [finding])
            scanner.write_csv_report(csv_path, [finding])
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            csv_text = csv_path.read_text(encoding="utf-8")
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["level"], "error")
        self.assertIn("provider", csv_text.splitlines()[0])
        self.assertIn("OpenAI", csv_text)


if __name__ == "__main__":
    unittest.main()
