import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import github_audit_scanner as scanner


def make_args(**overrides):
    base = dict(
        target="", local=[], source="", remote=False, clone=False,
        repo=[], repos_file="", all=False, discover="", interactive=False,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


class RepoTargetTest(unittest.TestCase):
    def test_normalize_github_urls(self):
        cases = {
            "owner/repo": "owner/repo",
            "https://github.com/owner/repo": "owner/repo",
            "https://github.com/owner/repo/": "owner/repo",
            "https://github.com/owner/repo.git": "owner/repo",
            "http://www.github.com/owner/repo": "owner/repo",
            "https://github.com/owner/repo/tree/develop": "owner/repo",
            "https://github.com/owner/repo/blob/main/README.md": "owner/repo",
            "git@github.com:owner/repo.git": "owner/repo",
            "ssh://git@github.com/owner/repo.git": "owner/repo",
            "github.com/owner/repo": "owner/repo",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(scanner.normalize_repo_target(raw), expected)

    def test_normalize_rejects_invalid(self):
        for raw in ("", "owner", "https://gitlab.com/owner/repo",
                    "C:\\projets\\repo", "./repo"):
            with self.subTest(raw=raw):
                self.assertEqual(scanner.normalize_repo_target(raw), "")

    def test_classify_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            kind, value = scanner.classify_target(tmp)
            self.assertEqual(kind, "local")
            self.assertEqual(Path(value), Path(tmp))
        self.assertEqual(scanner.classify_target("https://github.com/a/b"),
                         ("remote", "a/b"))
        self.assertEqual(scanner.classify_target("C:\\absent\\repo"),
                         ("local", "C:\\absent\\repo"))
        self.assertEqual(scanner.classify_target("pas-une-cible"), ("", ""))

    def test_positional_local_target_becomes_local(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = make_args(target=tmp)
            scanner.apply_target_argument(args)
            self.assertEqual(args.local, [tmp])
            self.assertEqual(args.repo, [])

    def test_positional_remote_target_becomes_repo(self):
        args = make_args(target="https://github.com/owner/repo/tree/main")
        scanner.apply_target_argument(args)
        self.assertEqual(args.repo, ["owner/repo"])
        self.assertEqual(args.local, [])

    def test_target_conflicts_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = make_args(target=tmp, source="remote")
            with self.assertRaises(SystemExit):
                scanner.apply_target_argument(args)
        args = make_args(target="owner/repo", local=["."])
        with self.assertRaises(SystemExit):
            scanner.apply_target_argument(args)

    def test_source_local_without_local_uses_cwd(self):
        args = make_args(source="local")
        self.assertEqual(scanner.resolve_effective_source(args), "local")
        self.assertEqual(args.local, ["."])

    def test_repos_file_accepts_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "depots.txt"
            path.write_text(
                "# commentaire\n"
                "https://github.com/owner/repo\n"
                "git@github.com:autre/projet.git\n"
                "invalide\n",
                encoding="utf-8",
            )
            self.assertEqual(scanner.load_repo_list(path),
                             ["owner/repo", "autre/projet"])

    def test_resolve_input_path_falls_back_to_tool_dir(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                self.assertEqual(scanner.resolve_input_path("mots_cles.txt"),
                                 scanner.TOOL_DIR / "mots_cles.txt")
                self.assertEqual(scanner.resolve_input_path("absent.txt"),
                                 Path("absent.txt"))
            finally:
                os.chdir(old)

    def test_current_git_repo_is_scanned_by_default(self):
        old = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                (Path(tmp) / ".git").mkdir()
                args = make_args()
                scanner.maybe_scan_current_repo(args)
                self.assertEqual(args.local, ["."])
                explicit = make_args(all=True)
                scanner.maybe_scan_current_repo(explicit)
                self.assertEqual(explicit.local, [])
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
