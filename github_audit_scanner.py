"""
Scanner par MOTS-CLES + audit de secrets sur n'importe quel depot.

Deux modes :
1) Mode MOTS-CLES (celui que tu as demande) :
     - Tu mets tes mots-cles dans un fichier texte (un par ligne).
     - Le programme scanne un dossier local OU un depot GitHub (API, sans cloner).
     - Des qu'un mot-cle est trouve, il ecrit un FICHIER TEXTE de resultats
       avec : mot-cle trouve, endroit (fichier + ligne + repo), detail (ligne tronquee).

2) Mode SECRETS :
     - Detecte TOUS types d'API-Key / tokens / secrets exposes dans n'importe
       quel depot (local ou distant) :
       formats connus (OpenAI, AWS, GitHub, Stripe, Slack, Google...), identifiants
       OAuth/OIDC (client_secret, refresh_token, GitHub/Google/Azure/Okta/Auth0...)
       + heuristiques generiques (api_key = ..., tokens, mots de passe, JWT...).
     - Resultats masques par defaut, categories et severites filtrables.

Le mode SECRETS est toujours autorise : aucun controle de proprietaire ni
attestation. --authorized reste accepte pour compatibilite mais sans effet.
"""

import argparse
import configparser
import csv
import fnmatch
import json
import math
import os
import random
import re
import subprocess
import sys
import time
from bisect import bisect_right
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ---------------------------------------------------------------- regles secrets
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SECRET_CATEGORIES = {
    "ai": "IA / LLM",
    "cloud": "Cloud",
    "code": "Hebergement de code / CI",
    "payments": "Paiement",
    "comms": "Messagerie / communication",
    "social": "Reseaux sociaux",
    "devtools": "Services de developpement / SaaS",
    "observability": "Observabilite",
    "databases": "Bases de donnees / files",
    "auth": "Authentification / jetons",
    "oauth": "OAuth / OpenID Connect",
    "crypto": "Cles cryptographiques",
    "generic": "Heuristiques generiques",
    "custom": "Regles personnalisees",
}


def _rule(rule_id, provider, category, severity, regex, group=0, min_len=8,
          min_entropy=0.0, priority=100, require_mixed=False,
          allow_placeholder=False, check_reference=True, description=""):
    """Decrit une regle de detection (compilee plus bas dans SECRET_RULES)."""
    return {
        "id": rule_id,
        "provider": provider,
        "category": category,
        "severity": severity,
        "regex": regex,
        "group": group,
        "min_len": min_len,
        "min_entropy": min_entropy,
        "priority": priority,
        "require_mixed": require_mixed,
        "allow_placeholder": allow_placeholder,
        "check_reference": check_reference,
        "description": description,
    }


GENERIC_KEY_NAMES = (
    r"api[_-]?key|apikey|api[_-]?secret|app[_-]?key|app[_-]?secret|"
    r"access[_-]?key(?:[_-]?id)?|access[_-]?token|auth[_-]?token|auth[_-]?key|"
    r"secret[_-]?key|secret[_-]?access[_-]?key|client[_-]?secret|"
    r"consumer[_-]?key|consumer[_-]?secret|signing[_-]?key|"
    r"encryption[_-]?key|master[_-]?key|license[_-]?key|webhook[_-]?secret|"
    r"private[_-]?key|refresh[_-]?token|session[_-]?token|"
    r"subscription[_-]?key|service[_-]?key|admin[_-]?key|bot[_-]?token|"
    r"personal[_-]?access[_-]?token|credentials?|secret|token|bearer"
)

GENERIC_ASSIGN_RX = (
    r"""(?ix)
    (?:^|[^\w.-])["']?
    (?:[A-Za-z0-9]+[_.-])*
    (?:""" + GENERIC_KEY_NAMES + r""")
    ["']?
    \s*(?:=|:|:=|=>)\s*
    (["']?)
    ([A-Za-z0-9_\-./+=~]{12,})
    \1
    """
)

GENERIC_CAMEL_RX = (
    r"""(?ix)
    (?<![A-Za-z0-9])
    (?:my|our|the|app|client|server|dev|prod|test)?
    (apiKey|apiSecret|accessKey|accessKeyId|accessToken|authToken|authKey|
     secretKey|clientSecret|consumerKey|consumerSecret|signingKey|
     encryptionKey|masterKey|licenseKey|webhookSecret|privateKey|
     refreshToken|sessionToken|subscriptionKey|serviceKey|adminKey|botToken|
     personalAccessToken)
    \s*(?:=|:|:=|=>)\s*
    (["']?)
    ([A-Za-z0-9_\-./+=~]{12,})
    \2
    """
)

PASSWORD_ASSIGN_RX = (
    r"""(?ix)
    (?:^|[^\w.-])["']?
    (?:[A-Za-z0-9]+[_.-])*
    (?:password|passwd|pwd|passphrase)
    ["']?
    \s*(?:=|:|:=|=>)\s*
    (["']?)
    ([^\s'";,{}]{8,})
    \1
    """
)

SECRET_RULES = [
    # IA / LLM
    _rule("openai_api_key", "OpenAI", "ai", "critical",
          r"\bsk-(?!ant-|or-v1-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}\b",
          description="Cle API OpenAI (sk-, sk-proj-, sk-svcacct-, sk-admin-)"),
    _rule("anthropic_api_key", "Anthropic", "ai", "critical",
          r"\bsk-ant-[A-Za-z0-9_-]{20,}\b", priority=120,
          description="Cle API Anthropic (Claude)"),
    _rule("google_api_key", "Google / Firebase", "ai", "high",
          r"\bAIza[0-9A-Za-z_-]{35}\b",
          description="Cle API Google (Maps, Gemini, Firebase...)"),
    _rule("groq_api_key", "Groq", "ai", "high",
          r"\bgsk_[A-Za-z0-9]{40,}\b", description="Cle API Groq"),
    _rule("huggingface_token", "Hugging Face", "ai", "high",
          r"\bhf_[A-Za-z0-9]{30,}\b", description="Token Hugging Face"),
    _rule("replicate_token", "Replicate", "ai", "high",
          r"\br8_[A-Za-z0-9]{30,}\b", description="Token Replicate"),
    _rule("openrouter_api_key", "OpenRouter", "ai", "critical",
          r"\bsk-or-v1-[a-f0-9]{64}\b", priority=130,
          description="Cle API OpenRouter"),
    _rule("perplexity_api_key", "Perplexity", "ai", "high",
          r"\bpplx-[a-f0-9]{40,}\b", description="Cle API Perplexity"),
    _rule("deepgram_api_key", "Deepgram", "ai", "high",
          r'''(?i)\bdeepgram[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['"]?([a-f0-9]{32,40})['"]?''',
          group=1, description="Cle API Deepgram"),
    _rule("elevenlabs_api_key", "ElevenLabs", "ai", "high",
          r'''(?i)\bxi-api-key\b\s*[:=]\s*['"]?([a-f0-9]{32})['"]?''',
          group=1, description="Cle API ElevenLabs"),
    _rule("cohere_api_key", "Cohere", "ai", "high",
          r'''(?i)\bcohere[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['"]?([A-Za-z0-9]{32,40})['"]?''',
          group=1, description="Cle API Cohere"),
    _rule("mistral_api_key", "Mistral", "ai", "high",
          r'''(?i)\bmistral[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?''',
          group=1, description="Cle API Mistral"),

    # Cloud
    _rule("aws_access_key_id", "AWS", "cloud", "critical",
          r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b",
          description="Access key AWS"),
    _rule("aws_secret_access_key", "AWS", "cloud", "critical",
          r'''(?i)\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?''',
          group=1, min_len=40, description="Secret access key AWS"),
    _rule("aws_session_token", "AWS", "cloud", "critical",
          r'''(?i)\baws[_-]?session[_-]?token\b\s*[:=]\s*['"]?([A-Za-z0-9/+=]{100,})['"]?''',
          group=1, min_len=100, description="Token de session AWS"),
    _rule("azure_storage_account_key", "Azure Storage", "cloud", "critical",
          r'''(?i)\bAccountKey\s*=\s*([A-Za-z0-9+/]{80,}={0,2})''',
          group=1, min_len=80, description="Cle de compte Azure Storage"),
    _rule("azure_sas_token", "Azure SAS", "cloud", "high",
          r'''(?i)[?&]sig=([A-Za-z0-9%+/=]{20,})''',
          group=1, description="Signature SAS Azure"),
    _rule("azure_devops_pat", "Azure DevOps", "cloud", "critical",
          r'''(?i)\b(?:azure[_-]?devops|azdo|vsts)[_-]?(?:pat|token)\b\s*[:=]\s*['"]?([A-Za-z0-9]{52})['"]?''',
          group=1, min_len=52, description="PAT Azure DevOps"),
    _rule("digitalocean_token", "DigitalOcean", "cloud", "critical",
          r"\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b",
          description="Token API DigitalOcean"),
    _rule("cloudflare_api_token", "Cloudflare", "cloud", "critical",
          r'''(?i)\b(?:cloudflare|cf)[_-]?(?:api[_-]?)?(?:token|key)\b\s*[:=]\s*['"]?([A-Za-z0-9_-]{37,40})['"]?''',
          group=1, description="Token ou cle globale Cloudflare"),
    _rule("alibaba_access_key", "Alibaba Cloud", "cloud", "critical",
          r"\bLTAI[A-Za-z0-9]{12,20}\b", description="Access key Alibaba Cloud"),
    _rule("linode_token", "Linode", "cloud", "high",
          r'''(?i)\b(?:linode[_-]?(?:api[_-]?)?(?:token|key)|linode_token)\b\s*[:=]\s*['"]?([a-f0-9]{64})['"]?''',
          group=1, description="Token API Linode"),
    _rule("vultr_api_key", "Vultr", "cloud", "high",
          r'''(?i)\bvultr[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['"]?([A-Z0-9]{36})['"]?''',
          group=1, description="Cle API Vultr"),
    _rule("hetzner_token", "Hetzner", "cloud", "high",
          r'''(?i)\bhetzner[_-]?(?:api[_-]?)?(?:token|key)\b\s*[:=]\s*['"]?([A-Za-z0-9]{64})['"]?''',
          group=1, description="Token API Hetzner"),

    # Hebergement de code / CI
    _rule("github_classic_token", "GitHub", "code", "critical",
          r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b",
          description="Token GitHub classique"),
    _rule("github_fine_grained_pat", "GitHub", "code", "critical",
          r"\bgithub_pat_[A-Za-z0-9_]{22,}\b",
          description="PAT GitHub fine-grained"),
    _rule("gitlab_token", "GitLab", "code", "critical",
          r"\b(?:glpat|glptt|glrt|gldt|glft|gloas)-[A-Za-z0-9_-]{20,}\b",
          description="Token GitLab (PAT, runner, deploy...)"),
    _rule("bitbucket_token", "Bitbucket", "code", "high",
          r"\bATBB[A-Za-z0-9]{28,}\b", description="Token Bitbucket"),
    _rule("npm_token", "npm", "code", "critical",
          r"\bnpm_[A-Za-z0-9]{36}\b", description="Token npm"),
    _rule("pypi_token", "PyPI", "code", "critical",
          r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b",
          description="Token PyPI"),
    _rule("docker_pat", "Docker Hub", "code", "high",
          r"\bdckr_pat_[A-Za-z0-9_-]{20,}\b", description="PAT Docker Hub"),
    _rule("sonarqube_token", "SonarQube", "code", "high",
          r"\b(?:sqp|squ)_[a-f0-9]{40}\b", description="Token SonarQube"),
    _rule("buildkite_token", "Buildkite", "code", "high",
          r"\bbkua_[a-f0-9]{40}\b", description="Token agent Buildkite"),
    _rule("jfrog_api_key", "JFrog", "code", "high",
          r"\bAKCp[A-Za-z0-9]{60,}\b", description="Cle API JFrog"),
    _rule("postman_api_key", "Postman", "code", "high",
          r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b", description="Cle API Postman"),
    _rule("atlassian_api_token", "Atlassian", "code", "high",
          r"\bATATT3[A-Za-z0-9_-]{80,}\b", description="Token API Atlassian"),
    _rule("figma_token", "Figma", "code", "high",
          r"\bfigd_[A-Za-z0-9_-]{40,}\b", description="Token Figma"),
    _rule("vercel_token", "Vercel", "code", "high",
          r'''(?i)\bvercel[_-]?(?:api[_-]?)?token\b\s*[:=]\s*['"]?([A-Za-z0-9]{24,})['"]?''',
          group=1, description="Token Vercel"),
    _rule("netlify_token", "Netlify", "code", "high",
          r'''(?i)\bnetlify[_-]?(?:api[_-]?)?(?:token|key)\b\s*[:=]\s*['"]?([A-Za-z0-9]{40,})['"]?''',
          group=1, description="Token Netlify"),
    _rule("circleci_token", "CircleCI", "code", "high",
          r'''(?i)\bcircleci[_-]?(?:api[_-]?)?token\b\s*[:=]\s*['"]?([a-f0-9]{40})['"]?''',
          group=1, description="Token API CircleCI"),

    # Paiement
    _rule("stripe_secret_key", "Stripe", "payments", "critical",
          r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{20,}\b",
          description="Cle secrete ou restreinte Stripe"),
    _rule("stripe_publishable_key", "Stripe", "payments", "low",
          r"\bpk_(?:live|test)_[0-9A-Za-z]{20,}\b", priority=30,
          description="Cle publique Stripe (non secrete)"),
    _rule("stripe_webhook_secret", "Stripe", "payments", "high",
          r"\bwhsec_[A-Za-z0-9+/=]{32,}\b", description="Secret webhook Stripe"),
    _rule("square_access_token", "Square", "payments", "critical",
          r"\bsq0atp-[0-9A-Za-z_-]{22}\b", description="Access token Square"),
    _rule("square_secret", "Square", "payments", "critical",
          r"\bsq0csp-[0-9A-Za-z_-]{43}\b", description="Secret Square"),
    _rule("square_oauth_secret", "Square", "payments", "critical",
          r"\bEAAA[A-Za-z0-9_-]{60,}\b", description="Secret OAuth Square"),
    _rule("paypal_client_secret", "PayPal / Braintree", "payments", "critical",
          r"\baccess_token\$(?:production|sandbox)\$[a-z0-9]{16}\$[a-f0-9]{32}\b",
          description="Token client PayPal / Braintree"),
    _rule("razorpay_key", "Razorpay", "payments", "critical",
          r"\brzp_(?:live|test)_[A-Za-z0-9]{14,}\b", description="Cle Razorpay"),
    _rule("shopify_token", "Shopify", "payments", "critical",
          r"\bshp(?:at|ss|ca|pa)_[a-fA-F0-9]{32}\b",
          description="Token Shopify (admin, storefront, custom app)"),
    _rule("flutterwave_secret", "Flutterwave", "payments", "critical",
          r"\bFLWSECK-[A-Za-z0-9_-]{30,}\b", description="Cle secrete Flutterwave"),
    _rule("paystack_secret", "Paystack", "payments", "critical",
          r"\bsk_(?:live|test)_[a-f0-9]{40}\b", priority=120,
          description="Cle secrete Paystack"),
    _rule("adyen_api_key", "Adyen", "payments", "high",
          r"\bAQE[A-Za-z0-9_-]{50,}\b", description="Cle API Adyen"),

    # Messagerie / communication
    _rule("slack_token", "Slack", "comms", "critical",
          r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", description="Token Slack"),
    _rule("slack_app_token", "Slack", "comms", "critical",
          r"\bxapp-[A-Za-z0-9-]{20,}\b", description="Token d'application Slack"),
    _rule("slack_webhook", "Slack", "comms", "high",
          r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
          description="URL de webhook Slack"),
    _rule("discord_webhook", "Discord", "comms", "high",
          r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{50,}",
          description="URL de webhook Discord"),
    _rule("discord_bot_token", "Discord", "comms", "critical",
          r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}\b",
          description="Token de bot Discord"),
    _rule("telegram_bot_token", "Telegram", "comms", "critical",
          r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", description="Token de bot Telegram"),
    _rule("firebase_cloud_messaging_key", "Firebase", "comms", "high",
          r"\bAAAA[A-Za-z0-9_-]{50,}:APA91b[A-Za-z0-9_-]{40,}\b",
          priority=120, description="Cle serveur Firebase Cloud Messaging"),
    _rule("twilio_api_key", "Twilio", "comms", "high",
          r"\bSK[0-9a-fA-F]{32}\b", description="Cle API Twilio (SK...)"),
    _rule("twilio_account_sid", "Twilio", "comms", "low",
          r"\bAC[0-9a-fA-F]{32}\b", priority=30,
          description="SID de compte Twilio (identifiant)"),
    _rule("twilio_auth_token", "Twilio", "comms", "critical",
          r'''(?i)\btwilio[_-]?(?:auth[_-]?)?token\b\s*[:=]\s*['"]?([0-9a-f]{32})['"]?''',
          group=1, description="Auth token Twilio"),
    _rule("sendgrid_api_key", "SendGrid", "comms", "critical",
          r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b",
          description="Cle API SendGrid"),
    _rule("mailgun_api_key", "Mailgun", "comms", "high",
          r"\bkey-[0-9a-zA-Z]{32}\b", description="Cle API Mailgun"),
    _rule("mailchimp_api_key", "Mailchimp", "comms", "high",
          r"\b[0-9a-f]{32}-us\d{1,2}\b", description="Cle API Mailchimp"),
    _rule("brevo_api_key", "Brevo", "comms", "high",
          r"\bxkeysib-[a-f0-9]{64}-[A-Za-z0-9]{16}\b",
          description="Cle API Brevo (Sendinblue)"),

    # Reseaux sociaux
    _rule("facebook_access_token", "Facebook / Meta", "social", "critical",
          r"\bEAA[A-Za-z0-9]{60,}\b", description="Token d'acces Facebook / Meta"),
    _rule("twitter_bearer_token", "Twitter / X", "social", "high",
          r"\bAAAA[A-Za-z0-9%_-]{30,}\b", description="Bearer token Twitter / X"),

    # Services de developpement / SaaS
    _rule("airtable_pat", "Airtable", "devtools", "high",
          r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b", description="PAT Airtable"),
    _rule("notion_token", "Notion", "devtools", "critical",
          r"\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{40,})\b",
          description="Token d'integration Notion"),
    _rule("linear_api_key", "Linear", "devtools", "high",
          r"\blin_api_[A-Za-z0-9]{40,}\b", description="Cle API Linear"),
    _rule("hubspot_private_app_token", "HubSpot", "devtools", "high",
          r"\bpat-(?:na1|eu1|ap1)-[a-z0-9-]{20,}\b",
          description="Token d'application privee HubSpot"),
    _rule("mapbox_token", "Mapbox", "devtools", "high",
          r"\b(?:pk|sk)\.(?:eyJ[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{50,})\b",
          description="Token Mapbox"),
    _rule("contentful_token", "Contentful", "devtools", "high",
          r"\bCFPAT-[A-Za-z0-9_-]{40,}\b", description="PAT Contentful"),
    _rule("launchdarkly_key", "LaunchDarkly", "devtools", "high",
          r"\bsdk-[a-f0-9-]{36}\b", description="Cle SDK LaunchDarkly"),
    _rule("supabase_pat", "Supabase", "devtools", "critical",
          r"\bsbp_[a-f0-9]{40}\b", description="PAT Supabase"),
    _rule("planetscale_token", "PlanetScale", "devtools", "critical",
          r"\bpscale_(?:tkn|oauth)_[A-Za-z0-9_]{32,}\b",
          description="Token PlanetScale"),

    # Observabilite
    _rule("datadog_api_key", "Datadog", "observability", "critical",
          r'''(?i)\b(?:datadog|dd)[_-]?(?:api[_-]?)?key\b\s*[:=]\s*['"]?([a-f0-9]{32})['"]?''',
          group=1, description="Cle API Datadog"),
    _rule("datadog_app_key", "Datadog", "observability", "critical",
          r'''(?i)\b(?:datadog|dd)[_-]?app[_-]?key\b\s*[:=]\s*['"]?([a-f0-9]{40})['"]?''',
          group=1, description="Application key Datadog"),
    _rule("new_relic_user_key", "New Relic", "observability", "critical",
          r"\bNRAK-[A-Z0-9]{27}\b", description="User key New Relic"),
    _rule("sentry_auth_token", "Sentry", "observability", "critical",
          r"\bsntrys_[A-Za-z0-9_-]{40,}\b", description="Auth token Sentry"),
    _rule("sentry_dsn", "Sentry", "observability", "medium",
          r"https://[a-f0-9]{32}@o\d+\.ingest\.sentry\.io/\d+",
          description="DSN Sentry"),
    _rule("grafana_service_account_token", "Grafana", "observability", "critical",
          r"\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b",
          description="Token de service Grafana"),

    # Bases de donnees / files
    _rule("database_url_credentials", "Base de donnees", "databases", "critical",
          r"(?i)\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|mariadb|redis|rediss|amqp|amqps|mssql|sqlserver)://[^/\s:@]+:([^@\s/]{4,})@",
          group=1, min_len=4, min_entropy=2.0, priority=110,
          description="Mot de passe dans une URL de connexion"),

    # OAuth / OpenID Connect
    _rule("google_oauth_client_secret", "Google OAuth", "oauth", "critical",
          r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", priority=120,
          description="Secret client OAuth Google"),
    _rule("google_oauth_refresh_token", "Google OAuth", "oauth", "high",
          r"\b1//[A-Za-z0-9_-]{40,}\b", priority=120,
          description="Refresh token OAuth Google"),
    _rule("github_oauth_token", "GitHub OAuth", "oauth", "critical",
          r"\bgh[ousr]_[A-Za-z0-9]{36,}\b", priority=115,
          description="Token OAuth GitHub (gho_, ghu_, ghs_, ghr_)"),
    _rule("gitlab_oauth_secret", "GitLab OAuth", "oauth", "critical",
          r"\bgloas-[A-Za-z0-9_-]{20,}\b", priority=115,
          description="Secret d'application OAuth GitLab"),
    _rule("azure_ad_client_secret", "Azure AD / Entra", "oauth", "critical",
          r"\b[A-Za-z0-9_~.]{3}8Q~[A-Za-z0-9_~.-]{31,34}\b", priority=120,
          description="Secret client Azure AD / Entra ID"),
    _rule("okta_api_token", "Okta", "oauth", "critical",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*okta[_-]?(?:api[_-]?)?token\b\s*[:=]\s*['"]?(00[A-Za-z0-9_-]{40})['"]?''',
          group=1, min_len=42, priority=108,
          description="Token API Okta"),
    _rule("auth0_client_secret", "Auth0", "oauth", "critical",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*auth0[_-]?(?:client[_-]?)?secret\b\s*[:=]\s*['"]?([A-Za-z0-9_-]{32,})['"]?''',
          group=1, min_len=32, priority=108,
          description="Secret client Auth0"),
    _rule("facebook_app_secret", "Facebook / Meta", "oauth", "critical",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*facebook[_-]?app[_-]?secret\b\s*[:=]\s*['"]?([a-f0-9]{32})['"]?''',
          group=1, min_len=32, priority=106,
          description="Secret d'application Facebook (OAuth)"),
    _rule("oauth_client_secret", "OAuth", "oauth", "critical",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*(?:oauth[_-]?)?client[_-]?secret\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=2.5, priority=108,
          description="Secret client OAuth / OIDC"),
    _rule("oauth_refresh_token", "OAuth", "oauth", "high",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*(?:oauth[_-]?)?refresh[_-]?token\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=3.0, priority=108,
          description="Refresh token OAuth / OIDC"),
    _rule("oauth_access_token", "OAuth", "oauth", "high",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*(?:oauth[_-]?)?access[_-]?token\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=3.0, priority=108,
          description="Access token OAuth / OIDC"),
    _rule("oauth1_token_secret", "OAuth 1.0a", "oauth", "critical",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*(?:oauth[_-]?)?token[_-]?secret\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=3.0, priority=110,
          description="Token secret OAuth 1.0a"),
    _rule("oauth_id_token", "OpenID Connect", "oauth", "high",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*id[_-]?token\b\s*[:=]\s*['"]?(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})['"]?''',
          group=1, min_len=30, priority=108,
          description="ID token OpenID Connect (JWT)"),
    _rule("oauth_camel_tokens", "OAuth", "oauth", "high",
          r'''(?i)\b(?:my|our|app|client|server|dev|prod|test|oauth)?'''
          r'''(?:clientSecret|refreshToken|accessToken|idToken)\b'''
          r'''\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=2.5, priority=107,
          description="Jeton OAuth en camelCase (clientSecret, accessToken...)"),
    _rule("oauth_authorization_code", "OAuth", "oauth", "medium",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*(?:authorization|auth)[_-]?code\b\s*[:=]\s*['"]?([A-Za-z0-9_\-.]{16,})['"]?''',
          group=1, min_len=16, min_entropy=3.0, priority=104,
          description="Code d'autorisation OAuth"),
    _rule("oauth_code_verifier", "OAuth PKCE", "oauth", "medium",
          r'''(?i)(?:^|[^\w.-])["']?(?:[A-Za-z0-9]+[_.-])*code[_-]?verifier\b\s*[:=]\s*['"]?([A-Za-z0-9_\-./+=~]{16,})['"]?''',
          group=1, min_len=16, min_entropy=3.0, priority=104,
          description="Code verifier PKCE OAuth"),

    # Authentification / jetons
    _rule("jwt_token", "JWT", "auth", "high",
          r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
          description="Jeton JWT"),
    _rule("bearer_token", "Bearer", "auth", "high",
          r'''(?i)\bBearer\s+([A-Za-z0-9\-._~+/]{20,}=*)''',
          group=1, min_len=20, description="Token Bearer"),
    _rule("basic_auth", "Basic Auth", "auth", "high",
          r'''(?i)\bBasic\s+([A-Za-z0-9+/]{16,}={0,2})''',
          group=1, min_len=16, min_entropy=2.5,
          description="Identifiants Basic Auth"),
    _rule("url_credentials", "URL avec identifiants", "auth", "high",
          r"(?i)\b[a-z][a-z0-9+.-]*://[^/\s:@]+:([^/\s@]{4,})@",
          group=1, min_len=4, min_entropy=2.0, priority=90,
          description="Mot de passe dans une URL"),

    # Cles cryptographiques
    _rule("private_key_block", "Cle privee", "crypto", "critical",
          r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----",
          description="Bloc de cle privee (RSA, EC, OpenSSH, PGP...)"),

    # Heuristiques generiques
    _rule("generic_api_key_assignment", "Generique", "generic", "high",
          GENERIC_ASSIGN_RX, group=2, min_len=12, min_entropy=3.0,
          priority=10, require_mixed=True,
          description="Affectation api_key / token / secret..."),
    _rule("generic_camelcase_assignment", "Generique", "generic", "high",
          GENERIC_CAMEL_RX, group=3, min_len=12, min_entropy=3.0,
          priority=11, require_mixed=True,
          description="Affectation camelCase apiKey / accessToken..."),
    _rule("generic_password_assignment", "Generique", "generic", "high",
          PASSWORD_ASSIGN_RX, group=2, min_len=8, min_entropy=2.5,
          priority=9, check_reference=False,
          description="Affectation password / pwd..."),
]

for _defined_rule in SECRET_RULES:
    _defined_rule["rx"] = re.compile(_defined_rule["regex"])
del _defined_rule

# Compatibilite avec l'ancien nom PATTERNS (dict id -> regex compilee).
PATTERNS = {r["id"]: r["rx"] for r in SECRET_RULES}
CUSTOM_SECRET_RULES = []

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist",
             "build", ".tox", ".ruff_cache", ".mypy_cache", ".pytest_cache"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".exe", ".dll", ".so"}
MAX_FILE_BYTES = 2_000_000
MAX_LINE_PREVIEW = 300

# Dossier de l'outil : permet de le lancer depuis N'IMPORTE QUEL depot.
TOOL_DIR = Path(__file__).resolve().parent


def resolve_input_path(path_str):
    """Resout un fichier d'ENTREE (mots-cles, liste de depots, config...).
    Priorite au dossier courant, puis au dossier de l'outil : on peut donc
    lancer le scanner depuis un autre depot sans copier mots_cles.txt.
    Les sorties (--report, --output, ...) ne passent jamais par ici."""
    if not path_str:
        return Path(path_str)
    p = Path(str(path_str)).expanduser()
    if p.is_absolute() or p.exists():
        return p
    bundled = TOOL_DIR / p
    if bundled.exists():
        return bundled
    return p


def read_text_file(path):
    """Lit un fichier texte quel que soit l'encodage courant du depot :
    UTF-8 (avec ou sans BOM), UTF-16 (BOM), sinon Windows-1252/latin-1.
    Evite qu'un fichier Windows fasse planter le scan."""
    data = Path(path).read_bytes()
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", errors="replace")
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


_GITHUB_URL_RX = re.compile(
    r"^(?:https?://|ssh://git@|git@)?(?:www\.)?github\.com[/:]"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+?)"
    r"(?:\.git)?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_REPO_NAME_RX = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def normalize_repo_target(value):
    """Normalise une cible GitHub : URL https/ssh/git@, owner/name, avec ou
    sans .git (et suffixes /tree/..., /blob/..., query...). Retourne
    'owner/name' ou '' si la cible n'est pas reconnue."""
    s = str(value or "").strip().strip('"').strip("'").strip()
    if not s:
        return ""
    if (s.startswith(("http://", "https://", "ssh://", "git@"))
            or "github.com" in s.lower()):
        m = _GITHUB_URL_RX.match(s)
        if not m:
            return ""
        return f"{m.group('owner')}/{m.group('repo')}"
    if _REPO_NAME_RX.match(s):
        owner, repo = s.split("/", 1)
        if owner in (".", "..") or repo in (".", ".."):
            return ""
        return s
    return ""


def classify_target(value):
    """Classe une cible de ligne de commande :
    ('local', chemin) | ('remote', 'owner/name') | ('', '')."""
    s = str(value or "").strip().strip('"').strip("'")
    if not s:
        return "", ""
    if s in (".", "..", "~") or Path(s).expanduser().exists():
        return "local", str(Path(s).expanduser())
    repo = normalize_repo_target(s)
    if repo:
        return "remote", repo
    looks_path = (s.startswith(("./", ".\\", "/", "\\", "~"))
                  or re.match(r"^[A-Za-z]:[\\/]", s) is not None
                  or "\\" in s)
    if looks_path:
        return "local", s
    return "", ""


# Fichiers d'entree/sortie de l'outil lui-meme : jamais scannes
# (evite que mots_cles.txt ou resultats.txt se retrouvent dans les resultats).
EXCLUDE_PATHS = set()


def _excluded(path: Path) -> bool:
    try:
        if str(path.resolve()) in EXCLUDE_PATHS:
            return True
        if path.resolve() == Path(__file__).resolve():
            return True
    except Exception:
        pass
    # Ne scanne jamais les entrees/sorties de l'outil (mots-cles, listes, rapports),
    # quel que soit le dossier scanne : compare sur le nom de fichier.
    name = path.name.lower()
    if name in ("mots_cles.txt", "depots.txt", "allowlist.txt", "audit.ini",
                ".audit_state.json"):
        return True
    report_exts = (".txt", ".json", ".html", ".csv", ".sarif")
    for prefix in ("resultat", "rapport", "audit_report"):
        if name.startswith(prefix) and name.endswith(report_exts):
            return True
    return False


def fill_excludes(*paths):
    for q in paths:
        if not q:
            continue
        try:
            EXCLUDE_PATHS.add(str(Path(q).resolve()))
        except Exception:
            pass


# ================================================== options transverses
# Reglages globaux issus de la CLI (exclusions, contexte, entropie, retry...),
# lus par les fonctions de scan sans changer toutes leurs signatures.
# (meme style que AUTHOR_HITS / _LAST_DISCOVER plus bas dans ce fichier).
OPTS = {
    "excludes": [],
    "include_exts": set(),
    "context": 0,
    "entropy": False,
    "entropy_threshold": 4.5,
    "entropy_min_len": 20,
    "no_retry": False,
    "secret_rule_categories": set(),
    "secret_skip_categories": set(),
    "secret_min_severity": "info",
    "secret_no_generic": False,
}

STATE_FILE = ".audit_state.json"


def parse_str_list(values):
    """Combine options repetables + virgules. Retourne liste unique ordonnee."""
    out = []
    seen = set()
    for item in values or []:
        for part in str(item).split(","):
            s = part.strip()
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out


def parse_include_exts(values):
    """Normalise --include-ext : '.py' / 'py' -> {'.py'} (minuscules)."""
    exts = set()
    for s in parse_str_list(values):
        s = s.strip().lower()
        if not s:
            continue
        if not s.startswith("."):
            s = "." + s
        exts.add(s)
    return exts


def _user_excluded(path_str: str, excludes) -> bool:
    """Vrai si le chemin matche un motif --exclude (fnmatch sur nom + chemin,
    ou sous-chaine si le motif n'a pas de joker)."""
    norm = path_str.replace("\\", "/")
    name = norm.split("/")[-1]
    for pat in excludes or []:
        p = pat.strip()
        if not p:
            continue
        if ("*" not in p) and ("?" not in p) and ("[" not in p):
            if p in norm or p in name:
                return True
            continue
        if fnmatch.fnmatch(name, p) or fnmatch.fnmatch(norm, p):
            return True
    return False


def keep_local_path(p: Path) -> bool:
    """Filtre --include-ext / --exclude pour un fichier local."""
    inc = OPTS.get("include_exts") or set()
    if inc and p.suffix.lower() not in inc:
        return False
    if _user_excluded(str(p), OPTS.get("excludes")):
        return False
    return True


def keep_remote_path(path_str: str) -> bool:
    """Filtre --include-ext / --exclude pour un chemin distant (owner/repo:path)."""
    inc = OPTS.get("include_exts") or set()
    if inc and Path(path_str).suffix.lower() not in inc:
        return False
    if _user_excluded(path_str, OPTS.get("excludes")):
        return False
    return True


def with_context(all_lines, num_1based: int, width: int):
    """Lignes de contexte autour de la ligne `num` (1-based), sans la ligne elle-meme."""
    if not width or width <= 0:
        return []
    ctx = []
    start = max(1, num_1based - width)
    end = min(len(all_lines), num_1based + width)
    for n in range(start, end + 1):
        if n == num_1based:
            continue
        txt = all_lines[n - 1].strip()
        if len(txt) > MAX_LINE_PREVIEW:
            txt = txt[:MAX_LINE_PREVIEW] + "... [tronque]"
        ctx.append({"line": n, "text": txt,
                    "pos": "avant" if n < num_1based else "apres"})
    return ctx


# ------------------------------------------------------- allowlist
def load_allowlist(path_str):
    """Lit allowlist.txt : sous-chaines (ou regex:...), # = commentaire.
    Fichier absent = aucune entree (pas d'erreur)."""
    if not path_str:
        return []
    p = Path(path_str)
    if not p.exists():
        return []
    items = []
    for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("regex:"):
            body = s[len("regex:"):].strip()
            try:
                items.append({"raw": s, "rx": re.compile(body, re.IGNORECASE)})
            except re.error as e:
                print(f"[allowlist ignore] regex invalide '{s}' : {e}")
        else:
            items.append({"raw": s, "text": s.lower()})
    if items:
        print(f"[allowlist] {len(items)} entree(s) chargee(s) depuis {p} "
              f"(occurrences marquees [ignore]).")
    return items


def _allow_text(f):
    return " ".join(str(f.get(k, "")) for k in
                    ("matched", "match_preview", "detail", "keyword",
                     "rule", "provider", "file", "repo"))


def finding_ignored(finding, allowlist) -> bool:
    if not allowlist:
        return False
    hay = _allow_text(finding)
    low = hay.lower()
    for item in allowlist:
        if "rx" in item:
            try:
                if item["rx"].search(hay):
                    return True
            except Exception:
                continue
        elif item.get("text") and item["text"] in low:
            return True
    return False


def mark_ignored(findings, allowlist):
    """Marque findings[i]['ignored']. Retourne le nombre d'ignorees."""
    n = 0
    for f in findings:
        ign = finding_ignored(f, allowlist)
        f["ignored"] = bool(ign)
        n += 1 if ign else 0
    return n


# ------------------------------------------------------- entropie
_TOKEN_RX = re.compile(r"[A-Za-z0-9+/=_.\-]{8,}")


def shannon_entropy(s: str) -> float:
    """Entropie de Shannon (bits/caractere). Elevee = chaine aleatoire
    type cle/token (ex: x7f9a2c...), basse = mot normal."""
    if not s:
        return 0.0
    n = len(s)
    counts = Counter(s)
    return -sum((v / n) * math.log2(v / n) for v in counts.values())


def entropy_hits_for_line(line: str, respect_filters: bool = False):
    """Tokens suspects a haute entropie (sans regex connue). Ne fait rien
    si OPTS['entropy'] est faux. Exclut mots purs et nombres purs.
    En mode secrets, respect_filters=True applique aussi les filtres
    --no-generic / --only-category / --min-severity."""
    if not OPTS.get("entropy"):
        return []
    if respect_filters and not entropy_enabled():
        return []
    try:
        min_len = int(OPTS.get("entropy_min_len") or 20)
        thr = float(OPTS.get("entropy_threshold") or 4.5)
    except (TypeError, ValueError):
        return []
    hits = []
    for tok in _TOKEN_RX.findall(line):
        if len(tok) < min_len:
            continue
        letters = sum(c.isalpha() for c in tok)
        digits = sum(c.isdigit() for c in tok)
        if letters == 0 or digits == 0:
            continue
        try:
            ent = shannon_entropy(tok)
        except Exception:
            continue
        if ent >= thr:
            hits.append({"kind": "entropy", "keyword": "[entropie]",
                         "matched": tok[:MAX_LINE_PREVIEW],
                         "entropy": round(ent, 2)})
    return hits


# ------------------------------------------------------- moteur de detection API-Key
_PLACEHOLDER_RX = re.compile(
    r"(?i)(?:your[_-]?(?:api|access|secret|private|token|key)|"
    r"example|sample|dummy|placeholder|changeme|change[_-]?me|"
    r"replace[_-]?me|insert[_-]|enter[_-]|redacted|todo|fixme|lorem|"
    r"\.\.\.|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|"
    r"\{[A-Za-z_][A-Za-z0-9_.-]*\}|"
    r"os\.environ|process\.env|getenv|env\[|secrets?\.)"
)

_PLACEHOLDER_VALUES = {
    "password", "passwd", "passphrase", "secret", "token", "apikey",
    "api_key", "api-key", "none", "null", "undefined", "nil", "true",
    "false", "changeme", "redacted", "placeholder",
}

_REFERENCE_RX = re.compile(
    r"(?i)^(?:https?|ftp|sftp|file)://|^[./~]|"
    r"^[A-Za-z_][A-Za-z0-9_.]*\s*\(|"
    r"^(?:os\.environ|os\.getenv|process\.env|env\.|config\.|settings\.|"
    r"self\.|this\.|getenv|secrets?\.|vault\.)|"
    r"^(?:true|false|null|none|undefined|nil)$"
)

_FILE_LIKE_RX = re.compile(
    r"(?i)^[A-Za-z0-9_.-]+\.(?:py|js|jsx|ts|tsx|json|ya?ml|env|txt|md|"
    r"html?|xml|ini|toml|lock|cfg|conf|java|go|rs|rb|php|sh|ps1|bat)$"
)


def _severity_ok(severity, minimum):
    return (SEVERITY_ORDER.get(str(severity).lower(), 0)
            >= SEVERITY_ORDER.get(str(minimum).lower(), 0))


def entropy_enabled():
    """L'entropie est une heuristique generique : elle doit respecter
    --no-generic / --only-category / --skip-category / --min-severity."""
    if not OPTS.get("entropy"):
        return False
    if OPTS.get("secret_no_generic"):
        return False
    only = set(OPTS.get("secret_rule_categories") or set())
    skip = set(OPTS.get("secret_skip_categories") or set())
    if only and "generic" not in only:
        return False
    if "generic" in skip:
        return False
    return _severity_ok("medium", OPTS.get("secret_min_severity") or "info")


def active_secret_rules():
    """Regles actives apres filtres --only-category / --skip-category /
    --min-severity / --no-generic. Inclut les regles personnalisees."""
    rules = list(SECRET_RULES) + list(CUSTOM_SECRET_RULES)
    only = set(OPTS.get("secret_rule_categories") or set())
    skip = set(OPTS.get("secret_skip_categories") or set())
    if OPTS.get("secret_no_generic"):
        skip.add("generic")
    min_sev = OPTS.get("secret_min_severity") or "info"
    return [r for r in rules
            if (not only or r.get("category") in only)
            and r.get("category") not in skip
            and _severity_ok(r.get("severity", "info"), min_sev)]


def _is_placeholder(secret):
    s = (secret or "").strip().strip("'\"")
    if not s:
        return True
    low = s.lower()
    if low in _PLACEHOLDER_VALUES:
        return True
    if low.startswith(("your", "my_key", "my-key", "mykey", "insert_your",
                       "enter_your", "replace_your", "put_your")):
        return True
    if _PLACEHOLDER_RX.search(s):
        return True
    if re.fullmatch(r"(.)\1{5,}", s):
        return True
    if re.fullmatch(r"[x*0._\-]{6,}", low):
        return True
    return False


def _looks_like_reference(secret):
    s = (secret or "").strip().strip("'\"")
    if not s:
        return True
    if _REFERENCE_RX.search(s):
        return True
    if _FILE_LIKE_RX.fullmatch(s):
        return True
    if (re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", s)
            and not re.search(r"\d", s) and len(s) < 24):
        return True
    return False


def _line_is_reference(line):
    low = (line or "").lower()
    if re.search(r"(?:getenv|environ|process\.env|import\.meta\.env)\s*[\(\[]", low):
        return True
    if re.search(r"(?:config|settings|secrets|vault)\.(?:get|read|fetch|load)\s*\(", low):
        return True
    return False


def _secret_is_valid(secret, rule, line=""):
    s = (secret or "").strip().strip("'\"")
    if len(s) < int(rule.get("min_len") or 8):
        return False
    if not rule.get("allow_placeholder") and _is_placeholder(s):
        return False
    if rule.get("category") in ("generic", "oauth"):
        if rule.get("check_reference", True):
            if _looks_like_reference(s) or _line_is_reference(line):
                return False
        elif _REFERENCE_RX.search(s) or _FILE_LIKE_RX.fullmatch(s):
            return False
    if rule.get("require_mixed"):
        if not (re.search(r"[A-Za-z]", s) and re.search(r"\d", s)):
            return False
    min_entropy = float(rule.get("min_entropy") or 0.0)
    if min_entropy and shannon_entropy(s) < min_entropy:
        return False
    return True


def _line_text_at(text, line_starts, start):
    line_no = bisect_right(line_starts, start)
    line_start = line_starts[line_no - 1]
    line_end = text.find("\n", start)
    if line_end == -1:
        line_end = len(text)
    return line_no, text[line_start:line_end]


def _dedupe_secret_hits(hits):
    hits.sort(key=lambda h: (-h["priority"], h["start"],
                             -(h["end"] - h["start"])))
    kept = []
    for hit in hits:
        duplicate = False
        for prev in kept:
            if hit["line"] == prev["line"] and hit["secret"] == prev["secret"]:
                duplicate = True
                break
            if hit["start"] < prev["end"] and prev["start"] < hit["end"]:
                duplicate = True
                break
        if not duplicate:
            kept.append(hit)
    kept.sort(key=lambda h: (h["line"], h["start"]))
    return kept


def detect_secrets(text, all_rules=False):
    """Retourne toutes les occurrences API-Key/secrets d'un texte, dedupliquees
    et filtrees (placeholders, references de code, entropie minimale).
    all_rules=True ignore les filtres de categories/severite (utilise pour
    masquer le contexte sans jamais laisser fuiter une cle filtree)."""
    if not text:
        return []
    line_starts = [0]
    for newline in re.finditer("\n", text):
        line_starts.append(newline.end())
    hits = []
    rules = (list(SECRET_RULES) + list(CUSTOM_SECRET_RULES)
             if all_rules else active_secret_rules())
    for rule in rules:
        rx = rule.get("rx")
        if rx is None:
            try:
                rx = re.compile(rule["regex"])
            except re.error:
                continue
        group = int(rule.get("group") or 0)
        for match in rx.finditer(text):
            try:
                secret = match.group(group)
            except (IndexError, re.error):
                continue
            if not secret:
                continue
            secret = secret.strip().strip("'\"")
            if not secret:
                continue
            start, end = match.span(group)
            if start < 0 or end <= start:
                continue
            line_no, line_txt = _line_text_at(text, line_starts, start)
            if not _secret_is_valid(secret, rule, line_txt):
                continue
            hits.append({
                "id": rule["id"],
                "provider": rule.get("provider", ""),
                "category": rule.get("category", ""),
                "severity": rule.get("severity", "medium"),
                "priority": int(rule.get("priority") or 100),
                "description": rule.get("description", ""),
                "secret": secret,
                "start": start,
                "end": end,
                "line": line_no,
            })
    return _dedupe_secret_hits(hits)


def _mask_text(text, secret, reveal=False):
    if reveal or not text or not secret:
        return text
    return text.replace(secret, mask_secret(secret))


def _sanitize_context(context, reveal=False):
    if reveal or not context:
        return context
    for item in context:
        text = item.get("text", "")
        for hit in detect_secrets(text, all_rules=True):
            text = _mask_text(text, hit.get("secret", ""), reveal)
        if OPTS.get("entropy"):
            for hit in entropy_hits_for_line(text, respect_filters=False):
                text = text.replace(hit["matched"], mask_secret(hit["matched"]))
        item["text"] = text
    return context


def _secret_finding(hit, file_label, repo="", source="", branch="", lines=None,
                    reveal=False, context_width=0):
    lines = lines or []
    line_no = int(hit.get("line") or 1)
    line_txt = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    secret = hit.get("secret", "")
    safe_line = _mask_text(line_txt.strip(), secret, reveal)[:MAX_LINE_PREVIEW]
    finding = {
        "rule": hit["id"],
        "provider": hit.get("provider", ""),
        "category": hit.get("category", ""),
        "severity": hit.get("severity", "medium"),
        "file": file_label,
        "line": line_no,
        "match_preview": secret if reveal else mask_secret(secret),
        "revealed": bool(reveal),
        "secret_length": len(secret),
        "detail": f"[{hit.get('provider', '')}/{hit['id']}] "
                  + (safe_line or "(ligne vide)"),
        "context": with_context(lines, line_no, context_width),
    }
    if repo:
        finding["repo"] = repo
    if source:
        finding["source"] = source
    if branch:
        finding["branch"] = branch
    finding["context"] = _sanitize_context(finding["context"], reveal)
    return finding


def load_custom_secret_rules(path_str):
    """Charge des regles JSON personnalisees (option --rules-file)."""
    p = Path(path_str)
    if not p.exists():
        print(f"[regles] fichier introuvable : {p}")
        sys.exit(2)
    try:
        data = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
    except Exception as e:
        print(f"[regles] JSON illisible ({p}) : {e}")
        sys.exit(2)
    if isinstance(data, dict):
        data = data.get("rules", [])
    if not isinstance(data, list):
        print("[regles] format attendu : liste JSON de regles.")
        sys.exit(2)
    existing = {r["id"] for r in SECRET_RULES} | {r["id"] for r in CUSTOM_SECRET_RULES}
    added = 0
    for item in data:
        if not isinstance(item, dict):
            print("[regles] entree ignoree (objet JSON attendu).")
            continue
        rid = str(item.get("id") or "").strip()
        rx_src = str(item.get("regex") or "").strip()
        if not rid or not rx_src:
            print("[regles] entree ignoree (id et regex obligatoires).")
            continue
        if rid in existing:
            print(f"[regles] id deja utilise, ignore : {rid}")
            continue
        category = str(item.get("category") or "custom").strip().lower()
        if category not in SECRET_CATEGORIES:
            category = "custom"
        severity = str(item.get("severity") or "medium").strip().lower()
        if severity not in SEVERITY_ORDER:
            severity = "medium"
        flags = re.IGNORECASE if item.get("ignore_case") else 0
        try:
            rx = re.compile(rx_src, flags)
        except re.error as e:
            print(f"[regles] regex invalide pour {rid} : {e}")
            continue
        try:
            group = int(item.get("group") or 0)
            min_len = int(item.get("min_len") or 8)
            min_entropy = float(item.get("min_entropy") or 0.0)
            priority = int(item.get("priority") or 100)
        except (TypeError, ValueError):
            print(f"[regles] valeurs numeriques invalides pour {rid}, ignore.")
            continue
        if group < 0 or group > rx.groups:
            print(f"[regles] groupe {group} invalide pour {rid} "
                  f"(la regex a {rx.groups} groupe(s) de capture), ignore.")
            continue
        rule = _rule(rid, str(item.get("provider") or "Personnalise"),
                     category, severity, rx_src, group=group,
                     min_len=min_len, min_entropy=min_entropy,
                     priority=priority,
                     require_mixed=bool(item.get("require_mixed", False)),
                     allow_placeholder=bool(item.get("allow_placeholder", False)),
                     check_reference=bool(item.get("check_reference", True)),
                     description=str(item.get("description") or "Regle personnalisee"))
        rule["rx"] = rx
        rule["custom"] = True
        CUSTOM_SECRET_RULES.append(rule)
        existing.add(rid)
        added += 1
    print(f"[regles] {added} regle(s) personnalisee(s) chargee(s) depuis {p}.")


def print_secret_rules():
    rules = active_secret_rules()
    total = len(SECRET_RULES) + len(CUSTOM_SECRET_RULES)
    print(f"[regles] {len(rules)} type(s) actif(s) sur {total} disponible(s).")
    filters = []
    if OPTS.get("secret_rule_categories"):
        filters.append("only=" + ",".join(sorted(OPTS["secret_rule_categories"])))
    if OPTS.get("secret_skip_categories"):
        filters.append("skip=" + ",".join(sorted(OPTS["secret_skip_categories"])))
    if OPTS.get("secret_no_generic"):
        filters.append("no-generic")
    if (OPTS.get("secret_min_severity") or "info") != "info":
        filters.append("min-severity=" + str(OPTS["secret_min_severity"]))
    if filters:
        print("[regles] filtres actifs : " + "; ".join(filters))
    current = ""
    for rule in sorted(rules, key=lambda r: (r.get("category", ""), r["id"])):
        category = rule.get("category", "")
        if category != current:
            current = category
            print(f"\n[{category}] {SECRET_CATEGORIES.get(category, category)}")
        desc = f" - {rule['description']}" if rule.get("description") else ""
        print(f"  {rule.get('severity', 'medium'):<8} {rule['id']:<34} "
              f"{rule.get('provider', '')}{desc}")
    if not rules:
        print("  (aucune regle active avec ces filtres)")


# ------------------------------------------------------- veille diff (--since-last-run)
def load_state(path_str=STATE_FILE):
    try:
        p = Path(path_str)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8-sig", errors="replace"))
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def save_state(state, path_str=STATE_FILE):
    try:
        Path(path_str).write_text(json.dumps(state, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
    except Exception as e:
        print(f"[veille] impossible d'ecrire {path_str} : {e}")


def apply_since_last_run(run_key, findings, key_fn):
    """Veille diff : ne garde que les occurrences jamais vues.
    Met a jour le cache .audit_state.json. Retourne (nouvelles, nb_masquees)."""
    state = load_state()
    runs = state.get("runs", {})
    entry = runs.get(run_key, {}) if isinstance(runs, dict) else {}
    seen = set(entry.get("seen", [])) if isinstance(entry, dict) else set()
    fresh = []
    for f in findings:
        try:
            h = key_fn(f)
        except Exception:
            h = repr(sorted(str(v) for v in f.values()))
        if h not in seen:
            fresh.append(f)
    new_hashes = set()
    for f in findings:
        try:
            new_hashes.add(key_fn(f))
        except Exception:
            pass
    runs[run_key] = {"ts": datetime.now(timezone.utc).isoformat(),
                     "seen": sorted(seen.union(new_hashes))}
    state["runs"] = runs
    save_state(state)
    return fresh, len(findings) - len(fresh)


def kw_finding_key(f):
    return "|".join(str(f.get(k, "")) for k in
                    ("repo", "file", "line", "keyword", "matched"))


def secret_finding_key(f):
    return "|".join(str(f.get(k, "")) for k in
                    ("repo", "file", "line", "rule", "match_preview"))


# ------------------------------------------------------- preset --config
def _cli_option_present(ap, dest):
    """True si l'option dest a ete tapee explicitement en CLI, meme avec une
    valeur egale au defaut (ex: --reveal quand reveal vaut deja true).
    Sert a garantir que la CLI reste prioritaire sur --config."""
    option_strings = []
    for action in ap._actions:
        if action.dest == dest:
            option_strings = action.option_strings
            break
    if not option_strings:
        return False
    for raw in sys.argv[1:]:
        if raw == "--":
            break
        for opt in option_strings:
            if raw == opt or raw.startswith(opt + "="):
                return True
    return False


def apply_config_file(args, ap, path_str):
    """Preset audit.ini (section [audit]) : remplit les options NON precisees
    en CLI (la CLI reste prioritaire : on ne remplace que les valeurs egales
    au defaut argparse). Cles = noms d'options sans '--' ('-' -> '_').
    Listes (append) = valeurs separees par virgules. Booleens = true/false."""
    p = Path(path_str)
    if not p.exists():
        print(f"[config] fichier introuvable : {p}")
        sys.exit(2)
    cfg = configparser.ConfigParser()
    try:
        cfg.read(p, encoding="utf-8-sig")
    except Exception as e:
        print(f"[config] illisible ({p}) : {e}")
        sys.exit(2)
    if "audit" not in cfg:
        print("[config] section [audit] absente, rien a appliquer.")
        return
    defaults = ap.parse_args([])
    applied = []
    for key, raw in cfg["audit"].items():
        dest = key.strip().replace("-", "_")
        if not hasattr(args, dest):
            print(f"[config] cle inconnue ignoree : {key}")
            continue
        current = getattr(args, dest)
        default = getattr(defaults, dest, None)
        if current != default or _cli_option_present(ap, dest):
            continue  # precise en CLI : prioritaire
        if isinstance(default, bool):
            try:
                val = cfg["audit"].getboolean(key)
            except ValueError:
                print(f"[config] booleen invalide pour {key} : {raw!r} (attendu true/false)")
                continue
        elif isinstance(default, int) and not isinstance(default, bool):
            try:
                val = cfg["audit"].getint(key)
            except ValueError:
                print(f"[config] entier invalide pour {key} : {raw!r}")
                continue
        elif isinstance(default, float):
            try:
                val = cfg["audit"].getfloat(key)
            except ValueError:
                print(f"[config] nombre invalide pour {key} : {raw!r}")
                continue
        elif isinstance(default, list):
            val = [s.strip() for s in str(raw).split(",") if s.strip()]
        else:
            val = str(raw).strip()
        setattr(args, dest, val)
        applied.append(f"{dest}={val!r}" if not isinstance(val, str) else f"{dest}={val}")
    if applied:
        print(f"[config] preset {p} : {len(applied)} option(s) appliquee(s) "
              f"({', '.join(applied[:8])}{'...' if len(applied) > 8 else ''}).")


# ------------------------------------------------------- rapports HTML / CSV / SARIF
def write_csv_report(csv_path, findings):
    """Rapport CSV (Excel) : une ligne par occurrence."""
    cols = ["keyword", "kind", "rule", "provider", "category", "severity",
            "matched", "match_preview", "repo", "file", "line", "detail",
            "ignored", "source", "branch", "sha"]
    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for f in findings:
            row = {c: f.get(c, "") for c in cols}
            row["ignored"] = "oui" if f.get("ignored") else "non"
            w.writerow(row)
    return Path(csv_path)


def _html_escape(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_html_report(html_path, title, source_label, findings):
    """Rapport HTML cliquable, plie par depot (<details>), sans dependance."""
    by_repo = {}
    for f in findings:
        by_repo.setdefault(f.get("repo") or "(local)", []).append(f)
    parts = ["<!DOCTYPE html><html lang='fr'><head><meta charset='utf-8'>",
             f"<title>{_html_escape(title)}</title>",
             "<style>body{font-family:sans-serif;margin:2em}details{margin:.5em 0}"
             "summary{cursor:pointer;font-weight:bold}.ign{color:#888}"
             ".loc{color:#555;font-size:.9em}pre{background:#f4f4f4;padding:.3em;overflow-x:auto}"
             ".sev{color:#fff;border-radius:.2em;padding:0 .35em;font-size:.8em}"
             ".sev-critical,.sev-high{background:#b00020}.sev-medium{background:#b36b00}"
             ".sev-low,.sev-info{background:#555}"
             "</style></head><body>",
             f"<h1>{_html_escape(title)}</h1>",
             f"<p>Source : {_html_escape(source_label)} — "
             f"{len(findings)} occurrence(s), {len(by_repo)} depot(s/dossier(s)).</p>"]
    for repo in sorted(by_repo):
        items = by_repo[repo]
        parts.append(f"<details open><summary>{_html_escape(repo)} "
                     f"({len(items)} occurrence(s))</summary><ul>")
        for f in items:
            ign = " <span class='ign'>[ignore]</span>" if f.get("ignored") else ""
            sev = str(f.get("severity", "")).lower()
            badge = f" <span class='sev sev-{_html_escape(sev)}'>{_html_escape(sev)}</span>" if sev else ""
            label = _html_escape(f.get("keyword") or f.get("rule", "?"))
            provider = f.get("provider")
            if provider:
                label += f" ({_html_escape(provider)})"
            where = _html_escape(f"{f.get('file', '')} (ligne {f.get('line', '?')})")
            detail = _html_escape(f.get("detail", f.get("match_preview", "")))
            parts.append(f"<li>{label}{badge}{ign}<br><span class='loc'>{where}</span>"
                         f"<pre>{detail}</pre></li>")
        parts.append("</ul></details>")
    parts.append("</body></html>")
    Path(html_path).write_text("\n".join(parts), encoding="utf-8")
    return Path(html_path)


def _sarif_level(severity):
    return {"critical": "error", "high": "error", "medium": "warning",
            "low": "note", "info": "note"}.get(str(severity or "").lower(),
                                               "warning")


def write_sarif_report(sarif_path, findings, tool_name="github-audit-scanner"):
    """Rapport SARIF 2.1.0 (onglet Security de GitHub / VS Code)."""
    rules = {}
    for f in findings:
        rid = str(f.get("rule") or f.get("keyword") or "trouvee")
        if rid not in rules:
            provider = str(f.get("provider") or "").strip()
            label = f"{provider} : {rid}" if provider else f"Motif {rid} detecte"
            rules[rid] = {"id": rid,
                          "name": rid.replace(" ", "_")[:64],
                          "shortDescription": {"text": label},
                          "defaultConfiguration": {
                              "level": _sarif_level(f.get("severity"))}}
    results = []
    for f in findings:
        rid = str(f.get("rule") or f.get("keyword") or "trouvee")
        try:
            line = int(f.get("line") or 1)
        except (TypeError, ValueError):
            line = 1
        msg = str(f.get("detail", f.get("match_preview", rid)))[:500]
        if f.get("ignored"):
            msg = "[ignore/allowlist] " + msg
        results.append({"ruleId": rid, "level": _sarif_level(f.get("severity")),
                        "message": {"text": msg},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": str(f.get("file", ""))},
                            "region": {"startLine": max(1, line)}}}]})
    sarif = {"version": "2.1.0",
             "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
             "runs": [{"tool": {"driver": {"name": tool_name,
                                           "informationUri": "https://github.com",
                                           "rules": list(rules.values())}},
                       "results": results}]}
    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh, indent=2, ensure_ascii=False)
    return Path(sarif_path)


def write_secret_report_bundle(args, findings, scanned_files, users,
                               title="Rapport secrets"):
    """Ecrit les sorties SECRETS (JSON + HTML/CSV/SARIF optionnels)."""
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanned_files": scanned_files,
            "findings_count": len(findings),
            "revealed": bool(args.reveal),
            "modified_by": list(users),
            "author_hits": dict(AUTHOR_HITS),
            "findings": findings,
        }, fh, indent=2, ensure_ascii=False)
    print(f"[SECRETS] : {len(findings)}")
    print(f"[RAPPORT] : {args.output}")
    if args.html:
        write_html_report(args.html, title, "audit-defensif-secrets", findings)
        print(f"[OK] Rapport HTML : {args.html}")
    if args.csv:
        write_csv_report(args.csv, findings)
        print(f"[OK] Rapport CSV : {args.csv}")
    if args.sarif:
        write_sarif_report(args.sarif, findings)
        print(f"[OK] Rapport SARIF : {args.sarif}")



# ------------------------------------------------------- historique git (--history)
def _wrap_history_finding(part, repo_label, file_path, sha, date, author):
    f = {"keyword": part.get("keyword", "?"),
         "kind": part.get("kind", "?"),
         "matched": part.get("matched", ""),
         "repo": repo_label,
         "file": f"{repo_label}:{file_path}" if repo_label else str(file_path),
         "line": 0,
         "detail": part.get("detail", ""),
         "source": "history",
         "branch": "",
         "sha": sha, "date": date, "author": author}
    if part.get("rule"):
        f["rule"] = part["rule"]
    for key in ("provider", "category", "severity", "secret_length"):
        if part.get(key) is not None:
            f[key] = part[key]
    if "match_preview" in part:
        f["match_preview"] = part["match_preview"]
    if "revealed" in part:
        f["revealed"] = part["revealed"]
    if part.get("entropy") is not None:
        f["entropy"] = part["entropy"]
    if part.get("detector"):
        f["detector"] = part["detector"]
    return f


def check_line_both(line, patterns, case_sensitive=False, reveal=False):
    """Historique : applique mots-cles ET secrets a une ligne ajoutee.
    Chaque morceau est tague pour etre reparti dans le bon rapport."""
    out = []
    for part in check_line_keywords(line, patterns, case_sensitive):
        part["detector"] = "keyword"
        out.append(part)
    for part in check_line_secrets(line, reveal=reveal):
        part["detector"] = "secret"
        out.append(part)
    return out


def check_line_keywords(line, patterns, case_sensitive=False):
    """Decoupe une ligne ajoutee (historique) en morceaux mots-cles/entropie."""
    out = []
    for entry in match_line(line, patterns, case_sensitive):
        preview = line.strip()
        if len(preview) > MAX_LINE_PREVIEW:
            preview = preview[:MAX_LINE_PREVIEW] + "... [tronque]"
        out.append({"kind": entry["kind"], "keyword": entry["keyword"],
                    "matched": matched_text(line, entry, case_sensitive),
                    "detail": preview})
    for h in entropy_hits_for_line(line):
        out.append({"kind": h["kind"], "keyword": h["keyword"],
                    "matched": h["matched"], "detail": line.strip()[:MAX_LINE_PREVIEW],
                    "entropy": h.get("entropy")})
    return out


def check_line_secrets(line, reveal=False):
    """Decoupe une ligne ajoutee (historique) en morceaux secrets."""
    out = []
    hits = detect_secrets(line)
    known = {hit["secret"] for hit in hits}
    for hit in hits:
        secret = hit["secret"]
        preview = secret if reveal else mask_secret(secret)
        detail_line = _mask_text(line.strip(), secret, reveal)[:MAX_LINE_PREVIEW]
        out.append({
            "kind": "secret", "keyword": hit["id"], "rule": hit["id"],
            "provider": hit.get("provider", ""),
            "category": hit.get("category", ""),
            "severity": hit.get("severity", "medium"),
            "secret_length": len(secret),
            "matched": preview,
            "match_preview": preview,
            "revealed": bool(reveal),
            "detail": f"[{hit.get('provider', '')}/{hit['id']}] " + detail_line,
        })
    for entropy_hit in entropy_hits_for_line(line, respect_filters=True):
        token = entropy_hit["matched"]
        if token in known or (known and any(
                token in secret or secret in token for secret in known)):
            continue
        out.append({
            "kind": "entropy", "keyword": "[entropie]", "rule": "[entropie]",
            "provider": "Entropie", "category": "generic", "severity": "medium",
            "secret_length": len(token),
            "matched": token if reveal else mask_secret(token),
            "match_preview": token if reveal else mask_secret(token),
            "revealed": bool(reveal),
            "entropy": entropy_hit.get("entropy"),
            "detail": "[entropie] " + _mask_text(
                line.strip(), token, reveal)[:MAX_LINE_PREVIEW],
        })
    return out


def scan_local_history(root, depth, check, repo_label=""):
    """Scanne les lignes AJOUTEES des `depth` derniers commits (git log -p).
    Une cle revoquee reste visible dans l'historique : c'est le but.
    Retourne (nb_commits_vus, findings)."""
    findings = []
    if _git_toplevel(Path(root)) is None:
        print(f"  [historique skip] pas un depot git : {root}")
        return 0, findings
    cmd = ["git", "-C", str(root), "log", f"-n{int(depth)}",
           "--format=HISTCOMMIT:%H|%ad|%an|%s", "--date=short",
           "-p", "--no-color", "--no-ext-diff", "--no-renames"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300,
                           errors="replace")
    except Exception as e:
        print(f"  [historique erreur] {root} :: {e}")
        return 0, findings
    if r.returncode != 0:
        print(f"  [historique erreur] git log a echoue pour {root}")
        return 0, findings
    sha, date, author = "", "", ""
    cur_file = ""
    n_commits = 0
    for raw in (r.stdout or "").splitlines():
        if raw.startswith("HISTCOMMIT:"):
            parts = raw[len("HISTCOMMIT:"):].split("|", 3)
            sha = parts[0][:7] if parts and parts[0] else ""
            date = parts[1] if len(parts) > 1 else ""
            author = parts[2] if len(parts) > 2 else ""
            n_commits += 1
            cur_file = ""
            continue
        if raw.startswith("+++ b/"):
            cur_file = raw[len("+++ b/"):]
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            if not keep_remote_path(cur_file or ""):
                continue
            added = raw[1:]
            for part in check(added):
                findings.append(_wrap_history_finding(
                    part, repo_label, cur_file or "(inconnu)", sha, date, author))
    return n_commits, findings


def scan_remote_history(token, full_name, depth, branch, check):
    """Scanne les lignes AJOUTEES des `depth` derniers commits via l'API
    Commits (1 appel liste + 1 appel par commit pour le patch).
    Retourne (nb_commits_vus, findings)."""
    import urllib.parse
    findings = []
    q = {"per_page": str(int(depth))}
    if branch:
        q["sha"] = branch
    url = (f"https://api.github.com/repos/{full_name}/commits?"
           f"{urllib.parse.urlencode(q)}")
    data, _ = _api_get_json(url, token)
    if not data or not isinstance(data, list):
        return 0, findings
    n = 0
    for c in data:
        sha_full = c.get("sha", "") if isinstance(c, dict) else ""
        if not sha_full:
            continue
        n += 1
        co = (c.get("commit", {}) or {}) if isinstance(c, dict) else {}
        au = (co.get("author", {}) or {})
        date = au.get("date", "")
        author = au.get("name", "")
        durl = f"https://api.github.com/repos/{full_name}/commits/{sha_full}"
        detail, _ = _api_get_json(durl, token)
        if not detail or not isinstance(detail, dict):
            continue
        for fh in detail.get("files", []) or []:
            fname = fh.get("filename", "")
            patch = fh.get("patch", "") or ""
            if not patch or not keep_remote_path(fname):
                continue
            for raw in patch.splitlines():
                if raw.startswith("+") and not raw.startswith("+++"):
                    for part in check(raw[1:]):
                        findings.append(_wrap_history_finding(
                            part, full_name, fname, sha_full[:7], date, author))
    return n, findings


# ------------------------------------------------------- quota / estimation
def print_api_estimate(n_repos, max_files_per_repo, extra_per_repo=0, label=""):
    """Affiche ~N appels API estimes AVANT de consommer le quota."""
    if max_files_per_repo and max_files_per_repo > 0:
        reads = n_repos * (1 + extra_per_repo + max_files_per_repo)
        print(f"[estimation] ~{reads} appels API max ({n_repos} depot(s) x "
              f"1 arbre + {extra_per_repo} suppl. + {max_files_per_repo} fichiers max)"
              f"{(' — ' + label) if label else ''}. Quota : 5000/h avec token.")
    else:
        print(f"[estimation] SANS PLAFOND de fichiers ({n_repos} depot(s)) : "
              f"1 appel arbre + 1 appel par fichier par depot"
              f"{(' — ' + label) if label else ''}. Quota : 5000/h avec token.")


def repo_passes_filters(info: dict, min_stars=0, topic="", exclude_language="") -> bool:
    """Filtres de veille pour un objet depot GitHub (decouverte + --all)."""
    try:
        if min_stars and int(info.get("stargazers_count") or 0) < int(min_stars):
            return False
    except (TypeError, ValueError):
        pass
    if exclude_language and (info.get("language") or "").lower() == exclude_language.lower():
        return False
    if topic:
        topics = info.get("topics") or []
        if topics and topic.lower() not in [str(t).lower() for t in topics]:
            return False
    return True


def fail_exit_code(args, findings) -> int:
    """--fail-on-find : exit 1 si >= 1 occurrence. --strict : seulement les
    non-allowlistees (les [ignore] ne font pas echouer)."""
    if not getattr(args, "fail_on_find", False):
        return 0
    if getattr(args, "strict", False):
        relevant = [f for f in findings if not f.get("ignored")]
    else:
        relevant = findings
    return 1 if relevant else 0


# ================================================================ mots-cles
# Chaque ligne de mots_cles.txt peut etre :
#   - un texte simple    : API_KEY        -> "contient API_KEY" (insensible a la casse par defaut)
#   - un joker           : sk-*           -> * = n'importe quoi, ? = 1 caractere
#   - une regex Python   : regex:sk-[A-Za-z0-9]{20,}  -> prefixe "regex:"
# Les jokers utilisent fnmatch (*, ?, [seq]) sans toucher au mode simple.
def load_keywords(path: Path):
    """Lit le fichier texte de mots-cles : un motif par ligne.
    Ignore les lignes vides et celles qui commencent par #."""
    p = Path(path)
    if not p.exists():
        print(f"Fichier mots-cles introuvable : {p}")
        sys.exit(2)
    raw = p.read_text(encoding="utf-8-sig", errors="replace").splitlines()
    seen = set()
    keywords = []
    for line in raw:
        kw = line.strip()
        if not kw or kw.startswith("#"):
            continue
        if kw not in seen:
            seen.add(kw)
            keywords.append(kw)
    if not keywords:
        print(f"Aucun mot-cle valide dans {p} (un par ligne, # = commentaire).")
        sys.exit(2)
    return keywords


def compile_patterns(keywords, case_sensitive: bool = False):
    """Compile chaque motif en testeur (kind, testeur, libelle).
    kind = 'contains' | 'wildcard' | 'regex'. Les regex invalides sont rejetees
    avec un message clair (le scan continue avec les motifs valides)."""
    import fnmatch
    compiled = []
    flags = 0 if case_sensitive else re.IGNORECASE
    for kw in keywords:
        if kw.startswith("regex:"):
            body = kw[len("regex:"):].strip()
            if not body:
                print(f"[motif ignore] regex vide : {kw}")
                continue
            try:
                rx = re.compile(body, flags)
            except re.error as e:
                print(f"[motif ignore] regex invalide '{kw}' : {e}")
                continue
            compiled.append({"keyword": kw, "kind": "regex", "rx": rx})
        elif "*" in kw or "?" in kw or ("[" in kw and "]" in kw):
            # Joker : on l'enveloppe en *motif* pour chercher PARTOUT dans la ligne
            # (sk-* trouve "...xxx sk-abc999..." meme avec du texte autour).
            wrapped = kw if (kw.startswith("*") and kw.endswith("*")) else f"*{kw}*"
            if case_sensitive:
                compiled.append({"keyword": kw, "kind": "wildcard",
                                 "match": lambda line, w=wrapped: fnmatch.fnmatchcase(line, w)})
            else:
                low = wrapped.lower()
                compiled.append({"keyword": kw, "kind": "wildcard",
                                 "match": lambda line, w=low: fnmatch.fnmatchcase(line.lower(), w)})
        else:
            compiled.append({"keyword": kw, "kind": "contains", "text": kw})
    if not compiled:
        print("Aucun motif valide (regex toutes invalides ?). Abandon.")
        sys.exit(2)
    kinds = {}
    for c in compiled:
        kinds[c["kind"]] = kinds.get(c["kind"], 0) + 1
    detail = ", ".join(f"{v} {k}" for k, v in kinds.items())
    print(f"[motifs] {len(compiled)} motif(s) compiles ({detail}).")
    return compiled


def match_line(line: str, compiled, case_sensitive: bool = False):
    """Teste UNE ligne contre tous les motifs. Retourne la liste des motifs trouves."""
    hay = line if case_sensitive else line.lower()
    hits = []
    for c in compiled:
        kind = c["kind"]
        if kind == "contains":
            kw = c["text"]
            if (kw in line) if case_sensitive else (kw.lower() in hay):
                hits.append(c)
        elif kind == "wildcard":
            try:
                if c["match"](line):
                    hits.append(c)
            except Exception:
                continue
        else:  # regex
            try:
                if c["rx"].search(line):
                    hits.append(c)
            except Exception:
                continue
    return hits


def matched_text(line: str, entry, case_sensitive: bool = False) -> str:
    """Extrait preis ce qui a matche (pour le detail du rapport) :
    texte exact, portion du joker, ou groupe regex."""
    kind = entry["kind"]
    if kind == "regex":
        m = entry["rx"].search(line)
        if m:
            return m.group(0)[:MAX_LINE_PREVIEW]
        return entry["keyword"]
    if kind == "wildcard":
        return entry["keyword"]
    kw = entry["text"]
    if case_sensitive:
        i = line.find(kw)
        return kw if i >= 0 else kw
    low = line.lower()
    i = low.find(kw.lower())
    if i < 0:
        return kw
    return line[i:i + len(kw)]


def ensure_patterns(obj, case_sensitive: bool = False):
    """Accepte une liste brute de motifs (str) ou deja compilee : compile si besoin."""
    if not obj:
        return []
    if isinstance(obj[0], dict) and "kind" in obj[0]:
        return obj
    return compile_patterns(list(obj), case_sensitive=case_sensitive)


def read_local_scan_text(path: Path):
    """Lit un fichier local si les filtres de scan l'autorisent.
    Retourne None pour un fichier exclu, trop gros ou illisible."""
    try:
        if _excluded(path):
            return None
        if not keep_local_path(path):
            return None
        if path.suffix.lower() in SKIP_EXT:
            return None
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        return read_text_file(path)
    except Exception:
        return None


def keyword_findings_from_text(text: str, file_label: str, patterns,
                               case_sensitive: bool = False, repo: str = "",
                               source: str = "", branch: str = ""):
    """Applique les motifs mots-cles a un contenu deja lu (local ou distant)."""
    patterns = ensure_patterns(patterns, case_sensitive)
    findings = []
    ctx_width = int(OPTS.get("context") or 0)
    lines = text.splitlines()
    for num, line in enumerate(lines, start=1):
        for entry in match_line(line, patterns, case_sensitive):
            preview = line.strip()
            if len(preview) > MAX_LINE_PREVIEW:
                preview = preview[:MAX_LINE_PREVIEW] + "... [tronque]"
            item = {
                "keyword": entry["keyword"],
                "kind": entry["kind"],
                "matched": matched_text(line, entry, case_sensitive),
                "file": file_label,
                "line": num,
                "detail": preview,
                "context": with_context(lines, num, ctx_width),
            }
            if repo:
                item["repo"] = repo
            if source:
                item["source"] = source
            if branch:
                item["branch"] = branch
            findings.append(item)
        for h in entropy_hits_for_line(line):
            item = {
                "keyword": h["keyword"],
                "kind": h["kind"],
                "matched": h["matched"],
                "file": file_label,
                "line": num,
                "detail": line.strip()[:MAX_LINE_PREVIEW],
                "entropy": h.get("entropy"),
                "context": with_context(lines, num, ctx_width),
            }
            if repo:
                item["repo"] = repo
            if source:
                item["source"] = source
            if branch:
                item["branch"] = branch
            findings.append(item)
    return findings


def secret_findings_from_text(text: str, file_label: str, reveal: bool = False,
                              repo: str = "", source: str = "",
                              branch: str = ""):
    """Applique la detection de secrets a un contenu deja lu (local ou distant)."""
    findings = []
    ctx_width = int(OPTS.get("context") or 0)
    lines = text.splitlines()
    hits = detect_secrets(text)
    for hit in hits:
        findings.append(_secret_finding(
            hit, file_label, repo=repo, source=source, branch=branch,
            lines=lines, reveal=reveal, context_width=ctx_width))
    if not entropy_enabled():
        return findings
    known = {h["secret"] for h in hits}
    seen_toks = set()
    for num, line in enumerate(lines, start=1):
        for h in entropy_hits_for_line(line, respect_filters=True):
            tok = h["matched"]
            if tok in seen_toks or tok in known:
                continue
            if known and any(tok in secret or secret in tok for secret in known):
                continue
            seen_toks.add(tok)
            item = {
                "rule": "[entropie]",
                "file": file_label,
                "line": num,
                "match_preview": tok if reveal else mask_secret(tok),
                "revealed": bool(reveal),
                "detail": "[entropie] " + _mask_text(
                    line.strip(), tok, reveal)[:MAX_LINE_PREVIEW],
                "entropy": h.get("entropy"),
                "context": _sanitize_context(
                    with_context(lines, num, ctx_width), reveal),
            }
            if repo:
                item["repo"] = repo
            if source:
                item["source"] = source
            if branch:
                item["branch"] = branch
            findings.append(item)
    return findings


def scan_file_for_keywords(path: Path, patterns, case_sensitive: bool = False):
    """Cherche chaque motif (contains / wildcard / regex) dans un fichier, ligne par ligne.
    `patterns` = liste compilee par compile_patterns() (ou liste brute, compilee a la volee).
    Retourne une liste de dicts : keyword, kind, matched, file, line, detail."""
    text = read_local_scan_text(path)
    if text is None:
        return []
    return keyword_findings_from_text(text, str(path), patterns, case_sensitive)



def scan_local_tree_keywords(root: Path, patterns, case_sensitive: bool = False):
    """Scanne toute une arborescence avec les motifs compiles."""
    patterns = ensure_patterns(patterns, case_sensitive)
    root = root.resolve()
    all_findings = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            scanned += 1
            all_findings.extend(scan_file_for_keywords(p, patterns, case_sensitive))
    return scanned, all_findings


def write_txt_report(report_path: Path, keywords, scanned_files: int,
                     findings, source_label: str, case_sensitive: bool,
                     author_users=None, author_hits=None):
    """Ecrit le fichier texte de resultats demande : quoi / ou / detail."""
    now = datetime.now(timezone.utc).isoformat()
    lines = []
    lines.append("=" * 70)
    lines.append("RAPPORT DE RECHERCHE PAR MOTS-CLES")
    lines.append("=" * 70)
    lines.append(f"Date (UTC)        : {now}")
    lines.append(f"Source scannee    : {source_label}")
    if author_users:
        lines.append(f"Filtre auteur     : depots modifies par {', '.join(author_users)}")
        for repo in sorted((author_hits or {}).keys()):
            info = (author_hits or {}).get(repo, {})
            if info:
                lines.append(f"  - {repo} : {info.get('user', '')} "
                             f"{info.get('date', '')} {info.get('sha', '')} :: {info.get('message', '')}")
    lines.append(f"Fichiers scannes  : {scanned_files}")
    lines.append(f"Motifs cherches ({len(keywords)}) : {', '.join(keywords)}")
    lines.append(f"Casse sensible    : {'oui' if case_sensitive else 'non'}")
    lines.append(f"Occurrences       : {len(findings)}")
    lines.append("")
    if not findings:
        lines.append("Aucun motif trouve.")
    else:
        # Regroupe par motif pour lisibilite
        by_kw = {}
        for f in findings:
            by_kw.setdefault(f["keyword"], []).append(f)
        idx = 0
        for kw in keywords:
            items = by_kw.get(kw, [])
            if not items:
                continue
            kind = items[0].get("kind", "contains")
            lines.append(f"--- Motif ({kind}) : \"{kw}\" ({len(items)} occurrence(s)) ---")
            for f in items:
                idx += 1
                repo = f.get("repo", "")
                where = f["file"]
                lines.append(f"[{idx}] Trouve : \"{f['keyword']}\" (type {f.get('kind', '?')})")
                if repo:
                    lines.append(f"     Depot   : {repo}")
                lines.append(f"     Endroit  : {where} (ligne {f['line']})")
                if f.get("matched") and f["matched"] != f["keyword"]:
                    lines.append(f"     Extrait  : {f['matched']}")
                lines.append(f"     Detail   : {f['detail'] if f['detail'] else '(ligne vide)'}")
                if f.get("ignored"):
                    lines.append("     [ignore/allowlist]")
                for c in f.get("context") or []:
                    lines.append(f"       {c.get('pos', '')} l.{c.get('line', '?')} : {c.get('text', '')}")
                lines.append("")
    lines.append("=" * 70)
    lines.append("Fin du rapport.")
    report_path = Path(report_path)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ================================================================ mode secrets (existant)
def mask_secret(value: str) -> str:
    value = value or ""
    if len(value) <= 8:
        return "***MASKED***"
    return f"***MASKED***{value[-4:]} (len={len(value)})"


def scan_file(path: Path, reveal: bool = False):
    text = read_local_scan_text(path)
    if text is None:
        return []
    return secret_findings_from_text(text, str(path), reveal=reveal)


def scan_file_both(path: Path, patterns, case_sensitive: bool = False,
                   reveal: bool = False):
    """Lit un fichier UNE fois et applique les deux detecteurs."""
    text = read_local_scan_text(path)
    if text is None:
        return [], []
    return (
        keyword_findings_from_text(text, str(path), patterns, case_sensitive),
        secret_findings_from_text(text, str(path), reveal=reveal),
    )


def scan_local_tree(root: Path, reveal: bool = False):
    root = root.resolve()
    all_findings = []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            scanned += 1
            all_findings.extend(scan_file(p, reveal=reveal))
    return scanned, all_findings


def scan_local_tree_both(root: Path, patterns, case_sensitive: bool = False,
                         reveal: bool = False):
    """Scanne une arborescence UNE fois : mots-cles + secrets."""
    root = root.resolve()
    kw_findings, secret_findings = [], []
    scanned = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            scanned += 1
            kw, sec = scan_file_both(p, patterns, case_sensitive, reveal)
            kw_findings.extend(kw)
            secret_findings.extend(sec)
    return scanned, kw_findings, secret_findings


def scan_local_target(root: Path, patterns, case_sensitive: bool = False,
                      both: bool = False, reveal: bool = False):
    """Scan local : renvoie (fichiers, findings mots-cles, findings secrets)."""
    if both:
        return scan_local_tree_both(root, patterns, case_sensitive, reveal)
    scanned, findings = scan_local_tree_keywords(
        root, patterns, case_sensitive=case_sensitive)
    return scanned, findings, []



# ------------------------------------------------------- GitHub (clone de depots)
def github_api_list_repos(token: str, mode: str = "me", owner: str = "", per_page: int = 100):
    import urllib.request
    import urllib.error
    import urllib.parse

    repos = []
    page = 1
    if mode == "org":
        base = f"https://api.github.com/orgs/{owner}/repos"
        query = {"per_page": per_page, "page": page, "sort": "full_name"}
    else:
        # "me" = TOUS mes depots accessibles via le token (perso + collabs + orgs),
        # sans avoir a indiquer un depot particulier.
        # affiliation=all equivalent : owner + collaborator + organization_member.
        base = "https://api.github.com/user/repos"
        query = {"per_page": per_page, "page": page, "visibility": "all",
                 "affiliation": "owner,collaborator,organization_member",
                 "sort": "full_name"}

    while True:
        query["page"] = page
        url = f"{base}?{urllib.parse.urlencode(query)}"
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "own-repo-keyword-scan/1.0",
            })
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            headers = dict(getattr(e, "headers", {}) or {})
            if e.code == 403 and str(headers.get("X-RateLimit-Remaining", "")) == "0":
                if _api_wait_for_quota(headers, url):
                    continue  # rejoue la meme page apres l'attente quota
                break
            print(f"  [API HTTP {e.code}] {url}")
            break
        except Exception as e:
            print(f"  [API erreur] {url} :: {e}")
            break
        if not data:
            break
        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    return repos


# ----------------------------------- decouverte publique (sans ciblage)
# La decouverte (fenetre recente / tirage aleatoire) porte sur des depots
# PUBLICS tiers : elle sert a la RECHERCHE DE CODE (mode mots-cles).
# Elle est INTERDITE en mode SECRETS (pas de moisson de cles d'autrui).
DISCOVER_CHOICES = ("updated", "created", "random")
# Borne haute approximative des IDs de depots GitHub, pour le tirage aleatoire
# via GET /repositories?since=<id> (les IDs sont croissants, non denses).
MAX_REPO_ID_GUESS = 200_000_000


def parse_window(value: str) -> timedelta:
    """Convertit une fenetre '12h' / '30m' / '7d' (nombre seul = heures) en timedelta."""
    m = re.match(r"^\s*(\d+)\s*([mMhHdD])?\s*$", value or "")
    if not m:
        raise ValueError(f"fenetre invalide : {value!r} (exemples : 30m, 12h, 7d)")
    n = int(m.group(1))
    unit = (m.group(2) or "h").lower()
    if n <= 0:
        raise ValueError(f"fenetre invalide : {value!r} (doit etre > 0)")
    if unit == "m":
        return timedelta(minutes=n)
    if unit == "d":
        return timedelta(days=n)
    return timedelta(hours=n)


def github_api_search_repos(token: str, query: str, sort: str = "updated",
                            order: str = "desc", per_page: int = 100,
                            max_pages: int = 10):
    """Recherche de depots PUBLICS via GET /search/repositories (max ~1000 resultats).
    Retourne la liste des items bruts. S'arrete proprement sur quota (403)."""
    import urllib.parse
    items = []
    for page in range(1, max_pages + 1):
        q = {"q": query, "sort": sort, "order": order,
             "per_page": per_page, "page": page}
        url = f"https://api.github.com/search/repositories?{urllib.parse.urlencode(q)}"
        data, _ = _api_get_json(url, token)
        if not data or not isinstance(data, dict):
            break
        batch = data.get("items", []) or []
        items.extend(batch)
        if data.get("incomplete_results"):
            print("  [attention] resultats de recherche incomplets "
                  "(timeout cote GitHub) : echantillon partiel.")
        if len(batch) < per_page:
            break
        if len(items) >= 1000:
            print("  [limite] plafond de 1000 resultats de l'API Search atteint.")
            break
    return items


def github_api_public_since(since_id: int, token: str = "", per_page: int = 100):
    """Un lot de depots PUBLICS via GET /repositories?since=<id> (ordre d'ID).
    Le token est optionnel (quota plus genereux avec). Retourne une liste (peut etre vide)."""
    import urllib.request
    import urllib.error
    import urllib.parse
    url = ("https://api.github.com/repositories?"
           f"{urllib.parse.urlencode({'since': since_id, 'per_page': per_page})}")
    headers = {"Accept": "application/vnd.github+json",
               "User-Agent": "own-repo-keyword-scan/1.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data if isinstance(data, list) else []
    except urllib.error.HTTPError as e:
        print(f"  [API HTTP {e.code}] tirage aleatoire (depuis ID {since_id})")
        return []
    except Exception as e:
        print(f"  [API erreur] tirage aleatoire :: {e}")
        return []


def discover_repos(token: str, discover: str, window: str = "12h", language: str = "",
                   sample: int = 20, include_forks: bool = False,
                   include_archived: bool = False, max_repos: int = 0,
                   seed=None, min_stars: int = 0, topic: str = "",
                   exclude_language: str = ""):
    """Decouverte de depots PUBLICS : 'updated' (pousses sur la fenetre),
    'created' (crees sur la fenetre) ou 'random' (tirage aleatoire).
    Applique les filtres forks/archives (+ --min-stars/--topic/--exclude-language
    pour la veille pertinente), puis un echantillon aleatoire (`sample`,
    0 = garde tout, reproductible via --seed) et le plafond `max_repos`."""
    rng = random.Random(seed) if seed is not None else random
    names = []
    if discover in ("updated", "created"):
        if not token:
            print("Decouverte publique (fenetre recente) : il faut un token "
                  "(--token ou env GITHUB_TOKEN, quota Search API).")
            sys.exit(2)
        try:
            delta = parse_window(window)
        except ValueError as e:
            print(f"[decouverte] {e}")
            sys.exit(2)
        cutoff = datetime.now(timezone.utc) - delta
        stamp = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
        field = "pushed" if discover == "updated" else "created"
        sort = "updated" if discover == "updated" else "created"
        query = f"{field}:>{stamp}"
        if language:
            query += f" language:{language.strip()}"
        label = ("modifies (push)" if discover == "updated" else "crees")
        print(f"[decouverte] depots publics {label} depuis {window} "
              f"(fenetre: {field} > {stamp}) ...")
        for r in github_api_search_repos(token, query, sort=sort):
            if r.get("fork") and not include_forks:
                continue
            if r.get("archived") and not include_archived:
                continue
            if not repo_passes_filters(r, min_stars, topic, exclude_language):
                continue
            if r.get("full_name"):
                names.append(r["full_name"])
        print(f"[decouverte] {len(names)} candidat(s) public(s) "
              f"(forks/archives exclus sauf options).")
    else:  # random
        print("[decouverte] tirage aleatoire de depots publics ...")
        if seed is not None:
            print(f"[decouverte] graine --seed {seed} (tirage reproductible).")
        seen = set()
        draws = max(2, (sample + 99) // 100 + 1) if sample and sample > 0 else 2
        for _ in range(draws):
            since = rng.randint(0, MAX_REPO_ID_GUESS)
            for r in github_api_public_since(since, token):
                if r.get("fork") and not include_forks:
                    continue
                if r.get("archived") and not include_archived:
                    continue
                if not repo_passes_filters(r, min_stars, topic, exclude_language):
                    continue
                fn = r.get("full_name")
                if fn and fn not in seen:
                    seen.add(fn)
                    names.append(fn)
            if sample and sample > 0 and len(names) >= sample:
                break
        print(f"[decouverte] {len(names)} candidat(s) tire(s) au hasard.")
    if sample and sample > 0 and len(names) > sample:
        names = rng.sample(names, sample)
        print(f"[decouverte] echantillon aleatoire : {sample} depot(s) retenu(s).")
    if max_repos and max_repos > 0:
        names = names[:max_repos]
        print(f"[decouverte] limite : {max_repos} depot(s) max.")
    else:
        print(f"[decouverte] {len(names)} depot(s) public(s) a consulter (AUCUN clone).")
    return names


def save_discovered_list(names, path_str):
    """--save-list : ecrit les depots decouverts (un owner/name par ligne),
    pour rescanner plus tard via --repos-file (sans re-consommer le quota)."""
    p = Path(path_str)
    p.write_text("\n".join(names) + ("\n" if names else ""), encoding="utf-8")
    print(f"[save-list] {len(names)} depot(s) ecrit(s) dans {p} (rescan : --repos-file {p}).")
    return p


def git_clone_shallow(clone_url: str, dest: Path, token: str):
    dest.parent.mkdir(parents=True, exist_ok=True)
    authed = clone_url.replace("https://", f"https://oauth2:{token}@")
    cmd = ["git", "clone", "--depth", "1", authed, str(dest)]
    print(f"  [clone] {clone_url} -> {dest}")
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        print(f"  [clone FAILED] {clone_url}")
        return False
    return True


def load_repo_list(path: Path):
    """Lit un fichier texte de depots cibles : un 'owner/name' par ligne.
    Ignore lignes vides et commentaires #. Accepte les URL GitHub completes."""
    p = resolve_input_path(path)
    if not p.exists():
        print(f"Fichier depots introuvable : {p}")
        sys.exit(2)
    repos = []
    seen = set()
    for line in p.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        name = line.strip()
        if not name or name.startswith("#"):
            continue
        repo = normalize_repo_target(name)
        if not repo:
            print(f"[repos] ignore (format attendu owner/name ou URL GitHub) : {line}")
            continue
        if repo not in seen:
            seen.add(repo)
            repos.append(repo)
    if not repos:
        print(f"Aucun depot valide dans {p} (un 'owner/name' par ligne).")
        sys.exit(2)
    return repos


def parse_target_repos(repo_args, repos_file):
    """Combine --repo (repetable, virgules acceptees) + --repos-file."""
    targets = []
    seen = set()
    if repo_args:
        for item in repo_args:
            for part in item.split(","):
                name = normalize_repo_target(part)
                if not name:
                    print(f"[repos] ignore (format attendu owner/name) : {part}")
                    continue
                if name not in seen:
                    seen.add(name)
                    targets.append(name)
    if repos_file:
        for name in load_repo_list(Path(repos_file)):
            if name not in seen:
                seen.add(name)
                targets.append(name)
    return targets


# Dernier commit vu par le filtre auteur : {repo: info}. Remplit par
# filter_repos_by_editors(), repris dans les rapports (JSON + libelle).
AUTHOR_HITS = {}


def parse_user_list(user_args):
    """Combine --modified-by repetable + virgules. Retourne logins uniques."""
    users = []
    seen = set()
    for item in user_args or []:
        for part in item.split(","):
            u = part.strip().lstrip("@")
            if not u:
                continue
            if u not in seen:
                seen.add(u)
                users.append(u)
    return users


def repo_touched_by_user(token: str, full_name: str, username: str,
                         branch: str = "", since: str = "", until: str = ""):
    """Dit si `username` a modifie le depot (commit trouve via API Commits).
    Retourne (True/False, info) avec dernier commit vu (sha/date/message).
    SANS cloner : GET /repos/{full}/commits?author=...&per_page=5."""
    import urllib.parse
    q = {"author": username, "per_page": "5"}
    if branch:
        q["sha"] = branch
    if since:
        q["since"] = since
    if until:
        q["until"] = until
    url = f"https://api.github.com/repos/{full_name}/commits?{urllib.parse.urlencode(q)}"
    data, _ = _api_get_json(url, token)
    if not data:
        return False, {}
    # data = liste de commits (vide = jamais modifie par cet utilisateur)
    first = data[0] if isinstance(data, list) and data else {}
    commit = first.get("commit", {}) if isinstance(first, dict) else {}
    author_info = commit.get("author", {}) if isinstance(commit, dict) else {}
    return True, {
        "user": username,
        "sha": (first.get("sha", "")[:7] if isinstance(first, dict) else ""),
        "date": author_info.get("date", ""),
        "message": (commit.get("message", "")[:120] if isinstance(commit, dict) else ""),
    }


def filter_repos_by_editors(token: str, full_names, usernames,
                            branch: str = "", since: str = "", until: str = ""):
    """Garde uniquement les depots modifies par AU MOINS un des utilisateurs.
    Retourne (gardes, details {repo: info}). Affiche la progression."""
    if not usernames:
        return list(full_names), {}
    print(f"[filtre auteur] depots modifies par : {', '.join(usernames)}"
          f"{f' (branche {branch})' if branch else ''}"
          f"{f' (depuis {since})' if since else ''}"
          f"{f' (jusqu a {until})' if until else ''} ...")
    kept = []
    details = {}
    for full_name in full_names:
        hit = None
        for u in usernames:
            ok, info = repo_touched_by_user(token, full_name, u, branch, since, until)
            if ok:
                hit = info
                break
        if hit:
            print(f"  [garde] {full_name} (modifie par {hit.get('user')}, "
                  f"{hit.get('date', '?')} {hit.get('sha', '')})")
            kept.append(full_name)
            details[full_name] = hit
        else:
            print(f"  [exclu] {full_name} (jamais modifie par {', '.join(usernames)})")
    print(f"[filtre auteur] {len(kept)}/{len(full_names)} depot(s) retenu(s).")
    return kept, details


def _git_toplevel(path: Path):
    """Racine du depot git contenant `path` (ou None si pas un depot git / git absent)."""
    try:
        r = subprocess.run(["git", "-C", str(path), "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=30)
        if r.returncode == 0 and r.stdout.strip():
            return Path(r.stdout.strip())
    except Exception:
        pass
    return None


def local_dir_touched_by_user(root: Path, username: str, since: str = "", until: str = ""):
    """Dit si `username` a commite dans ce depot git LOCAL (git log --author).
    Retourne (True/False, info) ; (None, {}) si pas un depot git (inverifiable)."""
    if _git_toplevel(root) is None:
        return None, {}
    cmd = ["git", "-C", str(root), "log", f"--author={username}",
           "--format=%H|%ad|%s", "--date=short", "-n", "1"]
    if since:
        cmd.append(f"--since={since}")
    if until:
        cmd.append(f"--until={until}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except Exception:
        return None, {}
    out = (r.stdout or "").strip()
    if r.returncode != 0 or not out:
        return False, {}
    parts = out.split("|", 2)
    return True, {
        "user": username,
        "sha": parts[0][:7] if parts else "",
        "date": parts[1] if len(parts) > 1 else "",
        "message": parts[2][:120] if len(parts) > 2 else "",
    }


def filter_local_dirs_by_editors(dirs, usernames, since: str = "", until: str = ""):
    """Garde les dossiers locaux modifies par AU MOINS un des utilisateurs (depots git).
    Les dossiers NON-git sont gardes avec un avertissement (auteur inverifiable).
    Remplit aussi AUTHOR_HITS {dossier: info} pour les rapports."""
    if not usernames:
        return list(dirs)
    print(f"[filtre auteur local] dossiers modifies par : {', '.join(usernames)} ...")
    AUTHOR_HITS.clear()
    kept = []
    for d in dirs:
        root = Path(d)
        decided = False
        for u in usernames:
            ok, info = local_dir_touched_by_user(root, u, since, until)
            if ok is None:
                print(f"  [garde quand meme] {d} (pas un depot git : auteur inverifiable)")
                kept.append(d)
                decided = True
                break
            if ok:
                print(f"  [garde] {d} (modifie par {info.get('user')}, "
                      f"{info.get('date', '?')} {info.get('sha', '')})")
                kept.append(d)
                AUTHOR_HITS[d] = info
                decided = True
                break
        if not decided:
            print(f"  [exclu] {d} (jamais modifie par {', '.join(usernames)})")
    print(f"[filtre auteur local] {len(kept)}/{len(dirs)} dossier(s) retenu(s).")
    return kept


def github_api_get_repo(token: str, full_name: str):
    """Recupere les infos d'UN depot via GET /repos/{owner}/{repo}."""
    import urllib.request
    import urllib.error
    url = f"https://api.github.com/repos/{full_name}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "own-repo-keyword-scan/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  [repo introuvable / non autorise] {full_name} (HTTP {e.code})")
        return None


def authorize_secret_targets(args, names) -> bool:
    """Le mode SECRETS est toujours autorise : aucune verification de droit
    d'ecriture, aucune attestation, quel que soit le depot cible."""
    return True


# -------------------------------------------- recherche DISTANTE sans clonage
def _api_wait_for_quota(headers, url=""):
    """Sur 403 quota : attend jusqu'a X-RateLimit-Reset (+5s marge) sauf --no-retry.
    Retourne True si on peut reessayer, False sinon."""
    if OPTS.get("no_retry"):
        print("  [--no-retry] quota atteint, abandon de cet appel.")
        return False
    try:
        reset = int(headers.get("X-RateLimit-Reset", "0") or 0)
    except (TypeError, ValueError):
        reset = 0
    wait = max(0, reset - int(time.time())) + 5 if reset else 60
    wait = min(wait, 3600)  # plafond 1h
    print(f"  [quota] limite API atteinte pour {url or 'appel'} : "
          f"attente ~{wait}s puis reprise...")
    try:
        time.sleep(wait)
    except KeyboardInterrupt:
        print("  [quota] attente interrompue.")
        return False
    return True


def _api_get_json(url: str, token: str, timeout: int = 30, _retried: bool = False):
    """GET JSON sur l'API GitHub. Retourne (data, headers) ou (None, headers).
    Sur 403 avec X-RateLimit-Remaining=0 : attend le reset et reprend (sauf --no-retry)."""
    import urllib.request
    import urllib.error
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "own-repo-keyword-scan/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw), dict(resp.headers.items())
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            body = ""
        headers = dict(getattr(e, "headers", {}) or {})
        remaining = str(headers.get("X-RateLimit-Remaining", ""))
        if e.code == 403 and remaining == "0" and not _retried:
            if _api_wait_for_quota(headers, url):
                return _api_get_json(url, token, timeout, _retried=True)
            return None, headers
        print(f"  [API HTTP {e.code}] {url} :: {body}")
        return None, headers
    except Exception as e:
        print(f"  [API erreur] {url} :: {e}")
        return None, {}


def _api_get_raw(url: str, token: str, timeout: int = 30, _retried: bool = False):
    """GET contenu brut (Accept: raw). Retourne bytes ou None.
    Meme retry quota 403 que _api_get_json."""
    import urllib.request
    import urllib.error
    headers = {
        "Accept": "application/vnd.github.raw",
        "User-Agent": "own-repo-keyword-scan/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        headers = dict(getattr(e, "headers", {}) or {})
        remaining = str(headers.get("X-RateLimit-Remaining", ""))
        if e.code == 403 and remaining == "0" and not _retried:
            if _api_wait_for_quota(headers, url):
                return _api_get_raw(url, token, timeout, _retried=True)
            return None
        print(f"  [fichier illisible HTTP {e.code}] {url}")
        return None
    except Exception as e:
        print(f"  [fichier erreur] {url} :: {e}")
        return None


def get_repo_default_branch(token: str, full_name: str, wanted: str = "") -> str:
    """Branche a scanner : --branch si precise, sinon branche par defaut du depot."""
    if wanted:
        return wanted
    info = github_api_get_repo(token, full_name)
    if info and info.get("default_branch"):
        return info["default_branch"]
    return "main"


def list_remote_tree(token: str, full_name: str, branch: str):
    """Liste les fichiers via Git Trees API (recursive=1), SANS cloner.
    Retourne (branch_utilisee, [paths])."""
    import urllib.parse
    ref = urllib.parse.quote(branch, safe="")
    url = f"https://api.github.com/repos/{full_name}/git/trees/{ref}?recursive=1"
    data, _ = _api_get_json(url, token)
    if not data or "tree" not in data:
        return branch, []
    if data.get("truncated"):
        print(f"  [attention] arborescence tronquee par l'API pour {full_name} "
              f"(gros depot) : resultats partiels.")
    paths = []
    for node in data.get("tree", []):
        if node.get("type") != "blob":
            continue
        p = node.get("path", "")
        if not p:
            continue
        # memes exclusions qu'en local (extensions + fichiers outil)
        if Path(p).suffix.lower() in SKIP_EXT:
            continue
        if _excluded(Path(p)):
            continue
        size = node.get("size") or 0
        if size and size > MAX_FILE_BYTES:
            continue
        paths.append(p)
    return branch, paths


def fetch_remote_file_text(token: str, full_name: str, path: str, ref: str,
                           max_bytes: int = 1_000_000):
    """Recupere le contenu d'UN fichier via Contents API (raw), SANS cloner."""
    import urllib.parse
    quoted = urllib.parse.quote(path, safe="/")
    ref_q = urllib.parse.quote(ref, safe="")
    url = f"https://api.github.com/repos/{full_name}/contents/{quoted}?ref={ref_q}"
    raw = _api_get_raw(url, token)
    if raw is None:
        return None
    if len(raw) > max_bytes:
        print(f"  [skip] gros fichier distant ({len(raw)} octets) : {full_name}:{path}")
        return None
    return raw.decode("utf-8", errors="replace")


def scan_remote_repo_keywords(token: str, full_name: str, patterns,
                              branch: str = "", case_sensitive: bool = False,
                              max_files_per_repo: int = 5000,
                              max_bytes: int = 1_000_000):
    """Scanne UN depot ENTIEREMENT A DISTANCE (aucun clone, aucun dossier local).
    `patterns` = liste compilee par compile_patterns() (ou liste brute, compilee a la volee)."""
    patterns = ensure_patterns(patterns, case_sensitive)
    use_branch = get_repo_default_branch(token, full_name, branch)
    print(f"- {full_name} (distant, branche {use_branch})")
    _, paths = list_remote_tree(token, full_name, use_branch)
    if max_files_per_repo and max_files_per_repo > 0 and len(paths) > max_files_per_repo:
        print(f"  [limite] {len(paths)} fichiers distants, scan des {max_files_per_repo} premiers "
              f"(--max-files-per-repo pour changer, 0 = sans limite).")
        paths = paths[:max_files_per_repo]
    print(f"  [distant] {len(paths)} fichier(s) a lire via API")
    findings = []
    scanned = 0
    for p in paths:
        if not keep_remote_path(p):
            continue
        text = fetch_remote_file_text(token, full_name, p, use_branch, max_bytes)
        if text is None:
            continue
        scanned += 1
        findings.extend(keyword_findings_from_text(
            text, f"{full_name}:{p}", patterns, case_sensitive,
            repo=full_name, source="remote", branch=use_branch))
    return scanned, findings



def scan_remote_repo_secrets(token: str, full_name: str, branch: str = "",
                             reveal: bool = False,
                             max_files_per_repo: int = 5000,
                             max_bytes: int = 1_000_000):
    """Audit secrets d'UN depot ENTIEREMENT A DISTANCE (aucun clone)."""
    use_branch = get_repo_default_branch(token, full_name, branch)
    print(f"- {full_name} (distant, branche {use_branch})")
    _, paths = list_remote_tree(token, full_name, use_branch)
    if max_files_per_repo and max_files_per_repo > 0 and len(paths) > max_files_per_repo:
        print(f"  [limite] {len(paths)} fichiers distants, scan des {max_files_per_repo} premiers.")
        paths = paths[:max_files_per_repo]
    print(f"  [distant] {len(paths)} fichier(s) a lire via API")
    findings = []
    scanned = 0
    for p in paths:
        if not keep_remote_path(p):
            continue
        text = fetch_remote_file_text(token, full_name, p, use_branch, max_bytes)
        if text is None:
            continue
        scanned += 1
        findings.extend(secret_findings_from_text(
            text, f"{full_name}:{p}", reveal=reveal,
            repo=full_name, source="remote", branch=use_branch))
    return scanned, findings


def scan_remote_repo_both(token: str, full_name: str, patterns, branch: str = "",
                          case_sensitive: bool = False, reveal: bool = False,
                          max_files_per_repo: int = 5000,
                          max_bytes: int = 1_000_000):
    """Scanne UN depot A DISTANCE : un seul arbre, un seul telechargement par
    fichier, puis les deux detecteurs sur le meme contenu."""
    patterns = ensure_patterns(patterns, case_sensitive)
    use_branch = get_repo_default_branch(token, full_name, branch)
    print(f"- {full_name} (distant, branche {use_branch})")
    _, paths = list_remote_tree(token, full_name, use_branch)
    if max_files_per_repo and max_files_per_repo > 0 and len(paths) > max_files_per_repo:
        print(f"  [limite] {len(paths)} fichiers distants, scan des {max_files_per_repo} premiers "
              f"(--max-files-per-repo pour changer, 0 = sans limite).")
        paths = paths[:max_files_per_repo]
    print(f"  [distant] {len(paths)} fichier(s) a lire via API (mots-cles + secrets)")
    kw_findings, secret_findings = [], []
    scanned = 0
    for p in paths:
        if not keep_remote_path(p):
            continue
        text = fetch_remote_file_text(token, full_name, p, use_branch, max_bytes)
        if text is None:
            continue
        scanned += 1
        label = f"{full_name}:{p}"
        kw_findings.extend(keyword_findings_from_text(
            text, label, patterns, case_sensitive,
            repo=full_name, source="remote", branch=use_branch))
        secret_findings.extend(secret_findings_from_text(
            text, label, reveal=reveal,
            repo=full_name, source="remote", branch=use_branch))
    return scanned, kw_findings, secret_findings


def scan_remote_target(token: str, full_name: str, patterns, branch: str = "",
                       case_sensitive: bool = False, both: bool = False,
                       reveal: bool = False, max_files_per_repo: int = 5000):
    """Scan distant : renvoie (fichiers, findings mots-cles, findings secrets)."""
    if both:
        return scan_remote_repo_both(
            token, full_name, patterns, branch=branch,
            case_sensitive=case_sensitive, reveal=reveal,
            max_files_per_repo=max_files_per_repo)
    scanned, findings = scan_remote_repo_keywords(
        token, full_name, patterns, branch=branch,
        case_sensitive=case_sensitive,
        max_files_per_repo=max_files_per_repo)
    return scanned, findings, []



def resolve_remote_repo_names(token, kind, owner, repo_args, repos_file, scan_all,
                              include_forks=False, include_archived=False,
                              max_repos=0, modified_by=None, since="", until="",
                              branch="", discover="", discover_window="12h",
                              discover_language="", discover_sample=20,
                              seed=None, min_stars=0, topic="",
                              exclude_language=""):
    """Retourne la liste des 'owner/name' a consulter A DISTANCE (sans cloner).
    Si modified_by : ne garde que les depots modifies par cet/ces utilisateur(s).
    Si discover : decouverte de depots PUBLICS (updated/created/random),
    incompatible avec --repo/--repos-file/--all/--kind/--owner/--modified-by."""
    if discover:
        if discover not in DISCOVER_CHOICES:
            print(f"--discover invalide : {discover!r} (choix : {', '.join(DISCOVER_CHOICES)}).")
            sys.exit(2)
        conflicts = []
        if parse_target_repos(repo_args, repos_file):
            conflicts.append("--repo/--repos-file")
        if scan_all:
            conflicts.append("--all")
        if kind != "me" or owner:
            conflicts.append("--kind/--owner")
        if modified_by and parse_user_list(modified_by):
            conflicts.append("--modified-by")
        if conflicts:
            print(f"[decouverte] incompatible avec {' + '.join(conflicts)} : "
                  f"la decouverte choisit elle-meme les depots publics.")
            sys.exit(2)
        return discover_repos(token, discover, window=discover_window,
                              language=discover_language, sample=discover_sample,
                              include_forks=include_forks,
                              include_archived=include_archived,
                              max_repos=max_repos, seed=seed,
                              min_stars=min_stars, topic=topic,
                              exclude_language=exclude_language)
    specific = parse_target_repos(repo_args, repos_file)
    if specific and not scan_all:
        names = specific
    else:
        if kind == "org" and not owner:
            print("Precise --owner pour --kind org (ex: --kind org --owner ma-org).")
            sys.exit(2)
        if not token:
            print("Il faut un token : --token ou env GITHUB_TOKEN (sur TON compte).")
            sys.exit(2)
        print(f"[GitHub distant] liste des depots (kind={kind}, owner={owner or 'token-owner'}) ...")
        repos = github_api_list_repos(token, mode=kind, owner=owner)
        print(f"[GitHub distant] {len(repos)} depot(s) trouve(s) via API.")
        names = []
        nf = na = nv = 0
        for r in repos:
            if r.get("fork") and not include_forks:
                nf += 1
                continue
            if r.get("archived") and not include_archived:
                na += 1
                continue
            if not repo_passes_filters(r, min_stars, topic, exclude_language):
                nv += 1
                continue
            if r.get("full_name"):
                names.append(r["full_name"])
        if nf or na or nv:
            print(f"[GitHub distant] exclus : {nf} fork(s), {na} archive(s), "
                  f"{nv} hors veille (etoiles/topic/langage).")
    # Filtre auteur (commits via API, SANS cloner)
    users = parse_user_list(modified_by) if modified_by else []
    if users:
        names, details = filter_repos_by_editors(token, names, users, branch, since, until)
        AUTHOR_HITS.clear()
        AUTHOR_HITS.update(details)
    if max_repos and max_repos > 0:
        names = names[:max_repos]
        print(f"[GitHub distant] limite : {max_repos} depot(s) max.")
    else:
        print(f"[GitHub distant] SANS LIMITE : {len(names)} depot(s) a consulter (aucun clone).")
    return names


# Dernier mode de decouverte effectivement utilise (CLI ou interactif),
# pour un libelle de rapport correct meme en interactif.
_LAST_DISCOVER = {"mode": "", "window": "12h", "language": ""}


def resolve_remote_names(token, kind, owner, repo_args, repos_file, scan_all,
                         interactive, local_args=None,
                         include_forks=False, include_archived=False,
                         max_repos=0, preset="", modified_by=None,
                         since="", until="", branch="",
                         discover="", discover_window="12h",
                         discover_language="", discover_sample=20,
                         seed=None, min_stars=0,
                         topic="", exclude_language=""):
    """Noms 'owner/name' a consulter A DISTANCE (aucun clone).
    Retourne (names, ilocal, iusers) : ilocal non vide = scan local interactif,
    iusers = filtre auteur saisi en interactif (peut etre vide)."""
    if interactive:
        choice = ask_interactive_targets(local_args, preset=preset)
        if choice.get("local_dirs"):
            return [], choice["local_dirs"], choice.get("modified_by", []) or []
        if choice.get("discover"):
            discover = choice["discover"]
            discover_window = choice.get("discover_window", "") or discover_window
            discover_language = choice.get("discover_language", "")
            try:
                discover_sample = int(choice.get("discover_sample", discover_sample) or 0)
            except (TypeError, ValueError):
                pass
        repo_args = (repo_args or []) + choice.get("repos", [])
        repos_file = repos_file or choice.get("repos_file", "") or repos_file
        if choice.get("all"):
            scan_all = True
        modified_by = merge_users(parse_user_list(modified_by), choice.get("modified_by", []) or [])
    names = resolve_remote_repo_names(token, kind, owner, repo_args, repos_file,
                                      scan_all, include_forks, include_archived,
                                      max_repos, modified_by, since, until, branch,
                                      discover, discover_window,
                                      discover_language, discover_sample,
                                      seed, min_stars, topic, exclude_language)
    _LAST_DISCOVER["mode"] = discover or ""
    _LAST_DISCOVER["window"] = discover_window or "12h"
    _LAST_DISCOVER["language"] = discover_language or ""
    effective = parse_user_list(modified_by) if modified_by else []
    return names, [], effective


def decide_github_mode(source: str, remote: bool, clone: bool) -> str:
    """Retourne 'remote' (defaut, sans clonage) ou 'clone' (ancien mode)."""
    if source == "clone" or (clone and source != "remote"):
        return "clone"
    if source == "remote" or remote:
        return "remote"
    if source == "":
        return "remote"  # defaut : consultation a distance, AUCUN clone
    return source  # 'local' gere a part


def resolve_effective_source(args) -> str:
    """Option explicite local vs distant : 'local' | 'local-ask' | 'github'.
    --source local exige --local (ou --interactive pour saisir les dossiers).
    --source remote/clone refuse --local (conflit explicite)."""
    has_local = bool(parse_local_dirs(args.local))
    explicit = (args.source or "").strip()
    if args.remote and args.clone:
        print("Options incompatibles : --remote et --clone. Choisis distant (sans cloner) OU clone.")
        sys.exit(2)
    if args.remote:
        if explicit and explicit != "remote":
            print("Options incompatibles : --remote avec --source " + explicit + ".")
            sys.exit(2)
        explicit = "remote"
    if args.clone:
        if explicit and explicit != "clone":
            print("Options incompatibles : --clone avec --source " + explicit + ".")
            sys.exit(2)
        explicit = "clone"
    if explicit == "local":
        if has_local:
            return "local"
        if args.interactive:
            return "local-ask"  # l'interactif demandera les dossiers
        args.local = ["."]
        print("[source] local : aucun dossier precise, scan du dossier courant (.).")
        return "local"
    if explicit in ("remote", "clone"):
        if has_local:
            print(f"Conflit : --local (depot local) + --source {explicit} (depot distant). "
                  f"Choisis local OU distant, pas les deux.")
            sys.exit(2)
        return "github"
    # auto : dossier local si --local donne, sinon depot distant GitHub
    if has_local:
        return "local"
    return "github"


def interactive_preset(args) -> str:
    """Preset a passer a l'interactif selon l'option explicite."""
    explicit = (args.source or "").strip()
    if args.remote or explicit == "remote":
        return "remote"
    if args.clone or explicit == "clone":
        return "clone"
    if explicit == "local":
        return "local"
    return ""


def collect_specific_repos(token, repo_names, clone_dir: Path, refresh: bool = False):
    """Clone (shallow) UNIQUEMENT les depots cibles. Retourne [(full_name, chemin)]."""
    if not token:
        print("Il faut un token : --token ou env GITHUB_TOKEN (sur TON compte).")
        sys.exit(2)
    print(f"[GitHub] {len(repo_names)} depot(s) cible(s) : {', '.join(repo_names)}")
    targets = []
    for full_name in repo_names:
        info = github_api_get_repo(token, full_name)
        if not info:
            continue
        real_name = info.get("full_name", full_name)
        clone_url = info.get("clone_url", f"https://github.com/{full_name}.git")
        dest = clone_dir / real_name.replace("/", "__")
        print(f"- {real_name} ({'prive' if info.get('private') else 'public'})")
        if dest.exists() and not refresh:
            print("  [skip] deja clone (reutilise). --refresh pour re-cloner.")
        else:
            if dest.exists():
                import shutil
                shutil.rmtree(dest, ignore_errors=True)
            if not git_clone_shallow(clone_url, dest, token):
                continue
        targets.append((real_name, dest))
    return targets


def collect_github_targets(token, kind, owner, clone_dir: Path, max_repos: int,
                           refresh: bool = False,
                           include_forks: bool = False,
                           include_archived: bool = False,
                           min_stars: int = 0, topic: str = "",
                           exclude_language: str = "", authorize=None):
    """Clone (shallow) des depots SANS ciblage particulier (liste via API).
    --all / defaut sans --repo : TOUS les depots accessibles au token.
    Filtres de veille --min-stars/--topic/--exclude-language appliques ici aussi.
    max_repos=0 signifie SANS LIMITE. Retourne [(repo_full_name, chemin)]."""
    if not token:
        print("Il faut un token : --token ou env GITHUB_TOKEN (sur TON compte).")
        sys.exit(2)
    if kind == "org" and not owner:
        print("Precise --owner pour --kind org (ex: --kind org --owner ma-org).")
        sys.exit(2)
    print(f"[GitHub] liste des depots (kind={kind}, owner={owner or 'token-owner'}) ...")
    repos = github_api_list_repos(token, mode=kind, owner=owner)
    print(f"[GitHub] {len(repos)} depot(s) trouve(s) via API.")
    # Filtres anti-bruit (forks / archives exclus par defaut)
    # + filtres de veille --min-stars/--topic/--exclude-language.
    kept = []
    skipped_forks = 0
    skipped_archived = 0
    skipped_veille = 0
    for r in repos:
        if r.get("fork") and not include_forks:
            skipped_forks += 1
            continue
        if r.get("archived") and not include_archived:
            skipped_archived += 1
            continue
        if not repo_passes_filters(r, min_stars, topic, exclude_language):
            skipped_veille += 1
            continue
        kept.append(r)
    if skipped_forks or skipped_archived or skipped_veille:
        print(f"[GitHub] exclus : {skipped_forks} fork(s), {skipped_archived} archive(s), "
              f"{skipped_veille} hors veille (etoiles/topic/langage) "
              f"(options --include-forks / --include-archived pour les garder).")
    if max_repos and max_repos > 0:
        print(f"[GitHub] limite : {max_repos} depot(s) max (0 = sans limite).")
        kept = kept[:max_repos]
    else:
        print(f"[GitHub] SANS LIMITE : {len(kept)} depot(s) a cloner.")
    if authorize and not authorize([r.get("full_name", "?") for r in kept]):
        sys.exit(2)
    targets = []
    for r in kept:
        name = r.get("full_name", "?")
        clone_url = r.get("clone_url", "")
        dest = clone_dir / name.replace("/", "__")
        print(f"- {name} ({'prive' if r.get('private') else 'public'})")
        if dest.exists() and not refresh:
            print("  [skip] deja clone (reutilise). --refresh pour re-cloner.")
        else:
            if dest.exists():
                import shutil
                shutil.rmtree(dest, ignore_errors=True)
            if not git_clone_shallow(clone_url, dest, token):
                continue
        targets.append((name, dest))
    return targets


def parse_local_dirs(local_args):
    """Combine --local repetable + virgules. Retourne liste de dossiers uniques."""
    dirs = []
    seen = set()
    for item in local_args or []:
        for part in item.split(","):
            d = part.strip().strip('"').strip("'")
            if not d:
                continue
            if d not in seen:
                seen.add(d)
                dirs.append(d)
    return dirs


def apply_target_argument(args):
    """Transforme la cible positionnelle (dossier, URL GitHub, owner/name)
    en --local ou --repo. Exemple : scanner.py <n'importe quel depot>."""
    raw = (getattr(args, "target", "") or "").strip()
    if not raw:
        return
    kind, value = classify_target(raw)
    if not kind:
        print(f"Cible non reconnue : {raw}")
        print("Attendu : dossier local, URL GitHub ou 'owner/name'.")
        sys.exit(2)
    if kind == "local":
        if args.repo or args.repos_file or args.all or args.discover:
            print(f"Cible locale '{raw}' incompatible avec --repo/--repos-file/"
                  f"--all/--discover (choisis local OU distant).")
            sys.exit(2)
        if ((args.source or "") in ("remote", "clone")
                or args.remote or args.clone):
            print(f"Cible locale '{raw}' incompatible avec un mode distant "
                  f"(--source remote/clone, --remote, --clone).")
            sys.exit(2)
        args.local = list(args.local or []) + [value]
        print(f"[cible] local : {value}")
        return
    if args.all:
        print(f"Cible distante '{raw}' incompatible avec --all "
              f"(choisis un depot precis OU tous, pas les deux).")
        sys.exit(2)
    if args.local or (args.source or "") == "local":
        print(f"Cible distante '{raw}' incompatible avec --local/--source local.")
        sys.exit(2)
    args.repo = list(args.repo or []) + [value]
    print(f"[cible] distant : {value}")


def maybe_scan_current_repo(args):
    """Sans aucune cible explicite, si le dossier courant est un depot git,
    le scanner l'analyse en local. `python scanner.py` suffit donc dans
    n'importe quel depot ; --all reste necessaire pour TOUS les depots GitHub."""
    if getattr(args, "target", ""):
        return
    if (args.local or args.repo or args.repos_file or args.all or args.discover
            or args.interactive or args.remote or args.clone or args.source):
        return
    if not (Path.cwd() / ".git").exists():
        return
    args.local = ["."]
    print("[source] depot git detecte : scan local du dossier courant "
          "(pour tous tes depots GitHub, utilise --all).")


def _ask_author_filter():
    """Question interactif : filtrer sur les depots modifies par un utilisateur."""
    saisi = input("Filtrer : uniquement depots MODIFIES par (login GitHub, vide = tous) : ").strip()
    users = [u.strip().lstrip("@") for u in saisi.split(",") if u.strip()]
    return users


def _ask_local_author_filter():
    """Question interactif (local git) : motif git log --author (nom/email)."""
    saisi = input("Filtrer local : uniquement dossiers MODIFIES par (nom/email git, vide = tous) : ").strip()
    return [u.strip() for u in saisi.split(",") if u.strip()]


def merge_users(*lists):
    """Fusionne des listes d'utilisateurs en gardant l'ordre (sans doublons)."""
    out = []
    seen = set()
    for lst in lists:
        for u in lst or []:
            u = (u or "").strip()
            if u and u not in seen:
                seen.add(u)
                out.append(u)
    return out


def author_suffix(args, users=None):
    """Suffixe de libelle pour le filtre auteur (--modified-by [--since/--until])."""
    if users is None:
        users = parse_user_list(getattr(args, "modified_by", []) or [])
    if not users:
        return ""
    s = f" | modifies par {','.join(users)}"
    if getattr(args, "since", ""):
        s += f" depuis {args.since}"
    if getattr(args, "until", ""):
        s += f" jusqu'a {args.until}"
    return s


def _empty_github_choice(**extra):
    base = {"local_dirs": [], "repos": [], "repos_file": "", "all": False,
            "discover": "", "modified_by": []}
    base.update(extra)
    return base


def _ask_discover_params():
    """Saisie interactive des parametres de decouverte publique."""
    print("Decouverte : U) modifies recemment  C) crees recemment  R) aleatoire")
    d = (input("Decouverte [U/C/R] (defaut U) : ").strip().upper() or "U")
    mode = {"U": "updated", "C": "created", "R": "random"}.get(d, "updated")
    window = ""
    language = ""
    if mode in ("updated", "created"):
        window = input("Fenetre (ex: 30m, 12h, 7d) [12h] : ").strip() or "12h"
        language = input("Langage (vide = tous, ex: python) : ").strip()
    try:
        sample = int(input("Echantillon aleatoire (0 = tous) [20] : ").strip() or "20")
    except ValueError:
        sample = 20
    print("[decouverte] depots PUBLICS : scan selon le mode courant "
          "(mots-cles ou secrets).")
    return {"discover": mode, "window": window or "12h", "language": language,
            "sample": sample}


def _ask_github_choice(allow_discover=True):
    """Questionnaire distant commun : 1 / plusieurs / tous / fichier / decouverte."""
    print("1) Un seul depot (ex: mon-user/mon-repo)")
    print("2) Plusieurs depots (separes par des virgules)")
    print("3) TOUS mes depots, sans en indiquer un particulier (--all)")
    print("4) Depuis un fichier liste (--repos-file)")
    if allow_discover:
        print("5) DECOUVERTE publique : aleatoire ou fenetre recente")
        choix = input("Choix [1/2/3/4/5] (defaut 3) : ").strip() or "3"
    else:
        choix = input("Choix [1/2/3/4] (defaut 3) : ").strip() or "3"
    if choix == "1":
        one = input("Depot cible (owner/name) : ").strip()
        return _empty_github_choice(repos=([one] if one else []),
                                    modified_by=_ask_author_filter())
    if choix == "2":
        multi = input("Depots cibles separes par virgule : ").strip()
        return _empty_github_choice(
            repos=[m.strip() for m in multi.split(",") if m.strip()],
            modified_by=_ask_author_filter())
    if choix == "4":
        f = input("Fichier liste (defaut depots.txt) : ").strip() or "depots.txt"
        return _empty_github_choice(repos_file=f, modified_by=_ask_author_filter())
    if choix == "5" and allow_discover:
        params = _ask_discover_params()
        return _empty_github_choice(discover=params["discover"],
                                    discover_window=params["window"],
                                    discover_language=params["language"],
                                    discover_sample=params["sample"])
    if choix == "5":
        print("[decouverte] non disponible ici (incompatible avec --source clone).")
    return _empty_github_choice(all=True, modified_by=_ask_author_filter())


def ask_interactive_targets(local_args=None, preset="", allow_discover=True):
    """Mode interactif 'sur demande' : local et/ou GitHub (1 / plusieurs / tous).
    preset = 'local' | 'remote' | 'clone' | '' : force la source sans reposer la question L/G.
    Propose aussi le filtre 'depots modifies par ...' pour GitHub."""
    if preset == "local":
        saisi = input("Dossier(s) local/locaux (separes par virgule si plusieurs) : ").strip()
        return {"local_dirs": [m.strip() for m in saisi.split(",") if m.strip()],
                "repos": [], "repos_file": "", "all": False, "modified_by": _ask_local_author_filter()}
    if preset in ("remote", "clone"):
        print("\n--- Lancement a la demande (depots GitHub distants) ---")
        if preset == "clone":
            allow_discover = False
        return _ask_github_choice(allow_discover=allow_discover)
    print("\n--- Lancement a la demande ---")
    print("Source : L) depot LOCAL (dossiers --local)   G) depot DISTANT (GitHub via API, sans cloner)")
    src = (input("Source [L/G] (defaut G) : ").strip().upper() or "G")
    if src == "L":
        saisi = input("Dossier(s) local/locaux (separes par virgule si plusieurs) : ").strip()
        return {"local_dirs": [m.strip() for m in saisi.split(",") if m.strip()],
                "repos": [], "repos_file": "", "all": False, "modified_by": _ask_local_author_filter()}
    return _ask_github_choice(allow_discover=allow_discover)


def resolve_github_targets(token, kind, owner, clone_dir, max_repos,
                           repo_args, repos_file, refresh, interactive,
                           local_args=None, scan_all=False,
                           include_forks=False, include_archived=False,
                           preset="", modified_by=None, since="", until="",
                           branch="", min_stars=0, topic="",
                           exclude_language="", authorize=None):
    """Unifie le ciblage :
    - specifique (1/plusieurs/fichier via --repo / --repos-file),
    - ou --all / sans depot particulier = TOUS les depots accessibles au token.
    Si modified_by : clone uniquement les depots modifies par cet/ces utilisateur(s)
    (verifie via API Commits AVANT de cloner, SANS cloner les autres).
    Retourne (names, targets, ilocal, iusers) : ilocal+iusers = cas local interactif."""
    if interactive:
        choice = ask_interactive_targets(local_args, preset=preset)
        if choice.get("local_dirs"):
            # signale : scan local interactif + filtre auteur local eventuel
            return [], [], choice["local_dirs"], choice.get("modified_by", []) or []
        repo_args = (repo_args or []) + choice.get("repos", [])
        repos_file = repos_file or choice.get("repos_file", "") or repos_file
        if choice.get("all"):
            scan_all = True
        modified_by = merge_users(parse_user_list(modified_by), choice.get("modified_by", []) or [])
    users = parse_user_list(modified_by) if modified_by else []
    if users:
        # Noms d'abord (sans cloner), filtre auteur (API), puis clone des gardes.
        pre_names = parse_target_repos(repo_args, repos_file)
        if pre_names and not scan_all:
            names = pre_names
        else:
            if kind == "org" and not owner:
                print("Precise --owner pour --kind org (ex: --kind org --owner ma-org).")
                sys.exit(2)
            if not token:
                print("Il faut un token : --token ou env GITHUB_TOKEN (sur TON compte).")
                sys.exit(2)
            repos = github_api_list_repos(token, mode=kind, owner=owner)
            names = [r["full_name"] for r in repos
                     if r.get("full_name")
                     and (include_forks or not r.get("fork"))
                     and (include_archived or not r.get("archived"))
                     and repo_passes_filters(r, min_stars, topic,
                                             exclude_language)]
        names, details = filter_repos_by_editors(token, names, users, branch, since, until)
        AUTHOR_HITS.clear()
        AUTHOR_HITS.update(details)
        if max_repos and max_repos > 0:
            names = names[:max_repos]
        if authorize and not authorize(names):
            sys.exit(2)
        targets = []
        if names:
            targets = collect_specific_repos(token, names, Path(clone_dir), refresh)
        return names, targets, [], list(users)
    if scan_all:
        if parse_target_repos(repo_args, repos_file):
            print("[info] --all demande : on scanne TOUS les depots (ciblage --repo/--repos-file ignore).")
        targets = collect_github_targets(token, kind, owner, Path(clone_dir), max_repos,
                                         refresh, include_forks, include_archived,
                                         min_stars, topic, exclude_language,
                                         authorize=authorize)
        return [n for n, _ in targets], targets, [], []
    specific = parse_target_repos(repo_args, repos_file)
    if specific:
        if authorize and not authorize(specific):
            sys.exit(2)
        return specific, collect_specific_repos(token, specific, Path(clone_dir), refresh), [], []
    # sans depot particulier : tous les depots du compte / org
    targets = collect_github_targets(token, kind, owner, Path(clone_dir), max_repos,
                                     refresh, include_forks, include_archived,
                                     min_stars, topic, exclude_language,
                                     authorize=authorize)
    return [n for n, _ in targets], targets, [], []


# ---------------------------------------------------------------- main
def main():
    # Ne jamais planter sur un caractere non representable dans la console
    # Windows (BOM, accents, emoji...) : remplace au lieu de lever une erreur.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="Recherche de MOTS-CLES (fichier texte) avec rapport texte detaille + "
                    "audit secrets de n'importe quel depot (local ou distant).",
        epilog="Cible optionnelle : dossier local, URL GitHub ou owner/name. "
               "Ex : github_audit_scanner.py C:\\mon-repo "
               "ou github_audit_scanner.py https://github.com/owner/repo"
    )
    ap.add_argument("target", nargs="?", default="",
                    help="Cible optionnelle : dossier local (ex: . ou C:\\mon-repo), "
                         "URL GitHub (ex: https://github.com/owner/repo) ou owner/name. "
                         "Sans --keywords, la cible est auditee en mode SECRETS.")
    # Source a scanner : --local (1 ou plusieurs dossiers) OU GitHub (cible ou non) :
    ap.add_argument("--local", action="append", nargs="?", const=".", default=[],
                    help="Dossier local a scanner. Sans valeur = dossier courant. "
                         "Repetable ou separes par virgules. Ex: --local ./proj1 --local ./proj2")
    ap.add_argument("--source", choices=["local", "remote", "clone"], default="",
                    help="Choix explicite : local (dossiers --local), remote (depots GitHub consultes A DISTANCE via API, SANS cloner - defaut pour GitHub), clone (ancien mode : clone git puis scan). Defaut: auto.")
    ap.add_argument("--remote", action="store_true",
                    help="Raccourci de --source remote : consulte les depots GitHub A DISTANCE via l'API, SANS cloner.")
    ap.add_argument("--clone", action="store_true",
                    help="Force l'ancien mode par clonage git (clone shallow puis scan local du clone).")
    ap.add_argument("--branch", default="",
                    help="Branche a consulter en mode distant (defaut: branche par defaut de chaque depot).")
    ap.add_argument("--max-files-per-repo", type=int, default=5000,
                    help="Max de fichiers lus par depot en mode distant. 0 = sans limite. Defaut: 5000 (anti quota API).")
    ap.add_argument("--token", default=os.environ.get("GITHUB_TOKEN", ""),
                    help="Token GitHub (ou env GITHUB_TOKEN). Optionnel pour les depots publics.")
    ap.add_argument("--owner", help="TON organisation GitHub a auditer (avec --kind org)")
    ap.add_argument("--kind", choices=["me", "org"], default="me")
    ap.add_argument("--clone-dir", default="./_audit_clones")
    ap.add_argument("--max-repos", type=int, default=0,
                    help="Nombre max de depots en mode SANS ciblage (clone ou distant). 0 = SANS LIMITE (tous). Defaut: 0.")
    # Ciblage a la demande :
    ap.add_argument("--all", action="store_true",
                    help="TOUS les depots accessibles au token, sans indiquer un depot particulier. Ex: --all --keywords ./mots_cles.txt")
    ap.add_argument("--repo", action="append", default=[],
                    help="Depot CIBLE 'owner/name'. Repetable ou separes par virgules. Ex: --repo mon-user/mon-repo --repo autre/repo2")
    ap.add_argument("--repos-file", default="",
                    help="Fichier texte listant les depots cibles (un 'owner/name' par ligne). Ex: depots.txt")
    ap.add_argument("--discover", choices=["updated", "created", "random"], default="",
                    help="DECOUVERTE publique SANS depot particulier : "
                         "'updated' = depots publics modifies (push) sur la fenetre --window, "
                         "'created' = depots publics crees sur la fenetre, "
                         "'random' = tirage aleatoire de depots publics. Incompatible avec "
                         "--repo/--repos-file/--all/--kind/--owner/--modified-by/--source clone.")
    ap.add_argument("--window", default="12h",
                    help="Avec --discover updated|created : fenetre recente (ex: 30m, 12h, 24h, 7d). Defaut: 12h.")
    ap.add_argument("--language", default="",
                    help="Avec --discover updated|created : filtre langage GitHub (ex: python). Vide = tous.")
    ap.add_argument("--sample", type=int, default=20,
                    help="Avec --discover : taille de l'echantillon aleatoire tire parmi les candidats. 0 = tous. Defaut: 20.")
    ap.add_argument("--refresh", action="store_true",
                    help="Re-clone les depots deja clones (defaut: reutilise le clone existant).")
    ap.add_argument("--interactive", action="store_true",
                    help="Mode interactif : demande 1 depot / plusieurs / tous / fichier liste.")
    ap.add_argument("--include-forks", action="store_true",
                    help="Inclure les forks en mode SANS ciblage (defaut: exclus).")
    ap.add_argument("--include-archived", action="store_true",
                    help="Inclure les depots archives en mode SANS ciblage (defaut: exclus).")
    # Filtre auteur : ne garder que les depots MODIFIES par cet/ces utilisateur(s)
    ap.add_argument("--modified-by", action="append", default=[],
                    help="Ne garder que les depots modifies par cet utilisateur GitHub (login). Repetabe ou separes par virgules. Ex: --modified-by alice --modified-by bob,carol. Verifie via l'API Commits, SANS cloner.")
    ap.add_argument("--since", default="",
                    help="Avec --modified-by : ne compte que les commits APRES cette date ISO (ex: 2024-01-01).")
    ap.add_argument("--until", default="",
                    help="Avec --modified-by : ne compte que les commits AVANT cette date ISO (ex: 2025-01-01).")
    # --- Options transverses (les 15) ---
    ap.add_argument("--dry-run", action="store_true",
                    help="Liste les depots cibles SANS les scanner (securise les gros --sample).")
    ap.add_argument("--save-list", default="",
                    help="Sauvegarde les depots decouverts dans un fichier (ex: decouverts.txt), pour rescanner via --repos-file.")
    ap.add_argument("--seed", type=int, default=None,
                    help="Graine pour le tirage --discover random / --sample (reproductible). Ex: --seed 42.")
    ap.add_argument("--exclude", action="append", default=[],
                    help="Exclut des chemins (joker ou sous-chaine). Repetable ou virgules. Ex: --exclude '*.min.js,*.lock,vendor/'")
    ap.add_argument("--include-ext", action="append", default=[],
                    help="Ne garde QUE ces extensions. Repetable ou virgules. Ex: --include-ext .py --include-ext .env")
    ap.add_argument("--context", type=int, default=0,
                    help="Lignes avant/apres chaque occurrence dans resultats.txt (style grep -C). Defaut: 0.")
    ap.add_argument("--fail-on-find", action="store_true",
                    help="Exit 1 si >= 1 occurrence (pour GitHub Action / pre-commit bloquant).")
    ap.add_argument("--config", default="",
                    help="Preset audit.ini (section [audit]) : langage, fenetre, exclusions... La CLI reste prioritaire.")
    ap.add_argument("--min-stars", type=int, default=0,
                    help="Veille : ne garde que les depots avec au moins N etoiles (decouverte + --all). Defaut: 0.")
    ap.add_argument("--topic", default="",
                    help="Veille : ne garde que les depots ayant ce topic GitHub (ex: security).")
    ap.add_argument("--exclude-language", default="",
                    help="Veille : exclut ce langage principal (ex: JavaScript).")
    ap.add_argument("--allowlist", default="",
                    help="Fichier allowlist.txt : occurrences connues marquees [ignore].")
    ap.add_argument("--strict", action="store_true",
                    help="Avec --fail-on-find : echoue SEULEMENT sur les occurrences non-allowlistees.")
    ap.add_argument("--history", action="store_true",
                    help="Scanne aussi l'historique git (lignes AJOUTEES des N derniers commits) : une cle revoquee reste visible.")
    ap.add_argument("--history-depth", type=int, default=20,
                    help="Avec --history : nombre de derniers commits a scanner. Defaut: 20.")
    ap.add_argument("--since-last-run", action="store_true",
                    help="Veille diff : ne montre que les occurrences NOUVELLES depuis le dernier run (cache .audit_state.json).")
    ap.add_argument("--since-last-run-key", default="default",
                    help="Cle de veille pour --since-last-run (un cron par cle). Defaut: default.")
    ap.add_argument("--entropy", action="store_true",
                    help="Detecte aussi les chaines a haute entropie (cles/token inattendus, sans regex connue). Plus de faux positifs.")
    ap.add_argument("--entropy-threshold", type=float, default=4.5,
                    help="Avec --entropy : seuil bits/caractere. Defaut: 4.5.")
    ap.add_argument("--entropy-min-len", type=int, default=20,
                    help="Avec --entropy : longueur min du token suspect. Defaut: 20.")
    ap.add_argument("--html", default="",
                    help="Rapport HTML cliquable plie par depot (ex: rapport.html).")
    ap.add_argument("--csv", default="",
                    help="Rapport CSV (Excel) : une ligne par occurrence (ex: rapport.csv).")
    ap.add_argument("--sarif", default="",
                    help="Rapport SARIF 2.1.0 (onglet Security GitHub / VS Code, ex: rapport.sarif).")
    ap.add_argument("--no-retry", action="store_true",
                    help="Desactive le retry/backoff sur quota API 403 (defaut: attend X-RateLimit-Reset et reprend).")

    # Mode MOTS-CLES :
    ap.add_argument("--keywords", help="Fichier texte avec un mot-cle par ligne (ex: mots_cles.txt)")
    ap.add_argument("--report", default="resultats.txt",
                    help="Fichier texte de resultats a creer (quoi / ou / detail). Defaut: resultats.txt")
    ap.add_argument("--case-sensitive", action="store_true",
                    help="Recherche sensible a la casse (defaut: insensible).")
    ap.add_argument("--json-out", default="",
                    help="Optionnel : copie JSON des resultats mots-cles (ex: resultats.json)")
    ap.add_argument("--both", action="store_true",
                    help="Avec --keywords : lance AUSSI la detection de secrets sur les "
                         "memes fichiers, en UN SEUL parcours (aucun appel API double). "
                         "Ecrit le rapport texte mots-cles (--report) et le rapport JSON "
                         "secrets (--output).")

    # Mode SECRETS :
    ap.add_argument("--output", default="audit_report.json")
    ap.add_argument("--reveal", action=argparse.BooleanOptionalAction, default=True,
                    help="AFFICHE LES SECRETS EN CLAIR (defaut : oui). "
                         "--no-reveal (ou reveal = false dans audit.ini) pour masquer.")
    ap.add_argument("--authorized", action="store_true",
                    help="Option de compatibilite, sans effet : le mode SECRETS est "
                         "toujours autorise, sur tous les depots.")
    ap.add_argument("--list-rules", action="store_true",
                    help="Liste tous les types d'API-Key/secrets detectes (categories, severite) et quitte.")
    ap.add_argument("--only-category", action="append", default=[],
                    help="Mode secrets : ne garder QUE ces categories. Repetable ou virgules. "
                         "Ex: --only-category ai,cloud,oauth (voir --list-rules).")
    ap.add_argument("--skip-category", action="append", default=[],
                    help="Mode secrets : exclure ces categories. Repetable ou virgules. "
                         "Ex: --skip-category generic,payments")
    ap.add_argument("--min-severity", choices=["info", "low", "medium", "high", "critical"],
                    default="info",
                    help="Mode secrets : ne garder que les regles d'au moins cette severite. Defaut: info.")
    ap.add_argument("--no-generic", action="store_true",
                    help="Mode secrets : desactive les heuristiques generiques "
                         "(api_key = ..., tokens inconnus par affectation).")
    ap.add_argument("--rules-file", default="",
                    help="Mode secrets : fichier JSON de regles personnalisees "
                         "(id, provider, category, regex, group...).")
    args = ap.parse_args()

    # --- Preset --config (audit.ini) : la CLI reste prioritaire ---
    if getattr(args, "config", ""):
        args.config = str(resolve_input_path(args.config))
        apply_config_file(args, ap, args.config)

    # --- Cible positionnelle : dossier local, URL GitHub ou owner/name ---
    apply_target_argument(args)
    maybe_scan_current_repo(args)

    # --- Fichiers d'entree : cherches dans le dossier courant puis a cote
    #     du scanner (l'outil reste utilisable depuis n'importe quel depot) ---
    for _input_attr in ("keywords", "repos_file", "allowlist", "rules_file"):
        _val = getattr(args, _input_attr, "")
        if _val:
            setattr(args, _input_attr, str(resolve_input_path(_val)))

    if getattr(args, "both", False) and not getattr(args, "keywords", None):
        print("[both] --both necessite --keywords (fichier de mots-cles).")
        sys.exit(2)

    # --- Reglages transverses -> OPTS (lus par keep_*/entropie/retry) ---
    try:
        OPTS["excludes"] = parse_str_list(getattr(args, "exclude", []) or [])
    except Exception:
        OPTS["excludes"] = []
    try:
        OPTS["include_exts"] = parse_include_exts(getattr(args, "include_ext", []) or [])
    except Exception:
        OPTS["include_exts"] = set()
    try:
        OPTS["context"] = max(0, int(getattr(args, "context", 0) or 0))
    except (TypeError, ValueError):
        OPTS["context"] = 0
    OPTS["entropy"] = bool(getattr(args, "entropy", False))
    try:
        OPTS["entropy_threshold"] = float(getattr(args, "entropy_threshold", 4.5) or 4.5)
    except (TypeError, ValueError):
        OPTS["entropy_threshold"] = 4.5
    try:
        OPTS["entropy_min_len"] = int(getattr(args, "entropy_min_len", 20) or 20)
    except (TypeError, ValueError):
        OPTS["entropy_min_len"] = 20
    OPTS["no_retry"] = bool(getattr(args, "no_retry", False))
    OPTS["secret_rule_categories"] = {
        s.lower() for s in parse_str_list(getattr(args, "only_category", []) or [])
    }
    OPTS["secret_skip_categories"] = {
        s.lower() for s in parse_str_list(getattr(args, "skip_category", []) or [])
    }
    OPTS["secret_min_severity"] = str(
        getattr(args, "min_severity", "info") or "info").lower()
    OPTS["secret_no_generic"] = bool(getattr(args, "no_generic", False))
    unknown_categories = sorted(
        (OPTS["secret_rule_categories"] | OPTS["secret_skip_categories"])
        - set(SECRET_CATEGORIES))
    if unknown_categories:
        print(f"[regles] categorie(s) inconnue(s) : {', '.join(unknown_categories)}")
        print(f"[regles] categories valides : {', '.join(sorted(SECRET_CATEGORIES))}")
        sys.exit(2)
    if getattr(args, "rules_file", ""):
        load_custom_secret_rules(args.rules_file)
    if OPTS["excludes"]:
        print(f"[filtre] exclusions : {', '.join(OPTS['excludes'])}")
    if OPTS["include_exts"]:
        print(f"[filtre] extensions gardees : {', '.join(sorted(OPTS['include_exts']))}")
    if getattr(args, "list_rules", False):
        print_secret_rules()
        return

    # ================= MODE MOTS-CLES =================
    if args.keywords:
        both = bool(getattr(args, "both", False))
        if args.discover and decide_github_mode(args.source, args.remote, args.clone) == "clone":
            print("[decouverte] incompatible avec --source clone : "
                  "la decouverte consulte les depots publics SANS cloner.")
            sys.exit(2)
        if both:
            rules_active = active_secret_rules()
            if not rules_active:
                print("[regles] aucune regle active avec ces filtres (voir --list-rules).")
                sys.exit(2)
            print(f"[regles] {len(rules_active)} type(s) d'API-Key/secrets actif(s).")
            print("[both] mots-cles + secrets : un seul parcours, aucun appel API double.")
        # Ne jamais scanner les fichiers d'entree/sortie de l'outil lui-meme
        fill_excludes(args.keywords, args.report, args.json_out, args.repos_file,
                      args.html, args.csv, args.sarif,
                      args.output if both else "",
                      "mots_cles.txt", "depots.txt")
        keywords = load_keywords(Path(args.keywords))
        print(f"[mots-cles] {len(keywords)} motif(s) charges depuis {args.keywords}")
        patterns = compile_patterns(keywords, case_sensitive=args.case_sensitive)

        findings_all = []
        secret_findings_all = []
        scanned_files = 0
        source_label = ""
        src = resolve_effective_source(args)
        preset = interactive_preset(args)
        cli_users = parse_user_list(args.modified_by)
        report_users = list(cli_users)

        if src in ("local", "local-ask"):
            local_dirs = []
            if src == "local-ask":
                choice = ask_interactive_targets(preset="local")
                local_dirs = [m for m in choice.get("local_dirs", []) if m]
                iusers_kw = choice.get("modified_by", []) or []
            else:
                local_dirs = parse_local_dirs(args.local)
                iusers_kw = []
            users_kw = merge_users(cli_users, iusers_kw)
            report_users = list(users_kw)
            if args.dry_run:
                print(f"[dry-run] {len(local_dirs)} dossier(s) cible(s), AUCUN scan :")
                for d in local_dirs:
                    print(f"  - {d}")
                return
            if users_kw:
                local_dirs = filter_local_dirs_by_editors(
                    local_dirs, users_kw, args.since, args.until)
            labels = []
            for d in local_dirs:
                root = Path(d)
                if not root.exists():
                    print(f"[skip] Dossier introuvable : {root}")
                    continue
                print(f"[scan local] {root}")
                labels.append(str(root.resolve()))
                n, f, sf = scan_local_target(
                    root, patterns, args.case_sensitive, both, args.reveal)
                scanned_files += n
                findings_all.extend(f)
                secret_findings_all.extend(sf)
            source_label = (",".join(labels) if labels else "(aucun dossier valide)")
            source_label += author_suffix(args, users_kw)
        else:
            mode = decide_github_mode(args.source, args.remote, args.clone)
            if mode == "clone":
                # ANCIEN mode : clone git puis scan local du clone
                print("[mode] clone : clonage git puis scan local des clones.")
                repo_names, targets, ilocal, iusers_c = resolve_github_targets(
                    args.token, args.kind, args.owner or "",
                    args.clone_dir, args.max_repos,
                    args.repo, args.repos_file, args.refresh, args.interactive,
                    local_args=args.local, scan_all=args.all,
                    include_forks=args.include_forks, include_archived=args.include_archived,
                    preset=preset, modified_by=args.modified_by,
                    since=args.since, until=args.until, branch=args.branch,
                    min_stars=args.min_stars, topic=args.topic,
                    exclude_language=args.exclude_language)
                users_c = merge_users(cli_users, iusers_c)
                report_users = list(users_c)
                if ilocal:
                    if users_c:
                        ilocal = filter_local_dirs_by_editors(ilocal, users_c, args.since, args.until)
                    labels = []
                    for d in ilocal:
                        root = Path(d)
                        if not root.exists():
                            print(f"[skip] Dossier introuvable : {root}")
                            continue
                        print(f"[scan local] {root}")
                        labels.append(str(root.resolve()))
                        n, f, sf = scan_local_target(
                            root, patterns, args.case_sensitive, both, args.reveal)
                        scanned_files += n
                        findings_all.extend(f)
                        secret_findings_all.extend(sf)
                    source_label = ",".join(labels) if labels else "(aucun dossier valide)"
                    source_label += author_suffix(args, users_c)
                else:
                    if args.all:
                        source_label = (f"github-clone:TOUS (kind={args.kind}, "
                                        f"owner={args.owner or 'token-owner'}, {len(targets)} depot(s))")
                    else:
                        source_label = (f"github-clone:cibles:{','.join(repo_names)}"
                                        if repo_names and len(repo_names) <= 10
                                        else f"github-clone:{args.kind}:{args.owner or 'token-owner'}")
                    source_label += author_suffix(args, users_c)
                    for repo_name, dest in targets:
                        n, f, sf = scan_local_target(
                            dest, patterns, args.case_sensitive, both, args.reveal)
                        scanned_files += n
                        for x in f + sf:
                            x["repo"] = repo_name
                        findings_all.extend(f)
                        secret_findings_all.extend(sf)
            else:
                # DEFAUT : consultation A DISTANCE via API, AUCUN clone
                print("[mode] distant : consultation via API GitHub, SANS cloner.")
                names, ilocal, iusers_r = resolve_remote_names(
                    args.token, args.kind, args.owner or "",
                    args.repo, args.repos_file, args.all,
                    args.interactive, local_args=args.local,
                    include_forks=args.include_forks,
                    include_archived=args.include_archived,
                    max_repos=args.max_repos, preset=preset,
                    modified_by=args.modified_by,
                    since=args.since, until=args.until, branch=args.branch,
                    discover=args.discover, discover_window=args.window,
                    discover_language=args.language, discover_sample=args.sample,
                    min_stars=args.min_stars, topic=args.topic,
                    exclude_language=args.exclude_language, seed=args.seed)
                users_r = merge_users(cli_users, iusers_r)
                report_users = list(users_r)
                if ilocal:
                    if users_r:
                        ilocal = filter_local_dirs_by_editors(ilocal, users_r, args.since, args.until)
                    labels = []
                    for d in ilocal:
                        root = Path(d)
                        if not root.exists():
                            print(f"[skip] Dossier introuvable : {root}")
                            continue
                        print(f"[scan local] {root}")
                        labels.append(str(root.resolve()))
                        n, f, sf = scan_local_target(
                            root, patterns, args.case_sensitive, both, args.reveal)
                        scanned_files += n
                        findings_all.extend(f)
                        secret_findings_all.extend(sf)
                    source_label = ",".join(labels) if labels else "(aucun dossier valide)"
                    source_label += author_suffix(args, users_r)
                else:
                    eff_discover = _LAST_DISCOVER.get("mode", "") or args.discover
                    eff_window = _LAST_DISCOVER.get("window", "") or args.window
                    eff_lang = _LAST_DISCOVER.get("language", "") or args.language
                    if eff_discover:
                        window_txt = (f", fenetre={eff_window}"
                                      f"{f', langage={eff_lang}' if eff_lang else ''}"
                                      if eff_discover in ("updated", "created") else "")
                        source_label = (f"github-distant:DECOUVERTE:{eff_discover}{window_txt} "
                                        f"({len(names)} depot(s) public(s), AUCUN clone)")
                    elif args.all or (not args.repo and not args.repos_file):
                        source_label = (f"github-distant:TOUS (sans ciblage, kind={args.kind}, "
                                        f"owner={args.owner or 'token-owner'}, {len(names)} depot(s), "
                                        f"branche={args.branch or 'defaut'}, AUCUN clone)")
                    else:
                        shown = ",".join(names[:10])
                        source_label = f"github-distant:cibles:{shown} (AUCUN clone)"
                    source_label += author_suffix(args, users_r if users_r else None)
                    if args.dry_run:
                        print(f"[dry-run] {len(names)} depot(s) cible(s), AUCUN scan :")
                        for n in names:
                            print(f"  - {n}")
                        return
                    print_api_estimate(len(names), args.max_files_per_repo,
                                       extra_per_repo=1 if users_r else 0,
                                       label="decouverte" if eff_discover else "distant")
                    for full_name in names:
                        n, f, sf = scan_remote_target(
                            args.token, full_name, patterns,
                            branch=args.branch,
                            case_sensitive=args.case_sensitive,
                            both=both, reveal=args.reveal,
                            max_files_per_repo=args.max_files_per_repo)
                        scanned_files += n
                        findings_all.extend(f)
                        secret_findings_all.extend(sf)

        # --- Enrichissements mots-cles : historique + allowlist + veille ---
        if args.history:
            print(f"[historique] scan des {args.history_depth} derniers commits "
                  f"(lignes AJOUTEES uniquement)...")
            if src in ("local", "local-ask"):
                for d in local_dirs:
                    _, hf = scan_local_history(
                        d, args.history_depth,
                        lambda line, _p=patterns, _cs=args.case_sensitive:
                            check_line_keywords(line, _p, _cs),
                        repo_label=str(Path(d).resolve()))
                    findings_all.extend(hf)
            else:
                hist_names = list(locals().get("names") or [])
                hist_local = list(locals().get("ilocal") or [])
                for full_name in hist_names:
                    if hist_local:
                        continue
                    _, hf = scan_remote_history(
                        args.token, full_name, args.history_depth, args.branch,
                        lambda line, _p=patterns, _cs=args.case_sensitive:
                            check_line_keywords(line, _p, _cs))
                    findings_all.extend(hf)
            print(f"[historique] total : {len(findings_all)} occurrence(s) "
                  f"(contenu + historique).")

        allow = load_allowlist(args.allowlist)
        ignored_n = mark_ignored(findings_all, allow) if allow else 0
        if ignored_n:
            print(f"[allowlist] {ignored_n} occurrence(s) connue(s) marquee(s) [ignore].")

        if args.since_last_run:
            findings_all, hidden = apply_since_last_run(
                args.since_last_run_key, findings_all, kw_finding_key)
            print(f"[veille] --since-last-run ({args.since_last_run_key}) : "
                  f"{len(findings_all)} nouvelle(s), {hidden} deja vue(s) masquee(s).")

        out = write_txt_report(Path(args.report), keywords, scanned_files,
                               findings_all, source_label, args.case_sensitive,
                               author_users=list(report_users),
                               author_hits=dict(AUTHOR_HITS))
        print(f"\n[OK] Fichiers scannes : {scanned_files}")
        print(f"[OK] Occurrences : {len(findings_all)}")
        print(f"[OK] Rapport texte : {out}")
        for f in findings_all[:10]:
            repo = f.get("repo", "")
            prefix = f"[{repo}] " if repo else ""
            print(f"  - \"{f['keyword']}\" {prefix}{f['file']}:{f['line']} :: {f['detail'][:120]}")

        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                json.dump({
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "keywords": keywords,
                    "source": source_label,
                    "case_sensitive": bool(args.case_sensitive),
                    "modified_by": report_users,
                    "author_hits": dict(AUTHOR_HITS),
                    "scanned_files": scanned_files,
                    "findings_count": len(findings_all),
                    "findings": findings_all,
                }, fh, indent=2, ensure_ascii=False)
            print(f"[OK] Copie JSON : {args.json_out}")
        eff_names = list(locals().get("names") or [])
        if args.save_list and eff_names:
            save_discovered_list(eff_names, args.save_list)
        if args.html:
            write_html_report(args.html, "Rapport mots-cles", source_label,
                              findings_all)
            print(f"[OK] Rapport HTML : {args.html}")
        if args.csv:
            write_csv_report(args.csv, findings_all)
            print(f"[OK] Rapport CSV : {args.csv}")
        if args.sarif:
            write_sarif_report(args.sarif, findings_all)
            print(f"[OK] Rapport SARIF : {args.sarif}")
        code = fail_exit_code(args, findings_all)
        if code:
            print("[fail-on-find] >= 1 occurrence -> exit 1 (CI / pre-commit).")
            sys.exit(code)
        return

    # ================= MODE SECRETS (sans --keywords) =================
    # Le mode SECRETS est toujours autorise : aucun controle de proprietaire,
    # aucune attestation, quel que soit le depot cible.
    if args.discover and decide_github_mode(args.source, args.remote, args.clone) == "clone":
        print("[decouverte] incompatible avec --source clone : "
              "la decouverte consulte les depots publics SANS cloner.")
        sys.exit(2)
    rules_active = active_secret_rules()
    if not rules_active:
        print("[regles] aucune regle active avec ces filtres (voir --list-rules).")
        sys.exit(2)
    print(f"[regles] {len(rules_active)} type(s) d'API-Key/secrets actif(s).")
    if args.reveal:
        print("[reveal] secrets EN CLAIR dans les rapports (defaut). "
              "--no-reveal ou reveal = false dans audit.ini pour masquer.")
    else:
        print("[reveal] secrets masques (--no-reveal / reveal = false).")

    findings_all = []
    scanned_files = 0
    fill_excludes(args.output, args.html, args.csv, args.sarif, args.repos_file,
                  "audit_report.json", "rapport-test.json", "rapport-test2.json",
                  "rapport-test3.json", "depots.txt", "mots_cles.txt",
                  "resultats.txt", "resultats2.txt")
    src = resolve_effective_source(args)
    preset = interactive_preset(args)
    cli_users_s = parse_user_list(args.modified_by)
    local_dirs = []
    users_s = list(cli_users_s)

    if src in ("local", "local-ask"):
        if src == "local-ask":
            choice = ask_interactive_targets(preset="local")
            local_dirs = [m for m in choice.get("local_dirs", []) if m]
            users_s = merge_users(cli_users_s, choice.get("modified_by", []) or [])
        else:
            local_dirs = parse_local_dirs(args.local)
            users_s = list(cli_users_s)
        if args.dry_run:
            print(f"[dry-run] {len(local_dirs)} dossier(s) cible(s), AUCUN scan :")
            for d in local_dirs:
                print(f"  - {d}")
            return
        if users_s:
            local_dirs = filter_local_dirs_by_editors(local_dirs, users_s, args.since, args.until)
        for d in local_dirs:
            root = Path(d)
            if not root.exists():
                print(f"[skip] Dossier introuvable : {root}")
                continue
            print(f"[scan local] {root}")
            n, f = scan_local_tree(root, reveal=args.reveal)
            scanned_files += n
            findings_all.extend(f)
    else:
        mode = decide_github_mode(args.source, args.remote, args.clone)
        if mode == "clone":
            print("[mode] clone : clonage git puis scan local des clones.")
            _, targets, ilocal, iusers_s = resolve_github_targets(
                args.token, args.kind, args.owner or "",
                args.clone_dir, args.max_repos,
                args.repo, args.repos_file, args.refresh, args.interactive,
                local_args=args.local, scan_all=args.all,
                include_forks=args.include_forks, include_archived=args.include_archived,
                preset=preset, modified_by=args.modified_by,
                since=args.since, until=args.until, branch=args.branch,
                min_stars=args.min_stars, topic=args.topic,
                exclude_language=args.exclude_language,
                authorize=lambda names: authorize_secret_targets(args, names))
            users_s = merge_users(cli_users_s, iusers_s)
            if ilocal:
                if users_s:
                    ilocal = filter_local_dirs_by_editors(ilocal, users_s, args.since, args.until)
                for d in ilocal:
                    root = Path(d)
                    if not root.exists():
                        print(f"[skip] Dossier introuvable : {root}")
                        continue
                    print(f"[scan local] {root}")
                    n, f = scan_local_tree(root, reveal=args.reveal)
                    scanned_files += n
                    findings_all.extend(f)
            else:
                for repo_name, dest in targets:
                    n, f = scan_local_tree(dest, reveal=args.reveal)
                    scanned_files += n
                    for x in f:
                        x["repo"] = repo_name
                    findings_all.extend(f)
        else:
            print("[mode] distant : consultation via API GitHub, SANS cloner.")
            names, ilocal, iusers_ss = resolve_remote_names(
                args.token, args.kind, args.owner or "",
                args.repo, args.repos_file, args.all,
                args.interactive, local_args=args.local,
                include_forks=args.include_forks,
                include_archived=args.include_archived,
                max_repos=args.max_repos, preset=preset,
                modified_by=args.modified_by,
                since=args.since, until=args.until, branch=args.branch,
                discover=args.discover, discover_window=args.window,
                discover_language=args.language, discover_sample=args.sample,
                min_stars=args.min_stars, topic=args.topic,
                exclude_language=args.exclude_language, seed=args.seed)
            users_s = merge_users(cli_users_s, iusers_ss)
            if ilocal:
                if users_s:
                    ilocal = filter_local_dirs_by_editors(ilocal, users_s, args.since, args.until)
                for d in ilocal:
                    root = Path(d)
                    if not root.exists():
                        print(f"[skip] Dossier introuvable : {root}")
                        continue
                    print(f"[scan local] {root}")
                    n, f = scan_local_tree(root, reveal=args.reveal)
                    scanned_files += n
                    findings_all.extend(f)
                hist_local = list(ilocal)
            else:
                hist_local = []
                if args.dry_run:
                    print(f"[dry-run] {len(names)} depot(s) cible(s), AUCUN scan :")
                    for n in names:
                        print(f"  - {n}")
                    return
                print_api_estimate(len(names), args.max_files_per_repo,
                                   extra_per_repo=1 if users_s else 0,
                                   label="distant")
                for full_name in names:
                    n, f = scan_remote_repo_secrets(
                        args.token, full_name,
                        branch=args.branch, reveal=args.reveal,
                        max_files_per_repo=args.max_files_per_repo)
                    scanned_files += n
                    findings_all.extend(f)

    # --- Enrichissements SECRETS : historique + allowlist + veille + rapports ---
    if args.history:
        print(f"[historique] scan des {args.history_depth} derniers commits "
              f"(lignes AJOUTEES uniquement)...")
        if src in ("local", "local-ask"):
            for d in local_dirs:
                _, hf = scan_local_history(
                    d, args.history_depth,
                    lambda line: check_line_secrets(line, reveal=args.reveal),
                    repo_label=str(Path(d).resolve()))
                findings_all.extend(hf)
        else:
            for full_name in list(locals().get("names") or []):
                if list(locals().get("hist_local") or []):
                    continue
                _, hf = scan_remote_history(
                    args.token, full_name, args.history_depth, args.branch,
                    lambda line: check_line_secrets(line, reveal=args.reveal))
                findings_all.extend(hf)
        print(f"[historique] total : {len(findings_all)} occurrence(s) "
              f"(contenu + historique).")

    allow_s = load_allowlist(args.allowlist)
    ignored_s = mark_ignored(findings_all, allow_s) if allow_s else 0
    if ignored_s:
        print(f"[allowlist] {ignored_s} occurrence(s) connue(s) marquee(s) [ignore].")

    if args.since_last_run:
        findings_all, hidden_s = apply_since_last_run(
            args.since_last_run_key, findings_all, secret_finding_key)
        print(f"[veille] --since-last-run ({args.since_last_run_key}) : "
              f"{len(findings_all)} nouvelle(s), {hidden_s} deja vue(s) masquee(s).")

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scanned_files": scanned_files,
            "findings_count": len(findings_all),
            "revealed": bool(args.reveal),
            "modified_by": list(users_s),
            "author_hits": dict(AUTHOR_HITS),
            "findings": findings_all,
        }, fh, indent=2, ensure_ascii=False)

    print(f"\n[OK] Fichiers scannes : {scanned_files}")
    print(f"[FINDINGS] : {len(findings_all)}")
    print(f"[RAPPORT] : {args.output}")
    if args.html:
        write_html_report(args.html, "Rapport secrets", "audit-defensif-secrets",
                          findings_all)
        print(f"[OK] Rapport HTML : {args.html}")
    if args.csv:
        write_csv_report(args.csv, findings_all)
        print(f"[OK] Rapport CSV : {args.csv}")
    if args.sarif:
        write_sarif_report(args.sarif, findings_all)
        print(f"[OK] Rapport SARIF : {args.sarif}")
    code = fail_exit_code(args, findings_all)
    if code:
        print("[fail-on-find] >= 1 occurrence -> exit 1 (CI / pre-commit).")
        sys.exit(code)


if __name__ == "__main__":
    main()
