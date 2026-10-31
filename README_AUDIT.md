# Scanner par mots-cles + audit d'API-Key — tous les depots

Outil d'audit avec deux modes :

- **Mode MOTS-CLES** : tu mets tes mots-cles dans un fichier texte (un par ligne),
  tu choisis **depot LOCAL** (`--source local --local ./dossier`) ou **depot DISTANT**
  (`--source remote`, consulte via l'API GitHub **sans cloner** — c'est le defaut pour GitHub),
  et le programme cree un **fichier texte de resultats** avec : mot-cle trouve, endroit
  (fichier + ligne + depot), detail (contenu de la ligne).
- **Mode SECRETS** : detecte **tout type d'API-Key** / token / secret expose
  dans **n'importe quel depot** (local ou distant), pour les revoquer : formats
  connus (OpenAI, AWS, GitHub, Stripe, Slack...), identifiants **OAuth / OIDC**
  (`client_secret`, `refresh_token`, GitHub/Google/Azure/Okta/Auth0...) +
  heuristiques generiques (`api_key = ...`, JWT, cles privees, mots de passe,
  URLs de connexion...).

> Le mode SECRETS est **toujours autorise** : aucune verification de droit
> d'ecriture, aucune attestation, quel que soit le depot cible. `--authorized`
> reste accepte pour compatibilite mais n'a plus d'effet.
> La DECOUVERTE publique (`--discover`, option 9) fonctionne en mode
> mots-cles comme en mode secrets.

## 0. Lancement facile sous Windows (double-clic)

Double-clique sur **`lancer.bat`** : un menu te propose depot LOCAL ou DISTANT,
mots-cles ou SECRETS, 1 depot / tous, la DECOUVERTE publique (option 9 :
fenetre recente ou tirage aleatoire, mots-cles ou secrets), le scan AVANCE
(option 10 : dry-run, historique, HTML/CSV, entropie, contexte), le test rapide,
la liste des types d'API-Key detectes (option 11), le scan secrets d'un depot
tiers (option 12), et l'ouverture de `mots_cles.txt` /
`depots.txt` dans le Bloc-notes.

Tu peux aussi passer des arguments, transmis tels quels au script :
`lancer.bat --help` ou
`lancer.bat --source local --local ./testdata --keywords mots_cles.txt --report resultats.txt`.

Depuis la version "n'importe quel depot", tu peux aussi **glisser-deposer un
dossier ou une URL GitHub directement sur `lancer.bat`**, ou choisir les options
13 (dossier courant) et 14 (URL GitHub) du menu.

## 0bis. Lancer le scanner sur N'IMPORTE QUEL depot

Le scanner n'a plus besoin d'etre copie dans le depot a analyser. Il accepte
une **cible positionnelle** : dossier local, URL GitHub ou `owner/name`. Les
fichiers d'entree fournis avec l'outil (`mots_cles.txt`, `depots.txt`,
`allowlist.txt`, `audit.ini`...) sont cherches dans le dossier courant puis
dans le dossier du scanner ; les rapports sont ecrits dans le dossier courant.

```powershell
# Depuis n'importe quel depot : scanner le dossier courant
python C:\outils\github_audit_scanner.py . --keywords mots_cles.txt   # mots-cles
python C:\outils\github_audit_scanner.py .                            # audit secrets
python C:\outils\github_audit_scanner.py --source local --keywords mots_cles.txt

# Un dossier local precis (Windows, Linux, macOS : n'importe quel depot git)
python C:\outils\github_audit_scanner.py C:\projets\mon-repo
python C:\outils\github_audit_scanner.py /home/moi/mon-repo --keywords mots_cles.txt

# Un depot GitHub distant par URL, sans cloner (token optionnel)
python C:\outils\github_audit_scanner.py https://github.com/owner/repo
python C:\outils\github_audit_scanner.py git@github.com:owner/repo.git
python C:\outils\github_audit_scanner.py owner/repo --report resultats-repo.txt

# Mode SECRETS sur n'importe quel depot (aucune attestation)
python C:\outils\github_audit_scanner.py . --output audit_report.json
python C:\outils\github_audit_scanner.py https://github.com/mon-org/mon-repo \
  --output audit_report.json
```

- Une cible existante sur le disque est traitee en **local** ; une URL GitHub
  ou `owner/name` est traitee en **distant** (API, aucun clone).
- Sans aucune cible, si le dossier courant est un depot git, le scanner
  l'analyse en local (mode SECRETS par defaut, ou mots-cles avec
  `--keywords`) : `python C:\outils\github_audit_scanner.py` suffit.
- `--local` sans valeur vaut `.` et `--source local` sans `--local` scanne le
  dossier courant.
- Une URL avec suffixe `/tree/<branche>` est acceptee ; pour cibler une branche
  precise, ajoute `--branch <branche>`.
- Les anciennes commandes restent valables : `--local`, `--repo`,
  `--repos-file`, `--all`, etc.

## 1. Pre-requis

- Python 3.10+
- `git` installe UNIQUEMENT si tu veux l'ancien mode `--source clone`
- Aucune dependance pip (stdlib uniquement)

## 1bis. Choisir depot LOCAL ou depot DISTANT (option explicite)

```powershell
# Depot LOCAL : un ou plusieurs dossiers sur ton disque
python github_audit_scanner.py --source local --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt

# Depot DISTANT : consulte les depots GitHub via l'API, SANS les cloner (defaut pour GitHub)
$env:GITHUB_TOKEN = "ghp_xxx"
python github_audit_scanner.py --source remote --repo mon-user/mon-repo --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --remote --all --keywords ./mots_cles.txt --report resultats.txt

# Ancien mode par clonage (si tu preferes cloner) :
python github_audit_scanner.py --source clone --repo mon-user/mon-repo --keywords ./mots_cles.txt --report resultats.txt
```

Regles : `--source local` sans `--local` scanne le dossier courant (`.`) ;
`--source remote|clone` refuse `--local` (conflit = erreur claire). Sans
`--source`, c'est auto : `--local` (ou une cible locale) donne = local,
sinon distant GitHub **sans cloner**. Une cible positionnelle (`dossier`,
`owner/name` ou URL GitHub) est acceptee partout, voir la section 0bis.
Options distantes : `--branch <nom>` (branche precise, defaut = branche par
defaut du depot), `--max-files-per-repo 5000` (0 = sans limite, anti quota API :
5000 appels / heure).

## 2. Mode MOTS-CLES (ton nouveau besoin)

### 2.1 Creer le fichier de mots-cles (texte simple, jokers, regex)

Fichier `mots_cles.txt`, **un motif par ligne**.
Lignes vides et lignes commencant par `#` ignorees. 3 types :

```text
# 1) Texte simple : cherche PARTOUT dans la ligne (pas besoin de *).
API_KEY

# 2) Jokers : * = n'importe quoi, ? = 1 seul caractere.
sk-*
pass?word

# 3) Regex Python (prefixe "regex:").
regex:sk-[A-Za-z0-9\-]{10,}
regex:todo[-_ ]secret
```

Le rapport precise le type (`contains` / `wildcard` / `regex`), la ligne
complete (Detail) et l'extrait trouve (Extrait, pour les regex).
Les regex invalides sont ignorees avec un message, le scan continue.

> `sk-*` est deja present dans `mots_cles.txt` : le mode mots-cles trouve donc
> deja les cles `sk-...` partout, sans limite de longueur. Pour ne chercher
> QUE ce prefixe, cree `sk_only.txt` contenant `sk-*` (ou `*sk-*` pour etre
> plus large) et passe-le a `--keywords sk_only.txt`.

### 2.2 Scanner en local, a la demande (1 ou plusieurs dossiers)

```powershell
# Un seul dossier
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt

# Plusieurs dossiers (option repetable ou virgules)
python github_audit_scanner.py --local ./proj1 --local ./proj2 --keywords ./mots_cles.txt --report resultats.txt
```

### 2.3 Scanner des depots GitHub DISTANTS (sans cloner), a la demande (1 / plusieurs / tous)

Par defaut GitHub = consultation A DISTANCE via l'API (arborescence + contenu),
**aucun clone, aucun dossier local**. Ajoute `--source clone` (+ `--refresh`)
si tu preferes l'ancien mode par clonage.

```powershell
$env:GITHUB_TOKEN = "ghp_xxx"

# A) UN SEUL depot cible
python github_audit_scanner.py --repo mon-user/mon-repo --keywords ./mots_cles.txt --report resultats.txt

# B) PLUSIEURS depots cibles (repetable ou virgules)
python github_audit_scanner.py --repo mon-user/repo1,mon-user/repo2 --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --repo mon-user/repo1 --repo ma-org/repo2 --keywords ./mots_cles.txt --report resultats.txt

# C) Liste depuis un fichier texte (un "owner/name" par ligne, voir depots.txt)
python github_audit_scanner.py --repos-file ./depots.txt --keywords ./mots_cles.txt --report resultats.txt

# D) TOUS les depots, sans en indiquer un particulier (nouveau : --all)
#    Liste via GET /user/repos avec affiliation=owner,collaborator,organization_member
#    (perso + collabs + orgs accessibles au token). Forks/archives exclus par defaut.
$env:GITHUB_TOKEN = "ghp_xxx"
python github_audit_scanner.py --all --keywords ./mots_cles.txt --report resultats.txt

#    Variantes : limiter, inclure forks/archives, cibler une org entiere
python github_audit_scanner.py --all --max-repos 10 --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --all --include-forks --include-archived --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --all --kind org --owner ma-org --keywords ./mots_cles.txt --report resultats.txt

#    Sans --all ni --repo hors depot git, le defaut scanne TOUS les depots
#    (sans limite) ; dans un depot git, le dossier courant est scanne en local :
python github_audit_scanner.py --keywords ./mots_cles.txt --report resultats.txt

# E) MODE INTERACTIF : le programme te demande LOCAL ou DISTANT, puis 1 / plusieurs / tous / fichier
python github_audit_scanner.py --interactive --keywords ./mots_cles.txt --report resultats.txt

# Forcer le choix en interactif : --source local / remote / clone + --interactive
python github_audit_scanner.py --source remote --interactive --keywords ./mots_cles.txt --report resultats.txt

# Ancien mode par clonage (au lieu du distant sans clone) :
python github_audit_scanner.py --source clone --repo mon-user/mon-repo --refresh --keywords ./mots_cles.txt --report resultats.txt

# Distant sur une branche precise :
python github_audit_scanner.py --remote --repo mon-user/mon-repo --branch develop --keywords ./mots_cles.txt --report resultats.txt
```

Limites du distant : fichiers > 1 Mo ignores, arborescences tronquees signalees
(gros depots), `--max-files-per-repo` (defaut 5000) pour rester sous le quota API.
Pour un audit exhaustif d'un gros depot, prefere `--source clone`.

### 2.3bis DECOUVERTE publique : sans ciblage, fenetre recente ou aleatoire

Sans `--repo` / `--repos-file` / `--all` : `--discover` choisit lui-meme des
depots **PUBLICS tiers**, consultes via l'API **SANS cloner**, pour de la
recherche de code (mots-cles) ou de secrets, selon le mode courant.

```powershell
$env:GITHUB_TOKEN = "ghp_xxx"

# Depots publics MODIFIES (push) sur les 12 dernieres heures (defaut), echantillon de 20
python github_audit_scanner.py --source remote --discover updated --keywords ./mots_cles.txt --report resultats.txt

# Fenetre personnalisee + filtre langage + echantillon reduit
python github_audit_scanner.py --source remote --discover updated --window 24h --language python --sample 10 --keywords ./mots_cles.txt --report resultats.txt

# Depots publics CREES sur les 7 derniers jours
python github_audit_scanner.py --source remote --discover created --window 7d --keywords ./mots_cles.txt --report resultats.txt

# Tirage ALEATOIRE de 10 depots publics (pas de fenetre)
python github_audit_scanner.py --source remote --discover random --sample 10 --keywords ./mots_cles.txt --report resultats.txt

# Plafond global en plus de l'echantillon
python github_audit_scanner.py --source remote --discover updated --window 12h --sample 50 --max-repos 10 --keywords ./mots_cles.txt --report resultats.txt
```

Details :
- `--discover updated|created` : recherche via `GET /search/repositories`
  (`pushed:>` / `created:>` + `language:` optionnel, tri `updated` / `created`).
  `--window` = `30m` / `12h` / `7d` (nombre seul = heures, defaut `12h`).
  Plafond ~1000 resultats cote API Search (30 req/min avec token).
- `--discover random` : tirages via `GET /repositories?since=<id aleatoire>`
  (IDs croissants, non denses). Token optionnel mais conseille.
- Apres la decouverte : `random.sample` sur `--sample` (`0` = tous les
  candidats), puis plafond `--max-repos` (`0` = sans limite).
- Conflits = erreur claire : incompatible avec `--repo` / `--repos-file` /
  `--all` / `--kind` / `--owner` / `--modified-by` / `--source clone`.
- Le rapport affiche `github-distant:DECOUVERTE:<mode>... (N depot(s) public(s), AUCUN clone)`.
- En interactif distant, choix `5) DECOUVERTE publique` (absent en
  `--source clone`).

### 2.3ter Mode SECRETS sur un depot tiers

Le mode SECRETS est **toujours autorise** : aucune verification de droit
d'ecriture, aucune attestation. Tu peux cibler n'importe quel depot public ou
prive accessible avec ton token. `--authorized` reste accepte pour compatibilite
mais n'a plus d'effet ; `--reveal` est actif par defaut (`--no-reveal` pour
masquer).

```powershell
# Scan secrets d'un depot tiers (aucune attestation)
python github_audit_scanner.py --remote --repo owner/repo --output rapport.json
python github_audit_scanner.py https://github.com/owner/repo --output rapport.json

# Plusieurs cibles
python github_audit_scanner.py --remote --repos-file ./depots.txt --output rapport.json
```

### 2.4 Options utiles

```powershell
# Recherche sensible a la casse (defaut : insensible)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --case-sensitive

# Copie JSON en plus du rapport texte
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --json-out resultats.json
```

### 2.4ter Options transverses : CI, rapports, veille, historique, reproductibilite

```powershell
# DRY-RUN : lister les cibles SANS scanner (securise un gros --sample / --all)
python github_audit_scanner.py --all --keywords ./mots_cles.txt --report resultats.txt --dry-run

# REPRODUCTIBILITE : graine du tirage --discover random / --sample
python github_audit_scanner.py --discover random --sample 10 --seed 42 --keywords ./mots_cles.txt --report resultats.txt

# RESCAN : figer la decouverte puis rescanner la meme liste (reproductible)
python github_audit_scanner.py --discover updated --window 12h --sample 20 --save-list decouverts.txt --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --repos-file ./decouverts.txt --keywords ./mots_cles.txt --report resultats2.txt

# FILTRES CHEMINS : exclure le bruit, ne garder que certaines extensions
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --exclude "*.min.js,*.lock,vendor/" --include-ext .py --include-ext .env

# CONTEXTE : lignes avant/apres chaque trouvaille (style grep -C 2)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --context 2

# CI BLOQUANTE : exit 1 si >= 1 occurrence (GitHub Action / pre-commit)
python github_audit_scanner.py --local . --keywords ./mots_cles.txt --report resultats.txt --fail-on-find

# PRESET : options lues depuis audit.ini, section [audit] (la CLI reste prioritaire)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --config audit.ini

# VEILLE DECOUVERTE / --all : etoiles, topic, anti-langage (cumules avec --dry-run)
python github_audit_scanner.py --discover updated --window 12h --min-stars 50 --topic security --exclude-language JavaScript --keywords ./mots_cles.txt --report resultats.txt

# ALLOWLIST + STRICT : faux positifs connus, CI verte malgre les [ignore]
python github_audit_scanner.py --local . --keywords ./mots_cles.txt --report resultats.txt --fail-on-find --strict --allowlist allowlist.txt

# HISTORIQUE : lignes AJOUTEES des 20 derniers commits (cle revoquee = toujours visible)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --history --history-depth 20
python github_audit_scanner.py --remote --repo mon-user/mon-repo --output rapport.json --history --history-depth 20

# VEILLE DIFF : que du NOUVEAU depuis le dernier run (cron : 1 cle par job, cache .audit_state.json)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --since-last-run --since-last-run-key quotidien

# ENTROPIE : chaines aleatoires type cle/token sans regex connue (plus de faux positifs)
python github_audit_scanner.py --local ./mon-projet --output rapport.json --entropy --entropy-threshold 4.5 --entropy-min-len 20

# RAPPORTS : HTML plie par depot, CSV (Excel), SARIF (onglet Security GitHub / VS Code)
python github_audit_scanner.py --local ./mon-projet --keywords ./mots_cles.txt --report resultats.txt --html rapport.html --csv rapport.csv --sarif rapport.sarif

# QUOTA API : retry/backoff auto sur 403 (X-RateLimit-Reset) + estimation d'appels avant chaque scan distant
# --no-retry pour echouer vite au lieu d'attendre
python github_audit_scanner.py --remote --all --keywords ./mots_cles.txt --report resultats.txt --no-retry
```

### 2.4quater CI + pre-commit (bloquant, sur un depot)

- Workflow GitHub Action : [`.github/workflows/audit.yml`](.github/workflows/audit.yml)
  (push + manuel, `--fail-on-find --strict --allowlist`, rapports en artefact 30 jours).
  Il lance les mots-cles **et** le mode SECRETS (API-Key : JSON, HTML, CSV, SARIF).
- Hook pre-commit : [`.pre-commit-config.yaml`](.pre-commit-config.yaml)
  (`pip install pre-commit && pre-commit install` : bloque le commit si occurrence).
- Preset : [`audit.ini`](audit.ini) (`--config audit.ini`, section `[audit]`).
- Faux positifs : [`allowlist.txt`](allowlist.txt) (`--allowlist allowlist.txt`
  + `--strict` : les occurrences `[ignore]` ne font plus echouer la CI).

### 2.4bis Filtrer : uniquement depots MODIFIES par un utilisateur (--modified-by)

Ne garde que les depots ou dossiers **modifies par cet/ces utilisateur(s)**,
avant de scanner. Fonctionne partout : distant, clone, local-git, interactif,
mots-cles et SECRETS.

```powershell
# DISTANT (GitHub, sans cloner) : login GitHub, verifie via l'API Commits (author=...)
$env:GITHUB_TOKEN = "ghp_xxx"
python github_audit_scanner.py --remote --all --modified-by alice --keywords ./mots_cles.txt --report resultats.txt
python github_audit_scanner.py --remote --all --modified-by alice,bob --kind org --owner ma-org --output rapport.json

# Fenetre de temps optionnelle (commits APRES / AVANT une date ISO)
python github_audit_scanner.py --remote --all --modified-by alice --since 2024-01-01 --until 2025-01-01 --keywords ./mots_cles.txt --report resultats.txt

# LOCAL (depot git) : motif git log --author (nom ou email), avec --since/--until de git log
python github_audit_scanner.py --source local --local ./mon-projet --modified-by "Alice Dupont" --keywords ./mots_cles.txt --report resultats.txt

# CLONE : meme filtre GitHub, mais seuls les depots gardes sont clones
python github_audit_scanner.py --source clone --all --modified-by alice --keywords ./mots_cles.txt --report resultats.txt

# INTERACTIF : le script demande "Filtrer : uniquement depots MODIFIES par ... (vide = tous)"
python github_audit_scanner.py --interactive --keywords ./mots_cles.txt --report resultats.txt
```

Details :
- distant : `GET /repos/{full}/commits?author=<login>&per_page=5` (+ `sha=<branch>`,
  `since=`, `until=` si precises). Depot garde si au moins 1 commit trouve.
- local : `git log --author=<motif> -n 1` dans chaque dossier. Dossier **non-git** :
  garde quand meme avec avertissement (auteur inverifiable), jamais exclu en silence.
- rapports : `resultats.txt` affiche `Filtre auteur : depots modifies par ...`
  + dernier commit vu par depot (user / date / sha / message) ; les JSON
  (`--json-out`, `--output`) contiennent `modified_by` + `author_hits`.

### 2.5 Format du fichier de resultats

`resultats.txt` contient pour chaque occurrence :

```text
--- Mot-cle : "API_KEY" (1 occurrence(s)) ---
[1] Trouve : "API_KEY"
     Endroit  : C:\...\app.env (ligne 2)
     Detail   : API_KEY = "ma-cle-factice-de-test-12345"
```

Test sans risque :

```powershell
python github_audit_scanner.py --local ./testdata --keywords ./mots_cles.txt --report resultats.txt
```

## 3. Mode SECRETS (audit de TOUS types d'API-Key)

Le mode SECRETS (sans `--keywords`) detecte :

- **des formats connus de fournisseurs** : OpenAI, Anthropic, Google/Firebase,
  AWS, Azure, GitHub, GitLab, Bitbucket, npm, PyPI, Docker, Stripe, Square,
  PayPal, Shopify, Slack, Discord, Telegram, Twilio, SendGrid, Mailgun,
  Datadog, Sentry, New Relic, Notion, Linear, Airtable, HubSpot, Supabase,
  PlanetScale, DigitalOcean, Cloudflare, Vercel, Netlify... (100+ regles) ;
- **des identifiants OAuth / OpenID Connect** : `client_secret`,
  `refresh_token`, `access_token`, ID token, code d'autorisation, PKCE,
  tokens OAuth GitHub/GitLab, Google OAuth, Azure AD/Entra, Okta, Auth0,
  Facebook OAuth... ;
- **des heuristiques generiques** : affectations `api_key = ...`,
  `client_secret`, `access_token`, `password`, camelCase `apiKey`, JWT,
  Bearer, Basic Auth, URLs avec identifiants, chaines de connexion
  PostgreSQL/MySQL/MongoDB/Redis, cles privees RSA/OpenSSH/PGP ;
- **en option**, des chaines a haute entropie (`--entropy`) qui ne
  correspondent a aucun format connu.

### 3.1 Lister les types detectes (sans scanner)

```powershell
# Toutes les regles : categorie, severite, identifiant, fournisseur
python github_audit_scanner.py --list-rules

# Seulement certaines categories / severites
python github_audit_scanner.py --list-rules --only-category ai,cloud
python github_audit_scanner.py --list-rules --only-category oauth
python github_audit_scanner.py --list-rules --min-severity critical
```

Categories : `ai`, `cloud`, `code`, `payments`, `comms`, `social`, `devtools`,
`observability`, `databases`, `auth`, `oauth`, `crypto`, `generic`, `custom`.

### 3.2 Scanner

```powershell
# Local (1 ou plusieurs dossiers)
python github_audit_scanner.py --source local --local ./mon-projet --output rapport.json

# GitHub DISTANT sans cloner (defaut) : 1 depot / plusieurs / fichier / TOUS sans ciblage
$env:GITHUB_TOKEN = "ghp_xxx"
python github_audit_scanner.py --remote --repo mon-user/mon-repo --output rapport.json
python github_audit_scanner.py --remote --all --output rapport.json
python github_audit_scanner.py --remote --repos-file ./depots.txt --output rapport.json
python github_audit_scanner.py --remote --all --kind org --owner ma-org --output rapport.json

# Ancien mode par clonage :
python github_audit_scanner.py --source clone --repo mon-user/mon-repo --output rapport.json
python github_audit_scanner.py --interactive --output rapport.json

# Filtrer les familles de cles (moins de bruit, audit cible)
python github_audit_scanner.py --local . --output rapport.json --only-category ai,cloud
python github_audit_scanner.py --local . --output rapport.json --only-category oauth
python github_audit_scanner.py --local . --output rapport.json --skip-category generic,payments
python github_audit_scanner.py --local . --output rapport.json --min-severity high

# Desactiver les heuristiques generiques (formats connus uniquement)
python github_audit_scanner.py --local . --output rapport.json --no-generic

# Ces filtres s'appliquent aussi aux hits d'entropie (--entropy).

# Ajouter des regles maison (voir 3.3)
python github_audit_scanner.py --local . --output rapport.json --rules-file api_key_rules.example.json

# Rapports : JSON (defaut), HTML, CSV, SARIF (onglet Security GitHub / VS Code)
python github_audit_scanner.py --local . --output rapport.json --html rapport.html --csv rapport.csv --sarif rapport.sarif
```

### 3.3 Regles personnalisees (JSON)

Un fichier JSON peut ajouter des formats maison sans modifier le script.
Exemple : [`api_key_rules.example.json`](api_key_rules.example.json).

```json
{
  "rules": [
    {
      "id": "acme_internal_key",
      "provider": "ACME",
      "category": "custom",
      "severity": "critical",
      "regex": "\\bacme_(?:live|test)_[A-Za-z0-9]{24,}\\b",
      "group": 0,
      "min_len": 24,
      "min_entropy": 0.0,
      "priority": 130,
      "description": "Cle interne ACME"
    }
  ]
}
```

Champs : `id`, `provider`, `category`, `severity`, `regex` (obligatoires) ;
`group` (groupe de capture du secret, 0 par defaut), `min_len`, `min_entropy`,
`priority` (plus grand = gagne en cas de chevauchement), `ignore_case`,
`require_mixed`, `allow_placeholder` (ne pas filtrer les valeurs contenant
`example`, `your`, `xxxx`...), `check_reference` (filtrer les references
`os.getenv`, `config.get`...), `description`. Une regex invalide est ignoree
avec un message.

### 3.4 Securite des rapports

Affichage par defaut : `match_preview`, `detail` et les lignes de `context`
sont en clair (`reveal = true`). `--no-reveal` (ou `reveal = false` dans
`audit.ini`) masque les secrets.
Aucune validation reseau des cles. Token jamais ecrit dans les logs.

Exemple de CI bloquante sur un depot (a adapter aux dossiers de test) :

```powershell
python github_audit_scanner.py --source local --local . --output audit_report.json `
  --fail-on-find --strict --allowlist allowlist.txt `
  --exclude ".git/" --exclude "testdata/" --exclude "tests/"
```

## 4. Si une vraie fuite est trouvee

1. Revoque la cle immediatement chez le provider.
2. Purge l'historique git (`git filter-repo` / BFG) — un simple commit ne suffit pas.
3. Passe aux variables d'environnement / gestionnaire de secrets.
4. Supprime tout rapport contenant des secrets en clair.

## 5. Fichiers

- `github_audit_scanner.py` — scanner (stdlib uniquement)
- `mots_cles.txt` — exemple de fichier de mots-cles (un par ligne)
- `depots.txt` — exemple de fichier de depots cibles (un `owner/name` par ligne)
- `api_key_rules.example.json` — exemple de regles API-Key personnalisees
- `resultats.txt` — rapport texte genere (quoi / ou / detail)
- `testdata/` — exemples factices pour tester (dont `secrets_demo.env`)
- `tests/test_api_key_detection.py` — tests unitaires (`python -m unittest discover -s tests -v`)
- `.github/workflows/audit.yml` — GitHub Action bloquante mots-cles + secrets (`--fail-on-find --strict`)
- `.pre-commit-config.yaml` — hook pre-commit bloquant (exemple)
- `audit.ini` — preset d'options (`--config audit.ini`)
- `allowlist.txt` — faux positifs connus (`--allowlist` + `--strict`)
- `.audit_state.json` — cache de veille (`--since-last-run`, cree au 1er run)
