@echo off
REM ============================================================
REM  Lanceur Windows pour github_audit_scanner.py
REM  Double-clic dessus pour ouvrir le menu.
REM  Tu peux aussi l'appeler avec des arguments, transmis au script :
REM    lancer.bat --help
REM    lancer.bat --source local --local ./testdata --keywords mots_cles.txt --report resultats.txt
REM    lancer.bat C:\chemin\vers\un\depot
REM    lancer.bat https://github.com/owner/repo
REM  Glisse-depose un dossier (ou une URL) sur ce fichier pour le scanner.
REM ============================================================
chcp 65001 >nul

set "TOOL_DIR=%~dp0"
set "SCANNER=%TOOL_DIR%github_audit_scanner.py"
set PYTHON=python
where %PYTHON% >nul 2>nul
if errorlevel 1 (
  echo [ERREUR] Python est introuvable dans le PATH.
  echo Installe Python 3.10+ depuis https://www.python.org/downloads/
  echo Pense a cocher "Add python.exe to PATH" pendant l'installation.
  echo.
  pause
  exit /b 1
)

REM --- Mode direct : arguments / cible glissee-deposee, transmis au script ---
if not "%~1"=="" (
  %PYTHON% "%SCANNER%" %*
  echo.
  pause
  exit /b %ERRORLEVEL%
)

:MENU
cls
echo ==============================================================
echo   SCANNER GitHub - Lanceur Windows
echo   Dossier courant : "%CD%"
echo   Outil : "%TOOL_DIR%"
echo ==============================================================
echo.
echo   --- Depot LOCAL (sur ton disque) ---
echo   1. Mots-cles  - dossier LOCAL (tu choisis, defaut = dossier courant)
echo   2. Mode SECRETS - dossier LOCAL (detecte les cles exposees)
echo   13. SCANNER CE DOSSIER / depot courant (mots-cles, 1 clic)
echo.
echo   --- Depot DISTANT (GitHub via API, SANS cloner) ---
echo   3. Mots-cles  - 1 depot DISTANT (owner/name ou URL GitHub)
echo   4. Mots-cles  - TOUS mes depots DISTANTS (sans rien indiquer)
echo   5. Mode SECRETS - depot DISTANT (1 ou tous)
echo   12. Mode SECRETS - depot tiers (sans attestation)
echo   14. SCANNER une URL GitHub (n'importe quel depot public)
echo.
echo   --- DECOUVERTE publique (SANS ciblage) ---
echo   9. DECOUVERTE - depots PUBLICS : fenetre recente ou tirage aleatoire
echo.
echo   --- Autres ---
echo   6. Mode INTERACTIF guide (le script te pose les questions)
echo   7. Test rapide (scan du dossier testdata, sans risque)
echo   8. Ouvrir mots_cles.txt / depots.txt dans le Bloc-notes
echo   10. Scan AVANCE (dry-run, historique, HTML/CSV, entropie, veille...)
echo   11. Lister tous les types d'API-Key detectes (mode SECRETS)
echo   0. Quitter
echo.
echo   Astuce : glisse-depose un dossier ou une URL GitHub sur lancer.bat.
echo   Chaque option propose le filtre "uniquement MODIFIE par ..." (vide = tous).
echo   La DECOUVERTE (9) porte sur des depots PUBLICS tiers : mots-cles ou secrets.
echo.
set CHOIX=
set /p CHOIX="Votre choix [0-14] : "

if "%CHOIX%"=="1" goto MOTS_LOCAL
if "%CHOIX%"=="2" goto SECRETS_LOCAL
if "%CHOIX%"=="3" goto MOTS_DISTANT_1
if "%CHOIX%"=="4" goto MOTS_DISTANT_ALL
if "%CHOIX%"=="5" goto SECRETS_DISTANT
if "%CHOIX%"=="9" goto DECOUVERTE
if "%CHOIX%"=="10" goto AVANCE
if "%CHOIX%"=="6" goto INTERACTIF
if "%CHOIX%"=="7" goto TEST
if "%CHOIX%"=="8" goto EDIT_FILES
if "%CHOIX%"=="11" goto LIST_RULES
if "%CHOIX%"=="12" goto SECRETS_AUTHORIZED
if "%CHOIX%"=="13" goto SCAN_HERE
if "%CHOIX%"=="14" goto SCAN_URL
if "%CHOIX%"=="0" exit /b 0
goto MENU

REM ------------------------------------------------------------
:MOTS_LOCAL
echo.
set DOSSIER=
set KEYWORDS=
set REPORT=
set /p DOSSIER="Dossier local a scanner [.] : "
if "%DOSSIER%"=="" set DOSSIER=.
set /p KEYWORDS="Fichier de mots-cles [mots_cles.txt] : "
if "%KEYWORDS%"=="" set KEYWORDS=mots_cles.txt
set /p REPORT="Fichier de resultats a creer [resultats.txt] : "
if "%REPORT%"=="" set REPORT=resultats.txt
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement MODIFIE par (login GitHub ou nom git, vide = tous) : "
echo.
echo Lancement : mots-cles LOCAL sur "%DOSSIER%" ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source local --local "%DOSSIER%" --keywords "%KEYWORDS%" --report "%REPORT%"
) else (
  %PYTHON% "%SCANNER%" --source local --local "%DOSSIER%" --keywords "%KEYWORDS%" --report "%REPORT%" --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
:SECRETS_LOCAL
echo.
set DOSSIER=
set OUTPUT=
set /p DOSSIER="Dossier local a auditer [.] : "
if "%DOSSIER%"=="" set DOSSIER=.
set /p OUTPUT="Fichier rapport JSON [audit_report.json] : "
if "%OUTPUT%"=="" set OUTPUT=audit_report.json
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement MODIFIE par (nom/email git, vide = tous) : "
echo.
echo Lancement : SECRETS LOCAL sur "%DOSSIER%" (resultats masques par defaut) ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source local --local "%DOSSIER%" --output "%OUTPUT%"
) else (
  %PYTHON% "%SCANNER%" --source local --local "%DOSSIER%" --output "%OUTPUT%" --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
REM Sous-routine : verifie le token. errorlevel 0 = OK, 1 = annule.
:CHECK_TOKEN
if not "%GITHUB_TOKEN%"=="" exit /b 0
echo.
echo Aucun token GitHub detecte dans cette fenetre.
echo Cree un token (lecture des depots cibles) : GitHub ^> Settings ^> Developer settings ^> Personal access tokens.
set GITHUB_TOKEN=
set /p GITHUB_TOKEN="Colle ton token ici (laisse vide pour annuler) : "
if "%GITHUB_TOKEN%"=="" exit /b 1
exit /b 0

REM ------------------------------------------------------------
:MOTS_DISTANT_1
call :CHECK_TOKEN
if errorlevel 1 (
  echo Annule.
  echo.
  pause
  goto MENU
)
echo.
set REPO=
set KEYWORDS=
set REPORT=
set /p REPO="Depot distant cible (owner/name ou URL GitHub) : "
if "%REPO%"=="" goto MENU
set /p KEYWORDS="Fichier de mots-cles [mots_cles.txt] : "
if "%KEYWORDS%"=="" set KEYWORDS=mots_cles.txt
set /p REPORT="Fichier de resultats a creer [resultats.txt] : "
if "%REPORT%"=="" set REPORT=resultats.txt
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement depots MODIFIES par (login GitHub, vide = tous) : "
echo.
echo Lancement : mots-cles DISTANT sur %REPO% (SANS cloner) ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source remote --repo "%REPO%" --keywords "%KEYWORDS%" --report "%REPORT%"
) else (
  %PYTHON% "%SCANNER%" --source remote --repo "%REPO%" --keywords "%KEYWORDS%" --report "%REPORT%" --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
:MOTS_DISTANT_ALL
call :CHECK_TOKEN
if errorlevel 1 (
  echo Annule.
  echo.
  pause
  goto MENU
)
echo.
echo Tous les depots accessibles au token, SANS en indiquer un (SANS cloner).
set MAXR=
set /p MAXR="Limite de depots (0 = sans limite, conseille 5 pour tester) [5] : "
if "%MAXR%"=="" set MAXR=5
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement depots MODIFIES par (login GitHub, vide = tous) : "
echo.
echo Lancement : mots-cles DISTANT sur TOUS (%MAXR% max) ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source remote --all --max-repos %MAXR% --keywords mots_cles.txt --report resultats.txt
) else (
  %PYTHON% "%SCANNER%" --source remote --all --max-repos %MAXR% --keywords mots_cles.txt --report resultats.txt --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
:SECRETS_DISTANT
call :CHECK_TOKEN
if errorlevel 1 (
  echo Annule.
  echo.
  pause
  goto MENU
)
echo.
echo  a) Un seul depot   b) Tous mes depots (sans indiquer)
set SMODE=
set /p SMODE="Choix [a/b, defaut a] : "
if "%SMODE%"=="" set SMODE=a
if /i "%SMODE%"=="b" goto SECRETS_DISTANT_ALL
goto SECRETS_DISTANT_ONE

:SECRETS_DISTANT_ONE
set REPO=
set OUTPUT=
set /p REPO="Depot distant cible (owner/name ou URL GitHub) : "
if "%REPO%"=="" goto MENU
set /p OUTPUT="Fichier rapport JSON [audit_report.json] : "
if "%OUTPUT%"=="" set OUTPUT=audit_report.json
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement depots MODIFIES par (login GitHub, vide = tous) : "
echo.
echo Lancement : SECRETS DISTANT sur %REPO% (SANS cloner) ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source remote --repo "%REPO%" --output "%OUTPUT%"
) else (
  %PYTHON% "%SCANNER%" --source remote --repo "%REPO%" --output "%OUTPUT%" --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

:SECRETS_DISTANT_ALL
set OUTPUT=
set MAXR=
set /p OUTPUT="Fichier rapport JSON [audit_report.json] : "
if "%OUTPUT%"=="" set OUTPUT=audit_report.json
set /p MAXR="Limite de depots (0 = sans limite) [5] : "
if "%MAXR%"=="" set MAXR=5
set AUTEUR=
set /p AUTEUR="Filtrer : uniquement depots MODIFIES par (login GitHub, vide = tous) : "
echo.
echo Lancement : SECRETS DISTANT sur TOUS (SANS cloner) ...
if "%AUTEUR%"=="" (
  %PYTHON% "%SCANNER%" --source remote --all --max-repos %MAXR% --output "%OUTPUT%"
) else (
  %PYTHON% "%SCANNER%" --source remote --all --max-repos %MAXR% --output "%OUTPUT%" --modified-by "%AUTEUR%"
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
:SECRETS_AUTHORIZED
call :CHECK_TOKEN
if errorlevel 1 (
  echo Annule.
  echo.
  pause
  goto MENU
)
echo.
echo Audit SECRETS d'un depot tiers : toujours autorise, sans attestation.
set REPO=
set OUTPUT=
set /p REPO="Depot distant cible (owner/name ou URL GitHub) : "
if "%REPO%"=="" goto MENU
set /p OUTPUT="Fichier rapport JSON [audit_report.json] : "
if "%OUTPUT%"=="" set OUTPUT=audit_report.json
echo.
echo Lancement : SECRETS sur %REPO% (SANS cloner) ...
%PYTHON% "%SCANNER%" --source remote --repo "%REPO%" --output "%OUTPUT%"
echo.
pause
goto MENU

REM ------------------------------------------------------------
:INTERACTIF
echo.
echo Le script Python va te guider (LOCAL ou DISTANT, 1 / plusieurs / tous).
%PYTHON% "%SCANNER%" --interactive --keywords mots_cles.txt --report resultats.txt
echo.
pause
goto MENU

REM ------------------------------------------------------------
:DECOUVERTE
call :CHECK_TOKEN
if errorlevel 1 (
  echo Annule.
  echo.
  pause
  goto MENU
)
echo.
echo DECOUVERTE publique : depots PUBLICS tiers, SANS ciblage, SANS cloner.
echo Mode courant : mots-cles ou secrets (selon les options du scan).
echo   U = modifies (push) sur une fenetre recente (ex : 12h)
echo   C = crees sur une fenetre recente
echo   R = tirage aleatoire
set DMODE=
set /p DMODE="Type de decouverte [U/C/R, defaut U] : "
if "%DMODE%"=="" set DMODE=U
if /i "%DMODE%"=="R" goto DECOUVERTE_RANDOM
if /i "%DMODE%"=="C" ( set DTYPE=created ) else ( set DTYPE=updated )
goto DECOUVERTE_WINDOW

:DECOUVERTE_RANDOM
set DSAMPLE=
set /p DSAMPLE="Echantillon aleatoire (0 = tous, conseille 5 pour tester) [5] : "
if "%DSAMPLE%"=="" set DSAMPLE=5
goto DECOUVERTE_KEYWORDS

:DECOUVERTE_WINDOW
set DWINDOW=
set /p DWINDOW="Fenetre recente (ex : 30m, 12h, 24h, 7d) [12h] : "
if "%DWINDOW%"=="" set DWINDOW=12h
set DLANG=
set /p DLANG="Langage (vide = tous, ex : python) : "
set DSAMPLE=
set /p DSAMPLE="Echantillon aleatoire parmi les candidats (0 = tous) [20] : "
if "%DSAMPLE%"=="" set DSAMPLE=20
goto DECOUVERTE_KEYWORDS

:DECOUVERTE_KEYWORDS
set DKEYWORDS=
set /p DKEYWORDS="Fichier de mots-cles [mots_cles.txt] : "
if "%DKEYWORDS%"=="" set DKEYWORDS=mots_cles.txt
set DREPORT=
set /p DREPORT="Fichier de resultats a creer [resultats.txt] : "
if "%DREPORT%"=="" set DREPORT=resultats.txt
echo.
if /i "%DMODE%"=="R" goto DECOUVERTE_RUN_RANDOM
goto DECOUVERTE_RUN_WINDOW

:DECOUVERTE_RUN_RANDOM
echo Lancement : DECOUVERTE aleatoire (%DSAMPLE% depot(s) public(s), mots-cles) ...
%PYTHON% "%SCANNER%" --source remote --discover random --sample %DSAMPLE% --keywords "%DKEYWORDS%" --report "%DREPORT%"
echo.
pause
goto MENU

:DECOUVERTE_RUN_WINDOW
if "%DLANG%"=="" goto DECOUVERTE_RUN_WINDOW_NOLANG
echo Lancement : DECOUVERTE %DTYPE% (fenetre %DWINDOW%, langage %DLANG%, echantillon %DSAMPLE%) ...
%PYTHON% "%SCANNER%" --source remote --discover %DTYPE% --window "%DWINDOW%" --language "%DLANG%" --sample %DSAMPLE% --keywords "%DKEYWORDS%" --report "%DREPORT%"
echo.
pause
goto MENU

:DECOUVERTE_RUN_WINDOW_NOLANG
echo Lancement : DECOUVERTE %DTYPE% (fenetre %DWINDOW%, echantillon %DSAMPLE%) ...
%PYTHON% "%SCANNER%" --source remote --discover %DTYPE% --window "%DWINDOW%" --sample %DSAMPLE% --keywords "%DKEYWORDS%" --report "%DREPORT%"
echo.
pause
goto MENU

REM ------------------------------------------------------------
:AVANCE
echo.
echo Scan AVANCE : options CI / rapports / veille / historique (tous depots).
echo Laisse vide pour garder le defaut propose entre crochets.
set ADOSS=
set /p ADOSS="Dossier local a scanner [.] : "
if "%ADOSS%"=="" set ADOSS=.
set AKEYW=
set /p AKEYW="Fichier de mots-cles [mots_cles.txt] : "
if "%AKEYW%"=="" set AKEYW=mots_cles.txt
set AREP=
set /p AREP="Rapport texte [resultats.txt] : "
if "%AREP%"=="" set AREP=resultats.txt
set AHTML=
set /p AHTML="Rapport HTML (vide = non) [] : "
set ACSV=
set /p ACSV="Rapport CSV (vide = non) [] : "
set ACTX=
set /p ACTX="Lignes de contexte autour des trouvailles [2] : "
if "%ACTX%"=="" set ACTX=2
set AHIST=
set /p AHIST="Scanner aussi l'historique git ? [o/N] : "
set AENT=
set /p AENT="Detecter les chaines haute-entropie ? [o/N] : "
set ADRY=
set /p ADRY="Mode dry-run (lister sans scanner) ? [o/N] : "
set AEXTRA=
if not "%AHTML%"=="" set AEXTRA=%AEXTRA% --html "%AHTML%"
if not "%ACSV%"=="" set AEXTRA=%AEXTRA% --csv "%ACSV%"
if /i "%AHIST%"=="o" set AEXTRA=%AEXTRA% --history --history-depth 20
if /i "%AHIST%"=="oui" set AEXTRA=%AEXTRA% --history --history-depth 20
if /i "%AENT%"=="o" set AEXTRA=%AEXTRA% --entropy
if /i "%AENT%"=="oui" set AEXTRA=%AEXTRA% --entropy
echo.
if /i "%ADRY%"=="o" (
  echo Lancement : scan AVANCE dry-run sur "%ADOSS%" ...
  %PYTHON% "%SCANNER%" --source local --local "%ADOSS%" --keywords "%AKEYW%" --report "%AREP%" --context %ACTX% --dry-run %AEXTRA%
) else if /i "%ADRY%"=="oui" (
  echo Lancement : scan AVANCE dry-run sur "%ADOSS%" ...
  %PYTHON% "%SCANNER%" --source local --local "%ADOSS%" --keywords "%AKEYW%" --report "%AREP%" --context %ACTX% --dry-run %AEXTRA%
) else (
  echo Lancement : scan AVANCE sur "%ADOSS%" ...
  %PYTHON% "%SCANNER%" --source local --local "%ADOSS%" --keywords "%AKEYW%" --report "%AREP%" --context %ACTX% %AEXTRA%
)
echo.
pause
goto MENU

REM ------------------------------------------------------------
:SCAN_HERE
echo.
echo Scan mots-cles du DOSSIER COURANT : %CD%
set HREPORT=
set /p HREPORT="Fichier de resultats a creer [resultats.txt] : "
if "%HREPORT%"=="" set HREPORT=resultats.txt
echo.
%PYTHON% "%SCANNER%" --source local --local "%CD%" --keywords "%TOOL_DIR%mots_cles.txt" --report "%HREPORT%"
echo.
pause
goto MENU

REM ------------------------------------------------------------
:SCAN_URL
echo.
echo Scan d'un depot GitHub par URL ou owner/name (SANS cloner).
set URL=
set /p URL="URL GitHub ou owner/name : "
if "%URL%"=="" goto MENU
set UREPORT=
set /p UREPORT="Fichier de resultats a creer [resultats.txt] : "
if "%UREPORT%"=="" set UREPORT=resultats.txt
echo.
echo Lancement : mots-cles DISTANT sur %URL% ...
%PYTHON% "%SCANNER%" --source remote --repo "%URL%" --keywords "%TOOL_DIR%mots_cles.txt" --report "%UREPORT%"
echo.
pause
goto MENU

REM ------------------------------------------------------------
:TEST
echo.
echo Test rapide et sans risque sur le dossier testdata de l'outil ...
%PYTHON% "%SCANNER%" --source local --local "%TOOL_DIR%testdata" --keywords "%TOOL_DIR%mots_cles.txt" --report resultats.txt
echo.
pause
goto MENU

REM ------------------------------------------------------------
:LIST_RULES
echo.
echo Liste des types d'API-Key / secrets detectes par le mode SECRETS :
%PYTHON% "%SCANNER%" --list-rules
echo.
pause
goto MENU

REM ------------------------------------------------------------
:EDIT_FILES
if not exist "%TOOL_DIR%mots_cles.txt" echo # Un mot-cle par ligne > "%TOOL_DIR%mots_cles.txt"
if not exist "%TOOL_DIR%depots.txt" echo # Un depot owner/name par ligne > "%TOOL_DIR%depots.txt"
start notepad.exe "%TOOL_DIR%mots_cles.txt"
start notepad.exe "%TOOL_DIR%depots.txt"
goto MENU
