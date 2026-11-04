@echo off
REM First-time setup on Windows: Python venv + packages, spaCy/NLTK data, npm packages, AIT-ADS dataset.
REM Run once from the repo root:  setup.bat
setlocal
cd /d "%~dp0"

REM ---- pick Python 3.12 / 3.11 / 3.10 (spaCy and torch do not support newer versions yet)
set PY=
for %%V in (3.12 3.11 3.10) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1 && set PY=py -%%V
  )
)
if not defined PY (
  python -c "import sys; assert (3,10) <= sys.version_info[:2] <= (3,12)" >nul 2>&1 && set PY=python
)
if not defined PY (
  echo [setup] Python 3.10-3.12 not found. Install it from https://www.python.org/downloads/ and run setup.bat again.
  exit /b 1
)
where node >nul 2>&1 || (
  echo [setup] Node.js not found. Install it with:  winget install OpenJS.NodeJS.LTS
  exit /b 1
)

echo [setup] 1/5 Python virtual environment in backend\.venv  (using %PY%)
if not exist backend\.venv\Scripts\python.exe %PY% -m venv backend\.venv || exit /b 1
set VPY=backend\.venv\Scripts\python.exe
%VPY% -m pip install --upgrade pip

echo [setup] 2/5 Python packages (torch CPU-only build first)
%VPY% -m pip install torch --index-url https://download.pytorch.org/whl/cpu || exit /b 1
%VPY% -m pip install -r backend\requirements.txt || exit /b 1

echo [setup] 3/5 spaCy model and NLTK data
%VPY% -m spacy download en_core_web_sm || exit /b 1
%VPY% -c "import nltk; [nltk.download(p, quiet=True) for p in ['punkt','punkt_tab','treebank','wordnet','averaged_perceptron_tagger','universal_tagset']]" || exit /b 1

echo [setup] 4/5 Frontend packages
pushd frontend
call npm install || (popd & exit /b 1)
popd

echo [setup] 5/5 AIT-ADS dataset (~96 MB download, ~2.8 GB unzipped; only needed for the evaluation)
%VPY% backend\scripts\download_data.py

echo.
echo [setup] Done. Start the app with:  start.bat
endlocal
