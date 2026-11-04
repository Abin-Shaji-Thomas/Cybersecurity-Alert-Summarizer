@echo off
REM Start the backend (FastAPI on :8000) and the frontend (Vite on :5173) in two windows, then open the browser.
cd /d "%~dp0"
if not exist backend\.venv\Scripts\python.exe (
  echo Run setup.bat first.
  exit /b 1
)
start "Alert Summarizer - backend" cmd /k "cd /d %~dp0backend && .venv\Scripts\python -m uvicorn main:app --port 8000"
start "Alert Summarizer - frontend" cmd /k "cd /d %~dp0frontend && npm run dev -- --port 5173 --strictPort"
REM give both servers a few seconds to start
timeout /t 6 /nobreak >nul
start "" http://localhost:5173
