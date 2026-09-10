@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo [Trocar] Checking environment...

where python >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.10+
    pause
    exit /b 1
)

if not exist ".env" (
    echo [WARN] .env not found, copying from .env.example
    copy .env.example .env >nul
    echo [WARN] Please edit .env and set API Key
    notepad .env
    pause
    exit /b 1
)

echo [Trocar] Installing dependencies...
python -m pip install -r requirements.txt -q 2>nul

echo [Trocar] Initializing database...
python -c "import asyncio; import db; asyncio.run(db.init_db())"

echo [Trocar] Starting server at http://127.0.0.1:8899
python app.py
pause
