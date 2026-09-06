#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "[VulnHunter] Checking environment..."

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo "[ERROR] Python not found. Please install Python 3.10+"
    exit 1
fi

PY=$(command -v python3 || command -v python)

if [ ! -f ".env" ]; then
    echo "[WARN] .env not found, copying from .env.example"
    cp .env.example .env
    echo "[WARN] Please edit .env and set ANTHROPIC_API_KEY"
    exit 1
fi

if [ ! -d "venv" ]; then
    echo "[VulnHunter] Creating virtual environment..."
    $PY -m venv venv
fi

source venv/bin/activate

echo "[VulnHunter] Installing dependencies..."
pip install -r requirements.txt -q 2>/dev/null

echo "[VulnHunter] Starting server at http://127.0.0.1:8899"
python app.py
