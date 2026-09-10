import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = DATA_DIR / "reports"
TEMP_DIR = DATA_DIR / "temp"
DB_PATH = DATA_DIR / "trocar.db"

SKILL_DIR = Path(os.getenv("SKILL_DIR", str(DATA_DIR / "skill")))
SKILL_FILE = SKILL_DIR / "SKILL.md"
KNOWLEDGE_DIR = BASE_DIR / "knowledge"

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
MODEL = os.getenv("MODEL", "claude-sonnet-5")
MODEL_STRONG = os.getenv("MODEL_STRONG", "claude-opus-5")
MODEL_FAST = os.getenv("MODEL_FAST", "claude-haiku-4-5-20251001")
MAX_TOKENS = int(os.getenv("MAX_TOKENS", "16384"))

BURP_PROXY = os.getenv("BURP_PROXY", "http://127.0.0.1:8080")
GITHUB_PROXY = os.getenv("GITHUB_PROXY", "http://127.0.0.1:7890")

MAX_CONCURRENT = int(os.getenv("MAX_CONCURRENT", "3"))
TEMP_LIMIT_MB = int(os.getenv("TEMP_LIMIT_MB", "5120"))
INACTIVITY_TIMEOUT = int(os.getenv("INACTIVITY_TIMEOUT", "600"))
MAX_TURNS = int(os.getenv("MAX_TURNS", "200"))
NO_FINDING_STOP = int(os.getenv("NO_FINDING_STOP", "8"))

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8899"))
