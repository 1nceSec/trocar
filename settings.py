import json
from pathlib import Path
from config import (
    DATA_DIR, ANTHROPIC_API_KEY, MODEL, MODEL_STRONG, MODEL_FAST, MAX_TOKENS,
    BURP_PROXY, MAX_CONCURRENT,
)

SETTINGS_FILE = DATA_DIR / "settings.json"

DEFAULTS = {
    "provider": "anthropic",
    "model": MODEL,
    "model_strong": MODEL_STRONG,
    "model_fast": MODEL_FAST,
    "api_key": ANTHROPIC_API_KEY,
    "base_url": "",
    "max_tokens": MAX_TOKENS,
    "burp_proxy": BURP_PROXY,
    "max_concurrent": MAX_CONCURRENT,
}


def load() -> dict:
    settings = dict(DEFAULTS)
    if SETTINGS_FILE.exists():
        try:
            saved = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            settings.update({k: v for k, v in saved.items() if k in DEFAULTS})
        except (json.JSONDecodeError, OSError):
            pass
    return settings


def save(settings: dict):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    to_save = {k: v for k, v in settings.items() if k in DEFAULTS}
    SETTINGS_FILE.write_text(json.dumps(to_save, indent=2, ensure_ascii=False), encoding="utf-8")


def get_masked() -> dict:
    s = load()
    key = s.get("api_key", "")
    if len(key) > 8:
        s["api_key_masked"] = key[:4] + "****" + key[-4:]
    else:
        s["api_key_masked"] = "****" if key else ""
    s.pop("api_key", None)
    return s
