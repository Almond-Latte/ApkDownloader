# settings.py
# Stores default configuration values.

import sys
from datetime import datetime, timezone # Import timezone
from pathlib import Path
from zoneinfo import ZoneInfo
import ast
import os
from typing import Any
from dotenv import load_dotenv

def load_env(key: str, default_value: Any = None) -> Any:
    """
    Load environment variable and convert to appropriate type using ast.literal_eval.
    Falls back to default_value if key is not set.
    """
    try:
        val = os.getenv(key)
        if val is None:
            if default_value is not None:
                return default_value
            raise ValueError(f"Environment variable {key} is not set and no default provided.")
        
        # Try to evaluate as Python literal (int, str, bool, etc.)
        try:
            return ast.literal_eval(val)
        except (ValueError, SyntaxError):
            # If literal_eval fails, return as string
            return val
    except Exception as e:
        if default_value is not None:
            return default_value
        raise

# Load environment variables
load_dotenv(override=True)

# --- API Key ---
API_KEY: str = load_env("API_KEY", "")

# --- Default Paths ---
_BASE_DIR: Path = Path(load_env("BASE_DIR", str(Path(__file__).parent.parent.resolve())))
_SCRIPT_DIR: Path = Path(__file__).parent.resolve()
LOG_DIR: Path = Path(load_env("LOG_DIR", _BASE_DIR / "logs"))
DOWNLOAD_DIR: Path = Path(load_env("DOWNLOAD_DIR", _BASE_DIR / "downloads"))
CACHE_DIR: Path = Path(load_env("CACHE_DIR", _BASE_DIR / "_cache"))
LOGGER_CONFIG_PATH: Path = Path(load_env("LOGGER_CONFIG_PATH", _BASE_DIR / "logger_config.json"))
ENV_PATH: Path = Path(load_env("ENV_PATH", _BASE_DIR / ".env"))
APK_LIST_PATH: Path = Path(load_env("APK_LIST_PATH", None))

# --- Default API and Data Settings ---
URL: str = load_env("URL", "https://androzoo.uni.lu/api/download")
MALWARE_THRESHOLD: int = load_env("MALWARE_THRESHOLD", 5)
N_MALWARE: int = load_env("N_MALWARE", 10)
N_CLEANWARE: int = load_env("N_CLEANWARE", 10)

# --- Default Date Range Settings (as strings) ---
# Start date (e.g., beginning of last year)
DATE_START_STR: str = load_env("DATE_START_STR", "2023-01-01 00:00:00")
DATE_START: datetime = datetime.strptime(DATE_START_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
# End date (e.g., today's date at the beginning of the day, UTC)
# Use timezone.utc for consistency
DATE_END_STR: str = load_env("DATE_END_STR", datetime.now(timezone.utc).strftime("%Y-%m-%d 00:00:00"))
DATE_END: datetime = datetime.strptime(DATE_END_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

# --- Default Performance Settings ---
CONCURRENT_DOWNLOADS: int = load_env("CONCURRENT_DOWNLOADS", 12)

# No active code here, just constants/defaults.