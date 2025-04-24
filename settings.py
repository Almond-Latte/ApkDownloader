# settings.py
# Stores default configuration values.

import sys
from datetime import datetime, timezone # Import timezone
from pathlib import Path
from zoneinfo import ZoneInfo

# --- Default Paths ---
_SCRIPT_DIR: Path = Path(__file__).parent.resolve()
DEFAULT_LOG_DIR: Path = _SCRIPT_DIR / "log"
DEFAULT_DOWNLOAD_DIR: Path = _SCRIPT_DIR / "Downloads"
DEFAULT_CACHE_DIR: Path = _SCRIPT_DIR / "_cache"
DEFAULT_LOGGER_CONFIG_PATH: Path = _SCRIPT_DIR / "logger_config.json"
DEFAULT_ENV_PATH: Path = _SCRIPT_DIR / ".env"

# --- Default API and Data Settings ---
DEFAULT_URL: str = "https://androzoo.uni.lu/api/download"
DEFAULT_MALWARE_THRESHOLD: int = 5
DEFAULT_N_MALWARE: int = 10
DEFAULT_N_CLEANWARE: int = 10

# --- Default Date Range Settings (as strings) ---
# Start date (e.g., beginning of last year)
DEFAULT_DATE_START_STR: str = "2023-01-01 00:00:00"
# End date (e.g., today's date at the beginning of the day, UTC)
# Use timezone.utc for consistency
DEFAULT_DATE_END_STR: str = datetime.now(timezone.utc).strftime("%Y-%m-%d 00:00:00")

# --- Default Performance Settings ---
DEFAULT_CONCURRENT_DOWNLOADS: int = 5

# No active code here, just constants/defaults.