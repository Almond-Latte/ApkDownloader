"""
Configuration management for ApkDownloader.
Loads settings from config file, environment variables, and defaults.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv

load_dotenv(override=True)


def load_config_file(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from YAML or JSON file."""
    if config_path is None:
        env_config_path = os.getenv("CONFIG_FILE")
        if env_config_path:
            config_path = Path(env_config_path)
        else:
            config_path = Path(__file__).parent.parent / "config.yaml"

    if not config_path.exists():
        json_path = config_path.with_suffix('.json')
        if json_path.exists():
            config_path = json_path
        else:
            return {}

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            if config_path.suffix == '.json':
                return json.load(f)
            else:
                try:
                    import yaml
                    return yaml.safe_load(f) or {}
                except ImportError:
                    f.seek(0)
                    try:
                        return json.load(f)
                    except json.JSONDecodeError:
                        print(f"Warning: PyYAML not installed and {config_path} is not valid JSON. Using defaults.")
                        return {}
    except Exception as e:
        print(f"Warning: Could not load config file {config_path}: {e}")
        return {}


config = load_config_file()

_BASE_DIR: Path = Path(__file__).parent.parent.resolve()

# API Configuration
API_KEY: str = os.getenv("API_KEY", "")
URL: str = config.get("api", {}).get("url", "https://androzoo.uni.lu/api/download")

# Directory Paths
LOG_DIR: Path = Path(os.getenv("LOG_DIR",
                               config.get("directories", {}).get("logs",
                                                                str(_BASE_DIR / "logs"))))
DOWNLOAD_DIR: Path = Path(os.getenv("DOWNLOAD_DIR",
                                    config.get("directories", {}).get("download",
                                                                     str(_BASE_DIR / "downloads"))))
CACHE_DIR: Path = Path(os.getenv("CACHE_DIR",
                                 config.get("directories", {}).get("cache",
                                                                  str(_BASE_DIR / "_cache"))))

# Fixed Paths
LOGGER_CONFIG_PATH: Path = _BASE_DIR / "logger_config.json"
ENV_PATH: Path = _BASE_DIR / ".env"

# Sample Selection Defaults
MALWARE_THRESHOLD: int = config.get("samples", {}).get("malware_threshold", 4)
N_MALWARE: int = config.get("samples", {}).get("default_malware_count", 500)
N_CLEANWARE: int = config.get("samples", {}).get("default_cleanware_count", 1000)

# Date Range Defaults
date_config = config.get("date_range", {})
DATE_START_STR: str = date_config.get("start", "2022-04-01 00:00:00")
DATE_END_STR: str = date_config.get("end", "2024-04-01 00:00:00")

try:
    DATE_START: datetime = datetime.strptime(DATE_START_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
except ValueError:
    DATE_START: datetime = datetime(2022, 4, 1, 0, 0, 0, tzinfo=timezone.utc)

try:
    DATE_END: datetime = datetime.strptime(DATE_END_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
except ValueError:
    DATE_END: datetime = datetime(2024, 4, 1, 0, 0, 0, tzinfo=timezone.utc)

# Performance Settings
CONCURRENT_DOWNLOADS: int = config.get("performance", {}).get("concurrent_downloads", 12)

# Options
options = config.get("options", {})
VERIFY_EXISTING_FILE_HASH: bool = options.get("verify_existing_file_hash", False)
RANDOM_SEED: Optional[int] = options.get("random_seed", None)

# APK List Path
APK_LIST_PATH: Optional[Path] = None
apk_list_str = os.getenv("APK_LIST_PATH")
if apk_list_str:
    APK_LIST_PATH = Path(apk_list_str)

if not API_KEY:
    print("Warning: API_KEY not set in environment variables. Please set it in your .env file.")