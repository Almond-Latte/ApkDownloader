"""
Configuration management for ApkDownloader.
Loads settings from config file and environment variables.
"""

import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
import json

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
            # Config file is required - no hardcoded defaults
            print(f"Error: Configuration file not found: {config_path}")
            print("Please create a config.yaml file based on config.yaml.example")
            sys.exit(1)

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
                        print(f"Error: PyYAML not installed and {config_path} is not valid JSON.")
                        print("Please install PyYAML: pip install pyyaml")
                        sys.exit(1)
    except Exception as e:
        print(f"Error: Could not load config file {config_path}: {e}")
        sys.exit(1)


config = load_config_file()

# Validate that required config sections exist
required_sections = ["api", "directories", "collection", "filtering", "performance", "behavior"]
missing_sections = [s for s in required_sections if s not in config]
if missing_sections:
    print(f"Error: Missing required sections in config file: {', '.join(missing_sections)}")
    sys.exit(1)

_BASE_DIR: Path = Path(__file__).parent.parent.resolve()

# API Configuration
API_KEY: str = os.getenv("API_KEY", "")
URL: str = config["api"]["download_url"]

# Directory Paths
LOG_DIR: Path = Path(os.getenv("LOG_DIR", config["directories"]["logs"]))
DOWNLOAD_DIR: Path = Path(os.getenv("DOWNLOAD_DIR", config["directories"]["downloads"]))
CACHE_DIR: Path = Path(os.getenv("CACHE_DIR", config["directories"]["cache"]))

# Fixed Paths
LOGGER_CONFIG_PATH: Path = _BASE_DIR / "logger_config.json"
ENV_PATH: Path = _BASE_DIR / ".env"

# Sample Collection Settings
MALWARE_THRESHOLD: int = config["collection"]["min_detections_for_malware"]
N_MALWARE: int = config["collection"]["malware_samples"]
N_CLEANWARE: int = config["collection"]["benign_samples"]
GOOGLE_PLAY_ONLY: bool = config["collection"]["google_play_only"]

# Filtering Period
DATE_START_STR: str = config["filtering"]["date_from"]
DATE_END_STR: str = config["filtering"]["date_until"]

try:
    DATE_START: datetime = datetime.strptime(DATE_START_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
except ValueError as e:
    print(f"Error: Invalid start date format in config: {DATE_START_STR}")
    sys.exit(1)

try:
    DATE_END: datetime = datetime.strptime(DATE_END_STR, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
except ValueError as e:
    print(f"Error: Invalid end date format in config: {DATE_END_STR}")
    sys.exit(1)

# Performance Settings
CONCURRENT_DOWNLOADS: int = config["performance"]["parallel_downloads"]

# Behavior Options
# Note: Internal code uses VERIFY_EXISTING_FILE_HASH (true means verify),
# but config uses skip_hash_verification (true means skip) for clarity
VERIFY_EXISTING_FILE_HASH: bool = not config["behavior"]["skip_hash_verification"]
RANDOM_SEED: Optional[int] = config["behavior"]["random_seed"]

# Data Source
apk_list_str = os.getenv("APK_LIST_PATH", config.get("data_source", {}).get("input_file"))
if apk_list_str:
    APK_LIST_PATH: Optional[Path] = Path(apk_list_str)
else:
    APK_LIST_PATH: Optional[Path] = None

if not API_KEY:
    print("Warning: API_KEY not set in environment variables. Please set it in your .env file.")