import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from dotenv import load_dotenv
from rich.console import Console

console = Console()


def load_env(key: str) -> str:
    """"""
    val = os.getenv(key)
    if val is None:
        console.log(
            f"Error: {key} is not set as an environment variable. \
            Consider adding {key} to the .env file.",
        )
        sys.exit()
    return val


dirname: Path = Path(__file__).parent
log_dir_path: Path = Path.joinpath(dirname, Path("log"))
log_dir_path.mkdir(exist_ok=True)

LOG_FILE_PATH: Path = Path.joinpath(
    log_dir_path, Path(f"{datetime.now(ZoneInfo("Asia/Tokyo")):%Y%m%d_%H%M%S}.log"),
)
LOGGER_CONFIG_PATH: Path = Path.joinpath(dirname, Path("logger_config.json"))

# Read .env File
dotenv_path: Path = Path.joinpath(dirname, ".env")
load_dotenv(dotenv_path, override=True)
URL: str = load_env("URL")
API_KEY: str = load_env("API_KEY")
APK_LIST_PATH: Path = Path(load_env("APK_LIST"))
MALWARE_THRESHOLD: int = int(load_env("MALWARE_THRESHOLD"))
N_MALWARE: int = int(load_env("N_MALWARE"))
N_CLEANWARE: int = int(load_env("N_CLEANWARE"))
DATE_AFTER: datetime = datetime.strptime(load_env("DATE_AFTER"), "%Y-%m-%d %H:%M:%S").replace(tzinfo=ZoneInfo("Europe/Paris"))
CONCURRENT_DOWNLOADS: int = int(load_env("CONCURRENT_DOWNLOADS"))
