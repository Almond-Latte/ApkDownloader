import csv
import json
import logging
import os
import random # Import random module
import signal
import sys
import time # time モジュールをインポート
# from collections.abc import Generator # Generator は不要に
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone # Import timezone
from enum import IntEnum, StrEnum, auto
from logging import Logger, config, getLogger
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple # typing を修正
from zoneinfo import ZoneInfo

import requests
import typer
from dotenv import load_dotenv
from rich import box, pretty, print # print は rich.print を使う
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    # TaskProgressColumn, # Polars 化で不要に
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.table import Table
from rich.columns import Columns

# Polars をインポート
try:
    import polars as pl
    # Polars の例外をインポート (DeprecationWarning 回避)
    from polars.exceptions import PolarsError
    POLARS_AVAILABLE = True
except ImportError:
    # polars がインストールされていない場合のフォールバック (エラーメッセージ用)
    POLARS_AVAILABLE = False
    PolarsError = ImportError # Fallback exception type
    # スクリプト開始前に警告を出す方が親切かもしれない
    # print("[bold red]Warning: 'polars' library not found. Feather file processing will fail.[/bold red]")
    # print("[bold yellow]Please install it using: pip install polars pyarrow[/bold yellow]")


import settings

# Type alias for JSON data (Polars/CSV 共通で使えるように)
type Json = Dict[str, Any] # 型エイリアスを修正

# Create a Typer app instance
app = typer.Typer(
    help="APK Downloader: Downloads APKs using Feather input, auto-converts from CSV if needed.", # ヘルプ更新
    add_completion=False,
)

# --- Enums for Status and Todos ---
class StatusCode(IntEnum):
    """Enum representing the status of different initialization/processing steps."""
    WAITING = auto()
    PROCESSING = auto()
    SUCCESS = auto()
    STOPPED = auto()
    ERROR = auto()

    @classmethod
    def get_names(cls) -> list[str]:
        """Get a list of status names."""
        return [i.name for i in cls]

    @classmethod
    def get_values(cls) -> list[int]:
        """Get a list of status integer values."""
        return [i.value for i in cls]


class TodoCode(StrEnum):
    """Enum representing the different tasks performed during initialization."""
    SP = "Setup Progress Display"
    RC = "Read Configuration"
    SE = "Setup Signal Handler"
    SL = "Setup Logger"
    MDD = "Make Download Directory"
    CHL = "Collect Hash values"
    DA = "Download APKs"

    @classmethod
    def get_names(cls) -> list[str]:
        """Get a list of task names."""
        return [i.name for i in cls]

    @classmethod
    def get_values(cls) -> list[str]:
        """Get a list of task string values."""
        return [i.value for i in cls]

# --- Helper Function for Loading Env Vars ---
def load_env_var(key: str, default: Optional[str] = None) -> Optional[str]:
    """Loads an environment variable. Returns default if not found."""
    return os.getenv(key, default)

# --- ApkDownloader Class ---
class ApkDownloader:
    """Handles the process of collecting APK hashes and downloading APK files."""

    def __init__(
        self,
        console: Console,
        url: str,
        api_key: str,
        apk_list_path: Path, # Feather ファイルパス想定
        malware_threshold: int,
        n_malware: int,
        n_cleanware: int,
        date_start: datetime,
        date_end: datetime,
        concurrent_downloads: int,
        log_file_path: Path,
        logger_config_path: Path,
        download_dir: Path,
        cache_dir: Path,
    ) -> None:
        """Initializes the ApkDownloader with necessary configurations."""
        self.console: Console = console
        self.init_success: bool = True
        # Initialize attributes to None or default before try blocks
        self.logger: Optional[Logger] = None
        self.live: Optional[Live] = None
        self.event: Optional[Event] = None
        self.progress_status: dict[str, StatusCode] = { todo: StatusCode.WAITING for todo in TodoCode.get_values() }
        self.overall_table = Table(box=box.SIMPLE)
        self.download_progress: Optional[Progress] = None # Initialize as None

        # --- 1. Setup Progress Display ---
        try:
            self.download_progress = Progress(
                TextColumn("[progress.description]{task.description}", justify="right"),
                SpinnerColumn(),
                TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
                BarColumn(),
                "[progress.percentage]{task.percentage:>3.1f}%",
                TextColumn("[green]{task.completed}/{task.total}", justify="right"),
                TransferSpeedColumn(),
                TimeElapsedColumn(),
                console=self.console
            )
            self.live = Live(
                self.generate_table(),
                auto_refresh=True,
                transient=False,
                console=self.console,
                vertical_overflow="crop"
            )
            self.live.start()
            self.progress_status[TodoCode.SP] = StatusCode.SUCCESS
        except Exception as e:
            self.console.print(f"[bold red]Error initializing Rich display:[/bold red] {e}")
            self.progress_status[TodoCode.SP] = StatusCode.ERROR
            self.init_success = False
        self._refresh_live_display() # 初期表示 (live が None でもエラーにならないように修正済み)
        if not self.init_success: return # Display setup failed, cannot proceed

        # --- 2. Store Configuration ---
        self.progress_status[TodoCode.RC] = StatusCode.PROCESSING
        self._refresh_live_display()
        self.URL = url
        self.API_KEY = api_key
        self.APK_LIST_PATH = apk_list_path # .feather ファイルパス
        self.MALWARE_THRESHOLD = malware_threshold
        self.N_MALWARE = n_malware
        self.N_CLEANWARE = n_cleanware
        self.DATE_START = date_start
        self.DATE_END = date_end
        self.CONCURRENT_DOWNLOADS = concurrent_downloads
        self.LOG_FILE_PATH = log_file_path
        self.LOGGER_CONFIG_PATH = logger_config_path
        self.DOWNLOAD_DIR = download_dir
        self.CACHE_DIR = cache_dir

        if self.DATE_START > self.DATE_END:
            self.console.log(f"[bold red]Error:[/bold red] Start date ({self.DATE_START.date()}) cannot be after end date ({self.DATE_END.date()}).")
            self.progress_status[TodoCode.RC] = StatusCode.ERROR
            self.init_success = False
        else:
            self.progress_status[TodoCode.RC] = StatusCode.SUCCESS
        self._refresh_live_display()
        if not self.init_success: return

        # --- 3. Setup Signal Handler ---
        self.progress_status[TodoCode.SE] = StatusCode.PROCESSING
        self._refresh_live_display()
        try:
            self.event = Event()
            signal.signal(signal.SIGINT, self.handle_sigint)
            self.progress_status[TodoCode.SE] = StatusCode.SUCCESS
        except Exception as e:
            self.console.log(f"[bold red]Error setting up signal handler:[/bold red] {e}")
            self.progress_status[TodoCode.SE] = StatusCode.ERROR
            self.init_success = False
        self._refresh_live_display()
        if not self.init_success: return

        # --- 4. Setup Logger ---
        self.progress_status[TodoCode.SL] = StatusCode.PROCESSING
        self._refresh_live_display()
        self.logger = self._setup_logger() # self.logger に代入
        # _setup_logger handles setting status to ERROR internally
        if self.progress_status[TodoCode.SL] != StatusCode.ERROR:
            self.progress_status[TodoCode.SL] = StatusCode.SUCCESS
            self.logger.info("Logger setup successful.")
            self.logger.info(f"Log file: {self.LOG_FILE_PATH}")
        else:
             self.init_success = False # ロガー設定失敗
        self._refresh_live_display()
        if not self.init_success: return

        # --- 5. gen_cache_filenames ---
        self.gen_cache_filenames()

        # --- 6. Make Download Directory ---
        self.progress_status[TodoCode.MDD] = StatusCode.PROCESSING
        self._refresh_live_display()
        if self._make_download_dirs():
            self.progress_status[TodoCode.MDD] = StatusCode.SUCCESS
        else:
            self.progress_status[TodoCode.MDD] = StatusCode.ERROR
            self.init_success = False
        self._refresh_live_display()
        if not self.init_success: return

        # --- 7 & 8 (Deferred) ---
        self.progress_status[TodoCode.CHL] = StatusCode.WAITING
        self.progress_status[TodoCode.DA] = StatusCode.WAITING
        self._refresh_live_display()

        self.logger.info("ApkDownloader initialization sequence complete.")
        self.logger.info(f"Target date range: {self.DATE_START.date()} to {self.DATE_END.date()}")
        self.logger.info(f"Target samples: {self.N_CLEANWARE} cleanware, {self.N_MALWARE} malware")


    def _setup_logger(self) -> Logger:
        """Configures and returns a logger instance."""
        try:
            # Ensure log directory exists before trying to open config
            log_dir = self.LOG_FILE_PATH.parent
            log_dir.mkdir(parents=True, exist_ok=True)

            with self.LOGGER_CONFIG_PATH.open(mode="r") as f:
                logger_conf = json.load(f)
                # Ensure handlers exist before modifying
                if "handlers" in logger_conf and "fileHandler" in logger_conf["handlers"]:
                    logger_conf["handlers"]["fileHandler"]["filename"] = str(self.LOG_FILE_PATH)
                else:
                    self.console.log("[bold yellow]Warning:[/bold yellow] 'handlers.fileHandler' not found in logger config. File logging might be skipped.")
                config.dictConfig(logger_conf)
            # Return the named logger
            logger = getLogger(__name__)
            logger.info("Logger configured successfully from file.")
            return logger
        except FileNotFoundError:
            self.progress_status[TodoCode.SL] = StatusCode.ERROR
            self.console.log(f"[bold red]Error:[/bold red] Logger config file not found: {self.LOGGER_CONFIG_PATH}")
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = getLogger(__name__)
            logger.warning("Using basic logging configuration due to missing config file.")
            return logger
        except (json.JSONDecodeError, KeyError, Exception) as e:
            self.progress_status[TodoCode.SL] = StatusCode.ERROR
            self.console.log(f"[bold red]Error setting up logger from config:[/bold red] {e}")
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = getLogger(__name__)
            logger.error(f"Using basic logging configuration due to error: {e}", exc_info=True)
            return logger


    def _refresh_live_display(self, download_panel: bool = False) -> None:
        """Updates the live display table if Live is active."""
        live = getattr(self, 'live', None)
        if live and live._started:
            try:
                 live.update(self.generate_table(download_panel=download_panel), refresh=True)
            except Exception as e:
                 logger = getattr(self, 'logger', None) or getLogger(__name__)
                 logger.error(f"Failed to update live display: {e}", exc_info=False)


    def generate_table(self, *, download_panel: bool = False) -> Align:
        """Generates the Rich Table layout for the progress display."""
        overall_table = Table(box=box.SIMPLE)
        overall_table.add_column("", style="dim", width=3, justify="center")
        overall_table.add_column("Task", style="cyan", no_wrap=True)
        overall_table.add_column("Status", justify="left")

        status_display_map = {
            StatusCode.WAITING:    {"icon": "[grey50]●", "color": "grey50", "text": "WAITING"},
            StatusCode.PROCESSING: {"icon": None,        "color": "blue",   "text": "PROCESSING"}, # Spinnerを使う
            StatusCode.SUCCESS:    {"icon": "[green]✔",   "color": "green",  "text": "SUCCESS"},
            StatusCode.STOPPED:    {"icon": "[yellow]✋",  "color": "yellow", "text": "STOPPED"},
            StatusCode.ERROR:      {"icon": "[red]✘",     "color": "red",    "text": "ERROR"},
        }

        progressing_spinner = Spinner("dots", style="blue", speed=1.0)

        # Ensure progress_status exists
        progress_status = getattr(self, 'progress_status', {})
        for todo_value in TodoCode.get_values(): # Iterate through all possible Todos
            status_code = progress_status.get(todo_value, StatusCode.WAITING) # Default to WAITING
            display_info = status_display_map.get(status_code, {"icon": "?", "color": "grey50", "text": "UNKNOWN"})

            icon_reanderable: Any

            if status_code == StatusCode.PROCESSING:
                icon_reanderable = progressing_spinner
            else:
                icon_reanderable = display_info["icon"]

            status_text = f"[{display_info['color']}] {display_info['text']} [/]" if display_info["text"] else ""

            overall_table.add_row(
                icon_reanderable,
                f"{todo_value}",
                status_text,
            )


        overall_panel = Panel(
            overall_table,
            title="Overall Progress",
            border_style="green",
            padding=(1, 1) # パディングは適宜調整
        )

        grid_table = Table.grid(expand=True)
        grid_table.add_column()
        if download_panel:
            grid_table.add_column()

        # --- 表示する要素（Renderable）のリストを作成 ---
        renderables = [overall_panel] # まず Overall パネルを追加

        if download_panel:
            download_progress = getattr(self, 'download_progress', None)
            if download_progress:
                # Download パネルを追加
                download_panel_obj = Panel(
                    download_progress,
                    title="Download Progress",
                    border_style="blue",
                    padding=(1, 1) # パディングは適宜調整
                )
                renderables.append(download_panel_obj)
            else:
                renderables.append("[bold red]Download progress not available.[/bold red]")

        # --- テーブルに行を追加 ---
        if renderables:
            grid_table.add_row(*renderables)
        return Align.center(grid_table)

    def handle_sigint(self, signum: int, frame: Optional[FrameType]) -> None:
        """Handles the SIGINT signal (Ctrl+C) by setting the termination event."""
        signame = signal.Signals(signum).name
        msg = f"Signal handler called with signal {signame} ({signum})"
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        if logger: logger.warning(msg)
        if logger: logger.warning("Stopping gracefully...")
        if event: event.set()

    def _make_download_dirs(self) -> bool:
        """Creates the necessary download directories (cleanware, malware)."""
        logger = getattr(self, 'logger', None)
        try:
            (self.DOWNLOAD_DIR / "cleanware").mkdir(parents=True, exist_ok=True)
            (self.DOWNLOAD_DIR / "malware").mkdir(parents=True, exist_ok=True)
            if logger: logger.info(f"Ensured download directories exist under: {self.DOWNLOAD_DIR}")
            return True
        except OSError as e:
            if logger: logger.error(f"Failed to create download directories: {e}")
            self.console.log(f"[bold red]Error creating download directories:[/bold red] {e}")
            return False

    @staticmethod
    def has_vt_detection(json_data: Json) -> bool:
        """Checks if 'vt_detection' key exists and is not empty."""
        # This check is primarily used by the old CSV logic, less critical for Polars filtering
        vt_detection_value = json_data.get("vt_detection")
        return vt_detection_value is not None and vt_detection_value != ""

    def is_malware(self, json_data: Json) -> bool:
        """Determines if an APK record represents malware based on the threshold."""
        # This check is primarily used by the old CSV logic
        logger = getattr(self, 'logger', None)
        try:
            # Attempt conversion, handle potential None or non-integer strings gracefully
            vt_detection_str = json_data.get("vt_detection")
            vt_detection = -1 # Default if conversion fails or value is None/empty
            if vt_detection_str is not None and vt_detection_str != '':
                 vt_detection = int(vt_detection_str)
            return vt_detection >= self.MALWARE_THRESHOLD
        except (ValueError, TypeError):
             sha256 = json_data.get('sha256', 'Unknown')
             vt_val = json_data.get("vt_detection")
             if logger: logger.warning(f"Invalid vt_detection '{vt_val}' for {sha256}. Treating as cleanware.")
             return False

    def is_within_date_range(self, json_data: Json) -> bool:
        """Checks if the APK's scan date is within the configured date range."""
        # This check is primarily used by the old CSV logic
        logger = getattr(self, 'logger', None)
        scan_date_str = json_data.get("vt_scan_date")
        if not scan_date_str:
            if logger: logger.warning(f"Missing 'vt_scan_date' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
            return False
        try:
            vt_scan_date = datetime.strptime(scan_date_str, "%Y-%m-%d %H:%M:%S")
            vt_scan_date = vt_scan_date.replace(tzinfo=timezone.utc)
            return self.DATE_START <= vt_scan_date <= self.DATE_END
        except (ValueError, TypeError):
            if logger: logger.warning(f"Invalid date format '{scan_date_str}' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
            return False

    def gen_cache_filenames(self) -> None:
        """Generates filenames for cache files."""
        logger = getattr(self, 'logger', None)
        info_chain: list[str] = [
            str(self.MALWARE_THRESHOLD), str(self.N_CLEANWARE), str(self.N_MALWARE),
            f"{self.DATE_START:%Y%m%d}", f"{self.DATE_END:%Y%m%d}",
        ]
        cache_sub_dir_name: str = "_".join(info_chain)
        cache_sub_dir: Path = self.CACHE_DIR / cache_sub_dir_name
        self.cleanware_cache_file: Path = cache_sub_dir / "cleanware_samples.jsonl"
        self.malware_cache_file: Path = cache_sub_dir / "malware_samples.jsonl"
        if logger: logger.info(f"Cache directory set to: {cache_sub_dir}")

    def make_cache_file(self, cleanware_samples: List[Json], malware_samples: List[Json]) -> bool:
        """Saves the selected samples to cache files."""
        logger = getattr(self, 'logger', None)
        if not cleanware_samples and not malware_samples:
             if logger: logger.info("No samples selected to cache.")
             return True
        # Ensure cache files are defined
        if not hasattr(self, 'cleanware_cache_file') or not hasattr(self, 'malware_cache_file'):
             if logger: logger.error("Cache filenames not generated. Cannot make cache file.")
             return False
        cache_dir: Path = self.cleanware_cache_file.parent
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            if logger: logger.error(f"Failed to create cache directory {cache_dir}: {e}")
            self.console.log(f"[bold red]Error:[/bold red] Could not create cache directory: {e}")
            return False
        
        def make_json_serializable(data: Json) -> Json:
            """辞書内の datetime オブジェクトを ISO 文字列に変換します。"""
            serializable_data = {}
            for key, value in data.items():
                if isinstance(value, datetime):
                    # datetime を ISO 8601 文字列形式に変換
                    serializable_data[key] = value.isoformat()
                # 必要であれば、他のシリアライズ不可能な型の処理を追加
                # elif isinstance(value, SomeOtherType):
                #     serializable_data[key] = convert_other_type(value)
                else:
                    serializable_data[key] = value
            return serializable_data
        
        try:
            with self.cleanware_cache_file.open(mode="w", encoding='utf-8') as f:
                for json_data in cleanware_samples:
                    # ダンプする前にデータが JSON シリアライズ可能であることを確認
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if logger: logger.info(f"{len(cleanware_samples)} 個の cleanware サンプルをキャッシュに正常に書き込みました: {self.cleanware_cache_file}")
        except (IOError, TypeError) as e: # TypeError もここに追加
            if logger: logger.exception(f"cleanware キャッシュの書き込みに失敗しました: {self.cleanware_cache_file}")
            self.console.log(f"[bold red]cleanware キャッシュ書き込みエラー:[/bold red] {e}")
            return False

        try:
            with self.malware_cache_file.open(mode="w", encoding='utf-8') as f:
                for json_data in malware_samples:
                    # ダンプする前にデータが JSON シリアライズ可能であることを確認
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if logger: logger.info(f"{len(malware_samples)} 個の malware サンプルをキャッシュに正常に書き込みました: {self.malware_cache_file}")
        except (IOError, TypeError) as e: # TypeError もここに追加
            if logger: logger.exception(f"malware キャッシュの書き込みに失敗しました: {self.malware_cache_file}")
            self.console.log(f"[bold red]malware キャッシュ書き込みエラー:[/bold red] {e}")
            return False

        return True

    def read_cache_file(self) -> Optional[Tuple[List[Json], List[Json]]]:
        """Reads selected samples from existing cache files."""
        logger = getattr(self, 'logger', None)
        # Ensure cache files are defined
        if not hasattr(self, 'cleanware_cache_file') or not hasattr(self, 'malware_cache_file'):
            if logger: logger.error("Cache filenames not generated. Cannot read cache file.")
            return None
        if not self.cleanware_cache_file.exists() or not self.malware_cache_file.exists():
            if logger: logger.info("Sample cache files not found.")
            return None
        if logger: logger.info(f"Attempting to read samples from cache files in {self.cleanware_cache_file.parent}")
        cleanware_list: List[Json] = []
        malware_list: List[Json] = []
        try:
            with self.cleanware_cache_file.open(mode="r", encoding='utf-8') as f:
                cleanware_list = [json.loads(line) for line in f if line.strip()]
            if logger: logger.info(f"Successfully read {len(cleanware_list)} cleanware samples from cache: {self.cleanware_cache_file}")
            with self.malware_cache_file.open(mode="r", encoding='utf-8') as f:
                malware_list = [json.loads(line) for line in f if line.strip()]
            if logger: logger.info(f"Successfully read {len(malware_list)} malware samples from cache: {self.malware_cache_file}")
            # Trim cache if needed
            if len(cleanware_list) > self.N_CLEANWARE or len(malware_list) > self.N_MALWARE:
                 if logger: logger.warning("Cache contains more samples than currently requested. Using subset.")
                 cleanware_list = cleanware_list[:self.N_CLEANWARE]
                 malware_list = malware_list[:self.N_MALWARE]
            return cleanware_list, malware_list
        except (IOError, json.JSONDecodeError) as e:
            if logger: logger.error(f"Error reading cache files: {e}. Re-collecting hashes.")
            self.console.log(f"[bold red]Error reading cache files:[/bold red] {e}. Cache will be ignored.")
            return None
        except Exception as e:
            if logger: logger.exception(f"Unexpected error reading cache files: {e}")
            self.console.log(f"[bold red]Unexpected error reading cache:[/bold red] {e}")
            return None

    def collect_apk_hashes(self, force_recollect: bool = False) -> Tuple[list[Json], list[Json]]:
        """Loads data from Feather file, filters, and randomly samples APKs."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        self.progress_status[TodoCode.CHL] = StatusCode.PROCESSING
        self._refresh_live_display()
        if logger: logger.info("Starting APK hash collection from Feather file...")

        # --- Cache Check ---
        if not force_recollect:
            cached_result = self.read_cache_file()
            if cached_result is not None:
                cached_clean, cached_mal = cached_result
                if logger: logger.info(f"Loaded {len(cached_clean)} cleanware and {len(cached_mal)} malware samples from cache.")
                self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
                self._refresh_live_display()
                return cached_clean, cached_mal
            else:
                if logger: logger.info("Cache not found or invalid. Proceeding with collection from Feather.")
        else:
            if logger: logger.info("Forcing re-collection of hashes, ignoring cache.")

        # --- Polars Processing ---
        sampled_cleanware: list[Json] = []
        sampled_malware: list[Json] = []

        if not POLARS_AVAILABLE:
             self.console.log("[bold red]Error: 'polars' library is not installed. Cannot process Feather file.[/bold red]")
             self.progress_status[TodoCode.CHL] = StatusCode.ERROR
             return [], []

        try:
            feather_file_path = self.APK_LIST_PATH
            if not feather_file_path.exists():
                 raise FileNotFoundError(f"Feather file not found: {feather_file_path}")

            if logger: logger.info(f"Loading Feather file: {feather_file_path} using Polars...")
            lf = pl.scan_ipc(feather_file_path)

            base_filtered_lf = (
                lf
                .filter(pl.col("vt_detection").is_not_null())
                .with_columns(pl.col("vt_detection").cast(pl.Int64, strict=False).alias("vt_detection_int"))
                .filter(pl.col("vt_detection_int").is_not_null())
                .with_columns(pl.col("vt_scan_date").str.strptime(pl.Datetime, format="%Y-%m-%d %H:%M:%S", strict=False, exact=True).dt.replace_time_zone("UTC").alias("vt_scan_datetime")) # exact=True might help
                .filter(pl.col("vt_scan_datetime").is_not_null())
                .filter(pl.col("vt_scan_datetime").is_between(self.DATE_START, self.DATE_END, closed="both"))
                .filter(pl.col("markets").is_not_null())
            )

            malware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") >= self.MALWARE_THRESHOLD)
            )

            cleanware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") == 0)
                .filter(pl.col("markets").str.strip_chars() == "play.google.com") # Google Play Store のみを対象
            )


            if logger: logger.info("Applying filters and collecting candidates...")

            malware_df = malware_candidates_lf.collect()
            cleanware_df = cleanware_candidates_lf.collect()

            if logger: logger.info(f"Found {len(malware_df)} malware candidates and {len(cleanware_df)} cleanware candidates.")

            # Convert to list of dictionaries
            all_malware_candidates = malware_df.to_dicts()
            all_cleanware_candidates = cleanware_df.to_dicts()
            del malware_df, cleanware_df # Memory cleanup

            # --- Random Sampling ---
            if len(all_cleanware_candidates) > self.N_CLEANWARE:
                if logger: logger.info(f"Randomly sampling {self.N_CLEANWARE} cleanware from {len(all_cleanware_candidates)} candidates.")
                sampled_cleanware = random.sample(all_cleanware_candidates, self.N_CLEANWARE)
            else:
                if logger: logger.info(f"Using all {len(all_cleanware_candidates)} found cleanware candidates (requested {self.N_CLEANWARE}).")
                sampled_cleanware = all_cleanware_candidates

            if len(all_malware_candidates) > self.N_MALWARE:
                if logger: logger.info(f"Randomly sampling {self.N_MALWARE} malware from {len(all_malware_candidates)} candidates.")
                sampled_malware = random.sample(all_malware_candidates, self.N_MALWARE)
            else:
                if logger: logger.info(f"Using all {len(all_malware_candidates)} found malware candidates (requested {self.N_MALWARE}).")
                sampled_malware = all_malware_candidates

            self.console.log(f"Selected {len(sampled_cleanware)} cleanware and {len(sampled_malware)} malware samples.")

            # --- Cache ---
            self.make_cache_file(sampled_cleanware, sampled_malware)

            self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
            self._refresh_live_display()
            return sampled_cleanware, sampled_malware

        except FileNotFoundError as e:
             if logger: logger.error(f"Input Feather file not found: {e}")
             self.console.log(f"[bold red]Error:[/bold red] {e}")
             self.progress_status[TodoCode.CHL] = StatusCode.ERROR
             return [], []
        except PolarsError as e: # Catch Polars specific errors
             if logger: logger.exception(f"Polars error processing Feather file: {e}")
             self.console.log(f"[bold red]Polars Error:[/bold red] {e}")
             self.progress_status[TodoCode.CHL] = StatusCode.ERROR
             return [], []
        except Exception as e: # Catch other errors during processing
             if logger: logger.exception(f"Unexpected error during Feather processing: {e}")
             self.console.log(f"[bold red]Unexpected error during Feather processing:[/bold red] {e}")
             self.progress_status[TodoCode.CHL] = StatusCode.ERROR
             return [], []


    # --- download_handler (より安全な logger/event/progress チェック追加) ---
    def download_handler( self, json_data: Json, task_id: TaskID, download_dir: Path) -> bool:
        """Downloads a single APK file."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        # Ensure sha256 is a string
        sha256 = str(json_data.get("sha256", ""))
        if not sha256:
            if logger: logger.error("Missing or empty 'sha256'. Cannot download.")
            return False
        if event and event.is_set(): return False

        filename = Path(f"{sha256}.apk")
        download_file_path = download_dir / filename

        if download_file_path.exists():
            if logger: logger.info(f"APK exists, skipping: {download_file_path}")
            if download_progress: download_progress.update(task_id, completed=1, total=1, visible=False)
            return True

        if logger: logger.info(f"Attempting download: {sha256} to {download_file_path}")
        params = {"apikey": self.API_KEY, "sha256": sha256}
        success = False
        response = None
        file_handle = None
        try:
            response = requests.get(self.URL, params=params, stream=True, timeout=(10, 60)) # Read timeout increased slightly
            response.raise_for_status()
            data_size = int(response.headers.get("content-length", 0))

            if download_progress:
                 download_progress.update(task_id, total=data_size, visible=True)
                 download_progress.start_task(task_id)

            chunk_size = 64 * 1024
            download_dir.mkdir(parents=True, exist_ok=True)
            file_handle = download_file_path.open(mode="wb")
            bytes_downloaded = 0
            for chunk in response.iter_content(chunk_size=chunk_size):
                if event and event.is_set():
                    if logger: logger.warning(f"Download interrupted by signal for {sha256}.")
                    success = False
                    break
                if chunk:
                    file_handle.write(chunk)
                    bytes_downloaded += len(chunk)
                    if download_progress: download_progress.update(task_id, advance=len(chunk))
            else: # no break
                 if not (event and event.is_set()):
                    # Check size if content-length was provided
                    if data_size > 0 and bytes_downloaded != data_size:
                        if logger: logger.warning(f"Incomplete download for {sha256}: Expected {data_size}, got {bytes_downloaded}.")
                        success = False
                    else:
                        success = True
                 else: success = False # Interrupted at the end

            if success and logger: logger.info(f"Success: {sha256}")

        except requests.exceptions.Timeout as e:
            if logger: logger.error(f"Timeout during download for {sha256}: {e}")
            self.console.log(f"[bold red]Timeout ({sha256[:12]}...):[/bold red] {e}")
            success = False
        except requests.exceptions.RequestException as e:
            if logger: logger.error(f"Download failed for {sha256}: {e}")
            self.console.log(f"[bold red]Download Error ({sha256[:12]}...):[/bold red] {e}")
            success = False
        except IOError as e:
             if logger: logger.error(f"File write error for {download_file_path}: {e}")
             self.console.log(f"[bold red]File Error ({sha256[:12]}...):[/bold red] {e}")
             success = False
        except Exception as e:
             if logger: logger.exception(f"Unexpected error downloading {sha256}: {e}")
             self.console.log(f"[bold red]Unexpected Error ({sha256[:12]}...):[/bold red] {e}")
             success = False
        finally:
            if download_progress: download_progress.update(task_id, visible=False)
            if file_handle is not None and not file_handle.closed: file_handle.close()
            if response is not None: response.close()
            if not success and download_file_path.exists():
                if logger: logger.warning(f"Download unsuccessful for {sha256}. Removing incomplete file.")
                try:
                    download_file_path.unlink()
                    if logger: logger.info(f"Removed incomplete file: {download_file_path}")
                except OSError as unlink_err:
                    if logger: logger.error(f"Failed to remove incomplete file {download_file_path}: {unlink_err}")
                    self.console.log(f"[bold red]Error removing file {filename.name}: {unlink_err}[/bold red]")
            elif not success and not download_file_path.exists():
                 if logger: logger.info(f"Download unsuccessful for {sha256}, no file created.")
        return success


    # --- download_apks (time.sleep 修正済み, logger/event/progress チェック追加) ---
    def download_apks(self, cleanware_list: List[Json], malware_list: List[Json]) -> None:
        """Downloads the selected cleanware and malware APKs concurrently."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        if not cleanware_list and not malware_list:
            if logger: logger.info("No samples selected for download.")
            self.console.log("No samples selected to download.")
            self.progress_status[TodoCode.DA] = StatusCode.SUCCESS
            self._refresh_live_display()
            return

        self.progress_status[TodoCode.DA] = StatusCode.PROCESSING
        self._refresh_live_display(download_panel=True)

        if logger: logger.info(f"Starting download of {len(cleanware_list)} cleanware and {len(malware_list)} malware samples.")
        total_files = len(cleanware_list) + len(malware_list)

        overall_apk_progress = None
        cleanware_progress = None
        malware_progress = None
        tasks_added = False
        if download_progress:
            try:
                overall_apk_progress = download_progress.add_task("[white]Overall Download:", filename="", total=total_files)
                cleanware_progress = download_progress.add_task("[green]Cleanware:", filename="", total=len(cleanware_list))
                malware_progress = download_progress.add_task("[green]Malware:", filename="", total=len(malware_list))
                tasks_added = True
            except Exception as e:
                 if logger: logger.error(f"Failed to add download progress tasks: {e}")
                 self.console.log(f"[bold red]Error adding progress tasks: {e}[/bold red]")

        cleanware_futures: List[Future[Any]] = []
        malware_futures: List[Future[Any]] = []
        future_to_sha: Dict[Future[Any], str] = {}

        with ThreadPoolExecutor(max_workers=self.CONCURRENT_DOWNLOADS, thread_name_prefix="Downloader") as executor:
            clean_dir = self.DOWNLOAD_DIR / "cleanware"
            mal_dir = self.DOWNLOAD_DIR / "malware"

            if tasks_added: # Only submit if progress tasks were added successfully
                for json_data in cleanware_list:
                    sha = str(json_data.get("sha256", "unknown")) # Ensure string
                    tid = download_progress.add_task("Queued", filename=f"{sha[:12]}...", visible=False, start=False)
                    future = executor.submit(self.download_handler, json_data, tid, clean_dir)
                    cleanware_futures.append(future)
                    future_to_sha[future] = sha
                for json_data in malware_list:
                    sha = str(json_data.get("sha256", "unknown")) # Ensure string
                    tid = download_progress.add_task("Queued", filename=f"{sha[:12]}...", visible=False, start=False)
                    future = executor.submit(self.download_handler, json_data, tid, mal_dir)
                    malware_futures.append(future)
                    future_to_sha[future] = sha
            else:
                 # Fallback if progress bar init failed? Or just log and exit?
                 self.console.log("[bold red]Cannot proceed with downloads as progress tasks failed.[/bold red]")
                 self.progress_status[TodoCode.DA] = StatusCode.ERROR
                 return # Exit download function if progress setup failed

            # --- Monitor Progress ---
            all_futures = cleanware_futures + malware_futures
            completed_futures = set()

            while len(completed_futures) < len(all_futures):
                if event and event.is_set():
                    if logger: logger.warning("Interrupt signal received during downloads. Stopping monitoring.")
                    break

                done_futures = {f for f in all_futures if f.done()}
                newly_completed = done_futures - completed_futures

                for future in newly_completed:
                    sha = future_to_sha.get(future, "unknown_sha")
                    try:
                        result = future.result()
                        # Log details only if logger exists
                        if logger:
                             if result is True: logger.debug(f"Future completed successfully for {sha}")
                             else: logger.warning(f"Future for {sha} completed but returned {result}.")
                    except Exception as e:
                        if logger: logger.error(f"Future for {sha} completed with an exception: {type(e).__name__}.")

                completed_futures.update(newly_completed)
                n_finished = len(completed_futures)

                # Update progress bars only if they exist
                if download_progress:
                     if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=n_finished)
                     if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=sum(f.done() for f in cleanware_futures))
                     if malware_progress is not None: download_progress.update(malware_progress, completed=sum(f.done() for f in malware_futures))

                # <<<--- time.sleep(0.1) を追加済み ---<<<

                self._refresh_live_display(download_panel=True) # Update live display
                time.sleep(0.5) # Yield control

            # --- Final Update After Loop ---
            if logger: logger.info("Download monitoring loop finished.")
            final_clean_done = sum(f.done() for f in cleanware_futures)
            final_mal_done = sum(f.done() for f in malware_futures)
            final_overall_done = final_clean_done + final_mal_done
            # Update progress bars only if they exist
            if download_progress:
                if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=final_overall_done)
                if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=final_clean_done)
                if malware_progress is not None: download_progress.update(malware_progress, completed=final_mal_done)
            if logger: logger.info(f"Final check: {final_overall_done}/{total_files} tasks marked as done.")

        # --- Set Final Status ---
        successful_downloads = 0
        failed_downloads = 0
        for future in all_futures:
            # Check future status robustly
            if future.done() and not future.cancelled():
                try:
                    if future.result() is True: successful_downloads += 1
                    else: failed_downloads += 1
                except Exception: failed_downloads += 1
            elif future.cancelled(): failed_downloads += 1
            else: # Should not happen if executor waits properly
                if logger: logger.error(f"Future for {future_to_sha.get(future, 'unknown')} did not complete after executor shutdown.")
                failed_downloads += 1

        if logger: logger.info(f"Final Download results: {successful_downloads} succeeded, {failed_downloads} failed/skipped/interrupted (out of {total_files} selected).")

        if event and event.is_set():
            self.progress_status[TodoCode.DA] = StatusCode.STOPPED
            # self.console.log(f"[bold yellow]Downloads stopped by user. {successful_downloads} completed, {failed_downloads} failed/stopped.[/bold yellow]")
        else:
            if failed_downloads > 0:
                self.progress_status[TodoCode.DA] = StatusCode.SUCCESS
                self.console.log(f"[bold yellow]Warning:[/bold yellow] {failed_downloads} downloads failed/skipped.")
                if logger: logger.warning(f"{failed_downloads} downloads failed or were skipped.")
            elif successful_downloads == total_files:
                self.progress_status[TodoCode.DA] = StatusCode.SUCCESS
                self.console.log("[bold green]All selected downloads completed successfully.[/bold green]")
            else: # Handle cases where successful_downloads < total_files without failures (e.g., interruption before start)
                if successful_downloads + failed_downloads != total_files:
                    # This might indicate interruption before all tasks were even processed by loop
                    if logger: logger.warning(f"Potential discrepancy in download counts ({successful_downloads}S/{failed_downloads}F/{total_files}T). May have been interrupted early.")
                    # Treat as error if not explicitly stopped
                    self.progress_status[TodoCode.DA] = StatusCode.ERROR if not (event and event.is_set()) else StatusCode.STOPPED
                else:
                    # All accounted for, but some failed - already handled above
                    self.progress_status[TodoCode.DA] = StatusCode.SUCCESS # Keep success status

        self._refresh_live_display(download_panel=True)


    # --- cleanup (logger/live チェック追加) ---
    def cleanup(self) -> None:
        """Stops the live display and logs the action if logger exists."""
        logger = getattr(self, 'logger', None)
        live = getattr(self, 'live', None)

        if live and live._started:
            try:
                live.stop()
                if logger: logger.info("Live display stopped.")
            except Exception as e:
                if logger: logger.error(f"Error stopping live display: {e}", exc_info=True)
        elif logger:
            logger.info("Cleanup called, Live display was not active or object didn't exist.")


    # --- CSVからFeatherを作成する静的メソッド ---
    @staticmethod
    def create_feather_from_csv(csv_path: Path, feather_path: Path, console: Console) -> bool:
        """Converts a CSV file to Feather (Arrow IPC) format using Polars."""
        # Check if Polars is available
        if not POLARS_AVAILABLE:
            console.print("[bold red]Error: 'polars' library is not installed. Cannot convert CSV to Feather.[/bold red]")
            return False

        print_func = console.print # Use self.console for printing status
        print_func(f"Attempting to convert '{csv_path}' to '{feather_path}' using Polars...")
        try:
            feather_path.parent.mkdir(parents=True, exist_ok=True)
            # Consider adding parameters like `ignore_errors=True` or specific dtypes if conversion fails
            pl.read_csv(csv_path, low_memory=True).write_ipc(feather_path)
            print_func(f"[bold green]Successfully converted to '{feather_path}'[/bold green]")
            try:
                 print_func(f"Generated Feather file size: {feather_path.stat().st_size / (1024*1024):.2f} MB")
            except Exception: pass
            return True
        except FileNotFoundError:
            print_func(f"[bold red]Error:[/bold red] Input CSV file not found at '{csv_path}'")
            return False
        except PolarsError as e:
            print_func(f"[bold red]Polars Error during conversion:[/bold red] {e}")
            # Provide more context if possible (e.g., schema mismatch, parsing error)
            return False
        except Exception as e:
            print_func(f"[bold red]An unexpected error occurred during conversion:[/bold red] {e}")
            return False

# --- Typer Command Function (main - ワークフロー統合版) ---
# Helper to parse date strings
def parse_date_string(date_str: str) -> datetime:
    """Parses YYYY-MM-DD HH:MM:SS string to timezone-aware datetime (UTC)."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError as e:
        raise typer.BadParameter(
            f"Invalid date format '{date_str}'. Use 'YYYY-MM-DD HH:MM:SS'.",
            param_hint="'--date-start' or '--date-end'"
        ) from e

@app.command() # Default command
def main(
    apk_list: Path = typer.Option(
        ...,
        "--apk-list", "-l",
        help="Path to the input APK list file (Feather format preferred, will auto-convert from .csv if missing).",
        file_okay=True, dir_okay=False, writable=True, readable=True, resolve_path=True,
    ),
    api_key: Optional[str] = typer.Option( None, "--api-key", "-k", help="AndroZoo API Key (or use API_KEY env var).", show_default=False ),
    url: Optional[str] = typer.Option( None, "--url", "-u", help="AndroZoo API URL (or use URL env var)." ),
    malware_threshold: int = typer.Option( lambda: int(load_env_var("MALWARE_THRESHOLD", str(settings.DEFAULT_MALWARE_THRESHOLD))), "--threshold", "-t", min=0, help="Min VT count for malware (or use MALWARE_THRESHOLD env var)." ),
    n_malware: int = typer.Option( lambda: int(load_env_var("N_MALWARE", str(settings.DEFAULT_N_MALWARE))), "--num-malware", "-m", min=0, help="Number of malware samples to randomly select (or use N_MALWARE env var)." ),
    n_cleanware: int = typer.Option( lambda: int(load_env_var("N_CLEANWARE", str(settings.DEFAULT_N_CLEANWARE))), "--num-cleanware", "-c", min=0, help="Number of cleanware samples to randomly select (or use N_CLEANWARE env var)." ),
    date_start_str: str = typer.Option( lambda: load_env_var("DATE_START", settings.DEFAULT_DATE_START_STR), "--date-start", "-ds", parser=parse_date_string, help="Start date (YYYY-MM-DD HH:MM:SS, UTC). Uses DATE_START env var or default.", show_default=f"Default: {settings.DEFAULT_DATE_START_STR}" ),
    date_end_str: str = typer.Option( lambda: load_env_var("DATE_END", settings.DEFAULT_DATE_END_STR), "--date-end", "-de", parser=parse_date_string, help="End date (YYYY-MM-DD HH:MM:SS, UTC). Uses DATE_END env var or default.", show_default=f"Default: {settings.DEFAULT_DATE_END_STR}" ),
    concurrent_downloads: int = typer.Option( lambda: int(load_env_var("CONCURRENT_DOWNLOADS", str(settings.DEFAULT_CONCURRENT_DOWNLOADS))), "--concurrent", "-j", min=1, help="Max concurrent downloads (or use CONCURRENT_DOWNLOADS env var)." ),
    download_dir: Path = typer.Option( lambda: Path(load_env_var("DOWNLOAD_DIR", str(settings.DEFAULT_DOWNLOAD_DIR))), "--download-dir", "-o", help="Base directory to save downloaded APKs (or use DOWNLOAD_DIR env var).", resolve_path=True, file_okay=False ),
    cache_dir: Path = typer.Option( lambda: Path(load_env_var("CACHE_DIR", str(settings.DEFAULT_CACHE_DIR))), "--cache-dir", help="Directory to store cache files (or use CACHE_DIR env var).", resolve_path=True, file_okay=False ),
    log_dir: Path = typer.Option( lambda: Path(load_env_var("LOG_DIR", str(settings.DEFAULT_LOG_DIR))), "--log-dir", help="Directory to save log files (or use LOG_DIR env var).", resolve_path=True, file_okay=False ),
    logger_config: Path = typer.Option( lambda: Path(load_env_var("LOGGER_CONFIG_PATH", str(settings.DEFAULT_LOGGER_CONFIG_PATH))), "--log-config", help="Path to logger config JSON (or use LOGGER_CONFIG_PATH env var).", exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True ),
    force_recollect: bool = typer.Option( False, "--force-recollect", help="Ignore cache and re-collect/re-sample hashes.", is_flag=True ),
) -> None:
    """
    Downloads APKs based on criteria. Uses Feather input file, automatically
    converts from CSV with the same name if Feather file is missing.
    """
    # --- Console Setup ---
    # --- Console オブジェクトを作成 ---
    console = Console(stderr=True) # 標準エラー出力を使用
    pretty.install(console=console) # pretty traceback を有効化

    # --- .env ロード処理 ---
    DEFAULT_ENV_PATH = getattr(settings, 'DEFAULT_ENV_PATH', Path(".env"))
    env_loaded_successfully = False
    if DEFAULT_ENV_PATH and DEFAULT_ENV_PATH.exists() and DEFAULT_ENV_PATH.is_file():
        try:
            load_dotenv(dotenv_path=DEFAULT_ENV_PATH, override=True)
            console.print(f"[bold green]Loaded environment variables from {DEFAULT_ENV_PATH}.[/bold green]")
            env_loaded_successfully = True
        except Exception as e:
            console.print(f"[bold red]Warning:[/bold red] Failed to load .env file at {DEFAULT_ENV_PATH}: {e}")

    if not env_loaded_successfully:
        console.print(f"[bold yellow]Warning:[/bold yellow] No valid .env file loaded. Relying on existing environment variables.")

    # --- Polars チェック ---
    if not POLARS_AVAILABLE:
         console.print("\n[bold red]Critical Error: The 'polars' library is required.[/bold red]")
         console.print("[bold yellow]Please install it using: pip install polars pyarrow[/bold yellow]")
         raise typer.Exit(code=1)

    # --- Input file handling and auto-conversion ---
    target_feather_path = apk_list
    if target_feather_path.suffix.lower() != ".feather":
          original_input = target_feather_path
          target_feather_path = target_feather_path.with_suffix('.feather')
          console.print(f"[yellow]Input path lacks '.feather' suffix. Assuming target is: '{target_feather_path}' based on input '{original_input}'[/yellow]")

    inferred_csv_path = target_feather_path.with_suffix('.csv')

    if not target_feather_path.exists():
        console.print(f"Feather file '{target_feather_path}' not found.")
        if inferred_csv_path.exists():
            console.print(f"Found corresponding CSV file: '{inferred_csv_path}'.")
            console.print("Attempting automatic conversion to Feather format...")
            conversion_success = ApkDownloader.create_feather_from_csv(
                inferred_csv_path, target_feather_path, console # <<<--- console を渡す
            )
            if not conversion_success:
                console.log("[bold red]Automatic conversion from CSV failed. Exiting.[/bold red]")
                raise typer.Exit(code=1)
            console.print(f"Successfully created Feather file '{target_feather_path}'.")
        else:
            console.log(f"[bold red]Error:[/bold red] Input file not found.")
            console.log(f"Checked for Feather file: '{target_feather_path}'")
            console.log(f"And for CSV file: '{inferred_csv_path}'")
            raise typer.Exit(code=1)
    else:
        console.print(f"Using existing Feather file: '{target_feather_path}'")

    feather_input_path = target_feather_path

    # --- Argument Validation & Processing ---
    api_key_val = api_key if api_key is not None else load_env_var("API_KEY")
    url_val = url if url is not None else load_env_var("URL", settings.DEFAULT_URL)

    if not api_key_val:
        console.log("[bold red]Error:[/bold red] API Key required (--api-key or API_KEY env var).")
        raise typer.Exit(code=1)
    if not url_val:
         console.log("[bold red]Error:[/bold red] AndroZoo URL required (--url or URL env var).")
         raise typer.Exit(code=1)

    date_start: datetime = date_start_str # Typerが既にdatetimeに変換済み
    date_end: datetime = date_end_str   # Typerが既にdatetimeに変換済み
    if date_start > date_end:
         console.log(f"[bold red]Error:[/bold red] Start date ({date_start.date()}) cannot be after end date ({date_end.date()}).")
         raise typer.Exit(code=1)

    # --- Log File Path ---
    log_filename = f"{datetime.now(ZoneInfo('Asia/Tokyo')):%Y%m%d_%H%M%S}_download.log"
    log_file_path = log_dir / log_filename

    # --- Welcome Message ---
    console.print(Align.center(Panel.fit("[bold]APK Downloader (Auto-Convert Workflow)[/bold]",
                                         title="Welcome to", subtitle="Refactored Version",
                                         padding=(2, 4), border_style="blue")))
    console.print("\n") # Welcomeメッセージの後には改行を入れる

    # --- 代替スクリーンバッファの開始 ---
    downloader = None
    exit_code = 0
    final_status = StatusCode.ERROR # デフォルト

    try:
        # with console.screen() で囲む
        with console.screen(style="white on black", hide_cursor=True): # スタイルは任意
            # --- ディレクトリ作成 ---
            try:
                download_dir.mkdir(parents=True, exist_ok=True)
                cache_dir.mkdir(parents=True, exist_ok=True)
                log_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                 console.print(f"[bold red]Error creating directories: {e}. Screen will close.[/bold red]")
                 time.sleep(2)
                 raise typer.Exit(code=1)

            # --- Initialize Downloader ---
            downloader = ApkDownloader(
                console=console, # <<<--- Console オブジェクトを渡す
                url=url_val,
                api_key=api_key_val,
                apk_list_path=feather_input_path,
                malware_threshold=malware_threshold,
                n_malware=n_malware,
                n_cleanware=n_cleanware,
                date_start=date_start,
                date_end=date_end,
                concurrent_downloads=concurrent_downloads,
                log_file_path=log_file_path,
                logger_config_path=logger_config,
                download_dir=download_dir,
                cache_dir=cache_dir,
            )

            if not downloader.init_success:
                # エラーメッセージは downloader 内で console.print/log 済みのはず
                console.print("[bold red]Initialization failed. Screen will close.[/bold red]")
                time.sleep(2)
                raise typer.Exit(code=1)

            # --- Execute Actions ---
            sampled_cleanware, sampled_malware = downloader.collect_apk_hashes(force_recollect=force_recollect)

            collection_status = downloader.progress_status.get(TodoCode.CHL)

            if collection_status == StatusCode.SUCCESS:
                downloader.download_apks(sampled_cleanware, sampled_malware)
            elif collection_status == StatusCode.STOPPED:
                 console.print("[bold yellow]Process stopped during hash collection.[/bold yellow]")
                 time.sleep(1)
            else: # ERROR
                 console.print("[bold red]Hash collection failed.[/bold red]")
                 time.sleep(1)

            # --- screen が閉じる前の最終状態表示 (任意) ---
            if downloader:
                 # ダウンロードまで進んだか、収集で終わったかで最終ステータスを見る
                 final_step_status = downloader.progress_status.get(TodoCode.DA, StatusCode.WAITING)
                 if final_step_status == StatusCode.WAITING: # DA が実行されなかった場合
                     final_step_status = downloader.progress_status.get(TodoCode.CHL, StatusCode.ERROR)

                 if final_step_status == StatusCode.SUCCESS:
                     console.print("[bold green]Processing finished. Screen will close.[/bold green]")
                 elif final_step_status == StatusCode.STOPPED:
                     console.print("[bold yellow]Processing stopped. Screen will close.[/bold yellow]")
                 else: # ERROR or WAITING (init error など)
                      console.print("[bold red]Processing did not complete successfully. Screen will close.[/bold red]")
                 time.sleep(1) # メッセージを読む時間

    except typer.Exit as e:
         exit_code = e.exit_code
         # final_status は下のロジックで決定
    except Exception: # 予期せぬエラー
         # pretty traceback が screen 外で表示してくれるはず
         # logger が初期化されていればログに記録
         if downloader and hasattr(downloader, 'logger') and downloader.logger:
             downloader.logger.exception("An unexpected error occurred during execution.")
         final_status = StatusCode.ERROR # エラー状態とする
         exit_code = 1 # エラー終了コード

    # --- 代替スクリーン終了後 ---

    # --- Cleanup ---
    if downloader:
        downloader.cleanup() # Live の停止などを試みる

    # --- Final Status Determination ---
    if downloader and hasattr(downloader, 'progress_status'):
        collection_status = downloader.progress_status.get(TodoCode.CHL)
        download_status = downloader.progress_status.get(TodoCode.DA, StatusCode.WAITING) # DA未実行はWAITING

        # 中断/停止ステータスを優先
        if collection_status == StatusCode.STOPPED or download_status == StatusCode.STOPPED:
            final_status = StatusCode.STOPPED
        # typer.Exit で終了したがSTOPPEDでない場合はエラー扱いとする（typer.Exit(1)など）
        elif exit_code != 0 and final_status != StatusCode.STOPPED:
             final_status = StatusCode.ERROR
        # 初期化失敗
        elif not getattr(downloader, 'init_success', True):
             final_status = StatusCode.ERROR
        # 収集またはダウンロードでエラー
        elif collection_status == StatusCode.ERROR or download_status == StatusCode.ERROR:
            final_status = StatusCode.ERROR
        # 収集とダウンロード（または未実行）が成功した場合
        elif collection_status == StatusCode.SUCCESS and download_status in [StatusCode.SUCCESS, StatusCode.WAITING]:
             # DAがWAITINGでも、CHLが成功していれば全体としては成功とする（ダウンロード対象が0の場合など）
             # もしダウンロード対象が必ずある前提なら、 DA != SUCCESS はエラー扱いにしても良い
             final_status = StatusCode.SUCCESS
        # その他のケースはデフォルトのERRORのまま

    # --- Final Status Message ---
    # 以前コメントアウトされていた箇所を有効化（先頭の \n はなし）
    if final_status == StatusCode.SUCCESS:
         console.print(f"[bold green]APK Downloader finished successfully.[/bold green]")
    elif final_status == StatusCode.STOPPED:
         console.print("[bold yellow]APK Downloader stopped by user.[/bold yellow]")
    else: # ERROR
         console.print("[bold red]APK Downloader finished with errors or did not complete successfully.[/bold red]")
         if exit_code == 0: exit_code = 1

    # --- プログラム終了 ---
    if exit_code != 0:
         raise typer.Exit(code=exit_code)


# --- Entry Point ---
if __name__ == "__main__":
    # .env ロードや Polars チェックは main 関数内で行うように変更済み
    app()