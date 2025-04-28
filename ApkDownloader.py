import csv
import json
import logging
import os
import random # Import random module for sampling
import signal
import sys
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone # Import timezone for UTC handling
from enum import IntEnum, StrEnum, auto
from logging import Logger, config, getLogger
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple
from zoneinfo import ZoneInfo

import requests
import typer
from dotenv import load_dotenv
from rich import box, pretty, print # Use rich.print
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
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.table import Table
from rich.columns import Columns

# Import Polars with a fallback mechanism
try:
    import polars as pl
    from polars.exceptions import PolarsError # Import specific Polars exception
    POLARS_AVAILABLE = True
except ImportError:
    POLARS_AVAILABLE = False
    PolarsError = ImportError # Define a fallback exception type for error handling
    # Note: A warning about missing Polars could be printed earlier if preferred.

import settings

# Type alias for JSON-like data structure (used for both Polars and CSV data)
type Json = Dict[str, Any]

# Create a Typer app instance for the command-line interface
app = typer.Typer(
    help="APK Downloader: Downloads APKs using Feather input, auto-converts from CSV if needed.",
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
    """Enum representing the different tasks performed during initialization and execution."""
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
        apk_list_path: Path, # Expected to be a Feather file path
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
        # Initialize attributes to None or default before try blocks to ensure they exist
        self.logger: Optional[Logger] = None
        self.live: Optional[Live] = None
        self.event: Optional[Event] = None # Event to signal termination (e.g., Ctrl+C)
        self.progress_status: dict[str, StatusCode] = { todo: StatusCode.WAITING for todo in TodoCode.get_values() }
        self.overall_table = Table(box=box.SIMPLE)
        self.download_progress: Optional[Progress] = None # Rich Progress instance for downloads

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
            # Setup Live display for overall progress and download progress
            self.live = Live(
                self.generate_table(),
                auto_refresh=True,
                transient=False, # Keep the final display after exit
                console=self.console,
                vertical_overflow="crop" # How to handle overflow
            )
            self.live.start()
            self.progress_status[TodoCode.SP] = StatusCode.SUCCESS
        except Exception as e:
            self.console.print(f"[bold red]Error initializing Rich display:[/bold red] {e}")
            self.progress_status[TodoCode.SP] = StatusCode.ERROR
            self.init_success = False
        self._refresh_live_display() # Initial display refresh (safe even if self.live is None)
        if not self.init_success: return # Cannot proceed if display setup failed

        # --- 2. Store Configuration ---
        self.progress_status[TodoCode.RC] = StatusCode.PROCESSING
        self._refresh_live_display()
        self.URL = url
        self.API_KEY = api_key
        self.APK_LIST_PATH = apk_list_path # Path to the Feather file
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

        # Validate date range
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
            self.event = Event() # Create the termination event flag
            signal.signal(signal.SIGINT, self.handle_sigint) # Register SIGINT (Ctrl+C) handler
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
        self.logger = self._setup_logger() # Assign the logger instance
        # _setup_logger handles setting status to ERROR internally on failure
        if self.progress_status[TodoCode.SL] != StatusCode.ERROR:
            self.progress_status[TodoCode.SL] = StatusCode.SUCCESS
            self.logger.info("Logger setup successful.")
            self.logger.info(f"Log file: {self.LOG_FILE_PATH}")
        else:
            self.init_success = False # Logger setup failed
        self._refresh_live_display()
        if not self.init_success: return

        # --- 5. Generate Cache Filenames ---
        # This step defines where cache files will be stored based on current parameters.
        self.gen_cache_filenames()

        # --- 6. Make Download Directory ---
        self.progress_status[TodoCode.MDD] = StatusCode.PROCESSING
        self._refresh_live_display()
        if self._make_download_dirs(): # Create 'malware' and 'cleanware' subdirectories
            self.progress_status[TodoCode.MDD] = StatusCode.SUCCESS
        else:
            self.progress_status[TodoCode.MDD] = StatusCode.ERROR
            self.init_success = False
        self._refresh_live_display()
        if not self.init_success: return

        # --- 7 & 8 (Deferred) ---
        # Set initial status for hash collection and downloading as WAITING
        self.progress_status[TodoCode.CHL] = StatusCode.WAITING
        self.progress_status[TodoCode.DA] = StatusCode.WAITING
        self._refresh_live_display()

        # Log successful initialization if all steps passed
        if self.logger:
            self.logger.info("ApkDownloader initialization sequence complete.")
            self.logger.info(f"Target date range: {self.DATE_START.date()} to {self.DATE_END.date()}")
            self.logger.info(f"Target samples: {self.N_CLEANWARE} cleanware, {self.N_MALWARE} malware")


    def _setup_logger(self) -> Logger:
        """Configures and returns a logger instance based on the JSON config file."""
        try:
            # Ensure log directory exists before trying to open config or log file
            log_dir = self.LOG_FILE_PATH.parent
            log_dir.mkdir(parents=True, exist_ok=True)

            # Load logger configuration from the specified JSON file
            with self.LOGGER_CONFIG_PATH.open(mode="r") as f:
                logger_conf = json.load(f)
                # Update the file handler's filename in the loaded config
                if "handlers" in logger_conf and "fileHandler" in logger_conf["handlers"]:
                    logger_conf["handlers"]["fileHandler"]["filename"] = str(self.LOG_FILE_PATH)
                else:
                    # Warn if the expected handler structure isn't found
                    self.console.log("[bold yellow]Warning:[/bold yellow] 'handlers.fileHandler' not found in logger config. File logging might be skipped or use a default path.")
                config.dictConfig(logger_conf)

            # Get and return the named logger instance
            logger = getLogger(__name__)
            logger.info("Logger configured successfully from file.")
            return logger
        except FileNotFoundError:
            # Fallback if the config file is not found
            self.progress_status[TodoCode.SL] = StatusCode.ERROR
            self.console.log(f"[bold red]Error:[/bold red] Logger config file not found: {self.LOGGER_CONFIG_PATH}")
            # Use basic config as a fallback
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = getLogger(__name__)
            logger.warning("Using basic logging configuration due to missing config file.")
            return logger
        except (json.JSONDecodeError, KeyError, Exception) as e:
            # Fallback for errors during config loading or setup
            self.progress_status[TodoCode.SL] = StatusCode.ERROR
            self.console.log(f"[bold red]Error setting up logger from config:[/bold red] {e}")
            # Use basic config as a fallback
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
            logger = getLogger(__name__)
            logger.error(f"Using basic logging configuration due to error: {e}", exc_info=True)
            return logger


    def _refresh_live_display(self, download_panel: bool = False) -> None:
        """Updates the live display table if Live is active and started."""
        live = getattr(self, 'live', None) # Safely get the live attribute
        if live and live._started:
            try:
                # Generate the table layout and update the Live instance
                live.update(self.generate_table(download_panel=download_panel), refresh=True)
            except Exception as e:
                # Log error if update fails, using existing logger or a basic one
                logger = getattr(self, 'logger', None) or getLogger(__name__)
                logger.error(f"Failed to update live display: {e}", exc_info=False) # Avoid recursive errors in logging


    def generate_table(self, *, download_panel: bool = False) -> Align:
        """Generates the Rich Table layout for the progress display."""
        # Create the main table for overall task status
        overall_table = Table(box=box.SIMPLE)
        overall_table.add_column("", style="dim", width=3, justify="center") # Icon column
        overall_table.add_column("Task", style="cyan", no_wrap=True)
        overall_table.add_column("Status", justify="left")

        # Map status codes to display elements (icon, color, text)
        status_display_map = {
            StatusCode.WAITING:    {"icon": "[grey50]●", "color": "grey50", "text": "WAITING"},
            StatusCode.PROCESSING: {"icon": None,        "color": "blue",   "text": "PROCESSING"}, # Uses a spinner
            StatusCode.SUCCESS:    {"icon": "[green]✔",   "color": "green",  "text": "SUCCESS"},
            StatusCode.STOPPED:    {"icon": "[yellow]✋", "color": "yellow", "text": "STOPPED"},
            StatusCode.ERROR:      {"icon": "[red]✘",     "color": "red",    "text": "ERROR"},
        }

        progressing_spinner = Spinner("dots", style="blue", speed=1.0) # Spinner for PROCESSING state

        # Ensure progress_status dictionary exists before accessing
        progress_status = getattr(self, 'progress_status', {})

        # Iterate through all defined tasks and add a row for each
        for todo_value in TodoCode.get_values():
            status_code = progress_status.get(todo_value, StatusCode.WAITING) # Default to WAITING if not found
            display_info = status_display_map.get(status_code, {"icon": "?", "color": "grey50", "text": "UNKNOWN"}) # Fallback

            icon_renderable: Any # Type hint for the icon/spinner

            if status_code == StatusCode.PROCESSING:
                icon_renderable = progressing_spinner # Use spinner for processing
            else:
                icon_renderable = display_info["icon"] # Use static icon otherwise

            status_text = f"[{display_info['color']}] {display_info['text']} [/]" if display_info["text"] else ""

            overall_table.add_row(
                icon_renderable,
                f"{todo_value}",
                status_text,
            )

        # Panel for the overall progress table
        overall_panel = Panel(
            overall_table,
            title="Overall Progress",
            border_style="green",
            padding=(1, 1)
        )

        # Grid layout to potentially place panels side-by-side
        grid_table = Table.grid(expand=True)
        grid_table.add_column() # Column for the overall panel
        if download_panel:
            grid_table.add_column() # Add a second column if download panel is requested

        # List of renderables to put in the grid
        renderables = [overall_panel] # Start with the overall panel

        # Add the download progress panel if requested and available
        if download_panel:
            download_progress = getattr(self, 'download_progress', None)
            if download_progress:
                download_panel_obj = Panel(
                    download_progress,
                    title="Download Progress",
                    border_style="blue",
                    padding=(1, 1)
                )
                renderables.append(download_panel_obj)
            else:
                # Fallback message if download progress object doesn't exist
                renderables.append("[bold red]Download progress not available.[/bold red]")

        # Add the renderables as a row in the grid
        if renderables:
            grid_table.add_row(*renderables)

        # Center the entire grid layout
        return Align.center(grid_table)

    def handle_sigint(self, signum: int, frame: Optional[FrameType]) -> None:
        """Handles the SIGINT signal (Ctrl+C) by setting the termination event."""
        signame = signal.Signals(signum).name
        msg = f"Signal handler called with signal {signame} ({signum})"
        logger = getattr(self, 'logger', None) # Safely get logger
        event = getattr(self, 'event', None)   # Safely get event

        if logger:
            logger.warning(msg)
            logger.warning("Stopping gracefully...")
        # Set the event flag to signal other threads (like download loop) to stop
        if event:
            event.set()

    def _make_download_dirs(self) -> bool:
        """Creates the necessary download subdirectories ('cleanware', 'malware')."""
        logger = getattr(self, 'logger', None)
        try:
            # Create directories, including parents, if they don't exist
            (self.DOWNLOAD_DIR / "cleanware").mkdir(parents=True, exist_ok=True)
            (self.DOWNLOAD_DIR / "malware").mkdir(parents=True, exist_ok=True)
            if logger: logger.info(f"Ensured download directories exist under: {self.DOWNLOAD_DIR}")
            return True
        except OSError as e:
            # Log and report error if directory creation fails
            if logger: logger.error(f"Failed to create download directories: {e}")
            self.console.log(f"[bold red]Error creating download directories:[/bold red] {e}")
            return False

    # Note: has_vt_detection, is_malware, is_within_date_range are kept for potential
    # compatibility or future use with non-Polars workflows, but are not the primary
    # filtering mechanism when using Polars with Feather files.

    @staticmethod
    def has_vt_detection(json_data: Json) -> bool:
        """Checks if 'vt_detection' key exists and is not empty."""
        # Primarily relevant for older CSV logic.
        vt_detection_value = json_data.get("vt_detection")
        return vt_detection_value is not None and vt_detection_value != ""

    def is_malware(self, json_data: Json) -> bool:
        """Determines if an APK record represents malware based on the threshold."""
        # Primarily relevant for older CSV logic.
        logger = getattr(self, 'logger', None)
        try:
            # Attempt conversion, handle potential None or non-integer strings gracefully
            vt_detection_str = json_data.get("vt_detection")
            vt_detection = -1 # Default if conversion fails or value is None/empty
            if vt_detection_str is not None and vt_detection_str != '':
                 vt_detection = int(vt_detection_str)
            return vt_detection >= self.MALWARE_THRESHOLD
        except (ValueError, TypeError):
            # Log warning if vt_detection is invalid, treat as cleanware
            sha256 = json_data.get('sha256', 'Unknown')
            vt_val = json_data.get("vt_detection")
            if logger: logger.warning(f"Invalid vt_detection '{vt_val}' for {sha256}. Treating as cleanware.")
            return False

    def is_within_date_range(self, json_data: Json) -> bool:
        """Checks if the APK's scan date is within the configured date range."""
        # Primarily relevant for older CSV logic.
        logger = getattr(self, 'logger', None)
        scan_date_str = json_data.get("vt_scan_date")
        if not scan_date_str:
            # Log warning if date is missing
            if logger: logger.warning(f"Missing 'vt_scan_date' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
            return False
        try:
            # Parse the date string and make it timezone-aware (UTC)
            vt_scan_date = datetime.strptime(scan_date_str, "%Y-%m-%d %H:%M:%S")
            vt_scan_date = vt_scan_date.replace(tzinfo=timezone.utc) # Assume UTC
            # Check if the date falls within the configured range
            return self.DATE_START <= vt_scan_date <= self.DATE_END
        except (ValueError, TypeError):
            # Log warning if date format is invalid
            if logger: logger.warning(f"Invalid date format '{scan_date_str}' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
            return False

    def gen_cache_filenames(self) -> None:
        """Generates filenames for cache files based on current parameters."""
        logger = getattr(self, 'logger', None)
        # Create a unique sub-directory name based on filtering/sampling parameters
        info_chain: list[str] = [
            str(self.MALWARE_THRESHOLD), str(self.N_CLEANWARE), str(self.N_MALWARE),
            f"{self.DATE_START:%Y%m%d}", f"{self.DATE_END:%Y%m%d}",
        ]
        cache_sub_dir_name: str = "_".join(info_chain)
        cache_sub_dir: Path = self.CACHE_DIR / cache_sub_dir_name
        # Define the full paths for cleanware and malware cache files
        self.cleanware_cache_file: Path = cache_sub_dir / "cleanware_samples.jsonl"
        self.malware_cache_file: Path = cache_sub_dir / "malware_samples.jsonl"
        if logger: logger.info(f"Cache directory set to: {cache_sub_dir}")

    def make_cache_file(self, cleanware_samples: List[Json], malware_samples: List[Json]) -> bool:
        """Saves the selected samples (lists of dictionaries) to cache files (JSON Lines format)."""
        logger = getattr(self, 'logger', None)
        if not cleanware_samples and not malware_samples:
            if logger: logger.info("No samples selected to cache.")
            return True # Nothing to do, considered success

        # Ensure cache file paths have been generated
        if not hasattr(self, 'cleanware_cache_file') or not hasattr(self, 'malware_cache_file'):
            if logger: logger.error("Cache filenames not generated. Cannot make cache file.")
            return False

        cache_dir: Path = self.cleanware_cache_file.parent
        try:
            # Create the cache directory if it doesn't exist
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            if logger: logger.error(f"Failed to create cache directory {cache_dir}: {e}")
            self.console.log(f"[bold red]Error:[/bold red] Could not create cache directory: {e}")
            return False

        def make_json_serializable(data: Json) -> Json:
            """Converts datetime objects within a dictionary to ISO strings for JSON serialization."""
            serializable_data = {}
            for key, value in data.items():
                if isinstance(value, datetime):
                    # Convert datetime to ISO 8601 string format
                    serializable_data[key] = value.isoformat()
                # Add handling for other non-serializable types if needed
                # elif isinstance(value, SomeOtherType):
                #     serializable_data[key] = convert_other_type(value)
                else:
                    serializable_data[key] = value
            return serializable_data

        # Write cleanware samples to cache
        try:
            with self.cleanware_cache_file.open(mode="w", encoding='utf-8') as f:
                for json_data in cleanware_samples:
                    # Ensure data is JSON serializable (handle datetimes)
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if logger: logger.info(f"Successfully wrote {len(cleanware_samples)} cleanware samples to cache: {self.cleanware_cache_file}")
        except (IOError, TypeError) as e: # Catch potential TypeError from json.dumps
            if logger: logger.exception(f"Failed to write cleanware cache: {self.cleanware_cache_file}")
            self.console.log(f"[bold red]Cleanware cache write error:[/bold red] {e}")
            return False

        # Write malware samples to cache
        try:
            with self.malware_cache_file.open(mode="w", encoding='utf-8') as f:
                for json_data in malware_samples:
                    # Ensure data is JSON serializable
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if logger: logger.info(f"Successfully read {len(malware_samples)} malware samples from cache: {self.malware_cache_file}")
        except (IOError, TypeError) as e: # Catch potential TypeError from json.dumps
            if logger: logger.exception(f"Failed to write malware cache: {self.malware_cache_file}")
            self.console.log(f"[bold red]Malware cache write error:[/bold red] {e}")
            return False

        return True

    def read_cache_file(self) -> Optional[Tuple[List[Json], List[Json]]]:
        """Reads selected samples from existing cache files if they exist."""
        logger = getattr(self, 'logger', None)
        # Ensure cache file paths have been generated
        if not hasattr(self, 'cleanware_cache_file') or not hasattr(self, 'malware_cache_file'):
            if logger: logger.error("Cache filenames not generated. Cannot read cache file.")
            return None

        # Check if both cache files exist
        if not self.cleanware_cache_file.exists() or not self.malware_cache_file.exists():
            if logger: logger.info("Sample cache files not found.")
            return None # Cache does not exist or is incomplete

        if logger: logger.info(f"Attempting to read samples from cache files in {self.cleanware_cache_file.parent}")
        cleanware_list: List[Json] = []
        malware_list: List[Json] = []

        try:
            # Read cleanware cache (JSON Lines format)
            with self.cleanware_cache_file.open(mode="r", encoding='utf-8') as f:
                cleanware_list = [json.loads(line) for line in f if line.strip()]
            if logger: logger.info(f"Successfully read {len(cleanware_list)} cleanware samples from cache: {self.cleanware_cache_file}")

            # Read malware cache (JSON Lines format)
            with self.malware_cache_file.open(mode="r", encoding='utf-8') as f:
                malware_list = [json.loads(line) for line in f if line.strip()]
            if logger: logger.info(f"Successfully read {len(malware_list)} malware samples from cache: {self.malware_cache_file}")

            # Trim cache results if they contain more samples than currently requested
            # This allows reusing a larger cache for smaller requests.
            if len(cleanware_list) > self.N_CLEANWARE or len(malware_list) > self.N_MALWARE:
                 if logger: logger.warning("Cache contains more samples than currently requested. Using subset.")
                 cleanware_list = cleanware_list[:self.N_CLEANWARE]
                 malware_list = malware_list[:self.N_MALWARE]

            return cleanware_list, malware_list
        except (IOError, json.JSONDecodeError) as e:
            # Handle errors during file reading or JSON parsing
            if logger: logger.error(f"Error reading cache files: {e}. Re-collecting hashes.")
            self.console.log(f"[bold red]Error reading cache files:[/bold red] {e}. Cache will be ignored.")
            return None # Indicate cache reading failed
        except Exception as e:
            # Catch any other unexpected errors
            if logger: logger.exception(f"Unexpected error reading cache files: {e}")
            self.console.log(f"[bold red]Unexpected error reading cache:[/bold red] {e}")
            return None


    def collect_apk_hashes(self, force_recollect: bool = False) -> Tuple[list[Json], list[Json]]:
        """Loads data from Feather file, filters based on criteria, randomly samples APKs, and caches results."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        self.progress_status[TodoCode.CHL] = StatusCode.PROCESSING
        self._refresh_live_display()
        if logger: logger.info("Starting APK hash collection...")

        # --- Cache Check ---
        if not force_recollect:
            cached_result = self.read_cache_file()
            if cached_result is not None:
                cached_clean, cached_mal = cached_result
                if logger: logger.info(f"Loaded {len(cached_clean)} cleanware and {len(cached_mal)} malware samples from cache.")
                self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
                self._refresh_live_display()
                return cached_clean, cached_mal # Return cached data
            else:
                if logger: logger.info("Cache not found or invalid. Proceeding with collection from Feather.")
        else:
            if logger: logger.info("Forcing re-collection of hashes, ignoring cache.")

        # --- Polars Processing ---
        sampled_cleanware: list[Json] = []
        sampled_malware: list[Json] = []

        # Check if Polars library is available
        if not POLARS_AVAILABLE:
             self.console.log("[bold red]Error: 'polars' library is not installed. Cannot process Feather file.[/bold red]")
             self.progress_status[TodoCode.CHL] = StatusCode.ERROR
             self._refresh_live_display()
             return [], [] # Return empty lists on error

        try:
            feather_file_path = self.APK_LIST_PATH
            if not feather_file_path.exists():
                 raise FileNotFoundError(f"Feather file not found: {feather_file_path}")

            if logger: logger.info(f"Loading and scanning Feather file: {feather_file_path} using Polars...")
            # Use scan_ipc for lazy loading, potentially saving memory for large files
            lf = pl.scan_ipc(feather_file_path)

            # Define the base filtering criteria using Polars expressions
            # This includes checking for non-null values, casting vt_detection to int,
            # parsing vt_scan_date to datetime (UTC), and filtering by date range.
            base_filtered_lf = (
                lf
                .filter(pl.col("vt_detection").is_not_null()) # Ensure vt_detection exists
                # Cast vt_detection to Int64, allowing potential errors (strict=False)
                .with_columns(pl.col("vt_detection").cast(pl.Int64, strict=False).alias("vt_detection_int"))
                .filter(pl.col("vt_detection_int").is_not_null()) # Filter out rows where cast failed
                # Parse vt_scan_date string to Datetime, replace timezone with UTC
                .with_columns(pl.col("vt_scan_date").str.strptime(pl.Datetime, format="%Y-%m-%d %H:%M:%S", strict=False, exact=True).dt.replace_time_zone("UTC").alias("vt_scan_datetime"))
                .filter(pl.col("vt_scan_datetime").is_not_null()) # Filter out rows where date parse failed
                # Filter rows within the specified date range (inclusive)
                .filter(pl.col("vt_scan_datetime").is_between(self.DATE_START, self.DATE_END, closed="both"))
                .filter(pl.col("markets").is_not_null()) # Ensure 'markets' column exists (used for cleanware)
            )

            # Define malware candidates: vt_detection >= threshold
            malware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") >= self.MALWARE_THRESHOLD)
            )

            # Define cleanware candidates: vt_detection == 0 and from Google Play Store
            cleanware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") == 0)
                # Filter for apps listed only on 'play.google.com'
                .filter(pl.col("markets").str.strip_chars() == "play.google.com")
            )

            if logger: logger.info("Applying filters and collecting candidate dataframes...")

            # --- Execute the lazy queries and collect results into DataFrames ---
            # Check for termination signal before collecting data
            if event and event.is_set():
                if logger: logger.warning("Hash collection interrupted by signal before collecting data.")
                self.progress_status[TodoCode.CHL] = StatusCode.STOPPED
                self._refresh_live_display()
                return [], []

            malware_df = malware_candidates_lf.collect()

            if event and event.is_set(): # Check again after the first collect
                if logger: logger.warning("Hash collection interrupted by signal after collecting malware candidates.")
                self.progress_status[TodoCode.CHL] = StatusCode.STOPPED
                self._refresh_live_display()
                return [], []

            cleanware_df = cleanware_candidates_lf.collect()

            if logger: logger.info(f"Found {len(malware_df)} potential malware candidates and {len(cleanware_df)} potential cleanware candidates.")

            # --- Convert DataFrames to lists of dictionaries ---
            # This format is easier to work with for sampling and caching.
            all_malware_candidates = malware_df.to_dicts()
            all_cleanware_candidates = cleanware_df.to_dicts()
            del malware_df, cleanware_df # Free up memory used by the DataFrames

            # Check for termination signal again before sampling
            if event and event.is_set():
                if logger: logger.warning("Hash collection interrupted by signal before sampling.")
                self.progress_status[TodoCode.CHL] = StatusCode.STOPPED
                self._refresh_live_display()
                return [], []

            # --- Random Sampling ---
            # Sample the required number of cleanware samples if more candidates were found than needed
            if len(all_cleanware_candidates) > self.N_CLEANWARE:
                if logger: logger.info(f"Randomly sampling {self.N_CLEANWARE} cleanware from {len(all_cleanware_candidates)} candidates.")
                sampled_cleanware = random.sample(all_cleanware_candidates, self.N_CLEANWARE)
            else:
                # Use all found candidates if fewer were found than requested
                if logger: logger.info(f"Using all {len(all_cleanware_candidates)} found cleanware candidates (requested {self.N_CLEANWARE}).")
                sampled_cleanware = all_cleanware_candidates

            # Sample the required number of malware samples
            if len(all_malware_candidates) > self.N_MALWARE:
                if logger: logger.info(f"Randomly sampling {self.N_MALWARE} malware from {len(all_malware_candidates)} candidates.")
                sampled_malware = random.sample(all_malware_candidates, self.N_MALWARE)
            else:
                if logger: logger.info(f"Using all {len(all_malware_candidates)} found malware candidates (requested {self.N_MALWARE}).")
                sampled_malware = all_malware_candidates

            self.console.log(f"Selected {len(sampled_cleanware)} cleanware and {len(sampled_malware)} malware samples.")

            # --- Cache the results ---
            # Save the sampled lists to the cache files for potential reuse.
            self.make_cache_file(sampled_cleanware, sampled_malware)

            # --- Finalize ---
            self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
            self._refresh_live_display()
            return sampled_cleanware, sampled_malware

        except FileNotFoundError as e:
            if logger: logger.error(f"Input Feather file not found: {e}")
            self.console.log(f"[bold red]Error:[/bold red] {e}")
            self.progress_status[TodoCode.CHL] = StatusCode.ERROR
            self._refresh_live_display()
            return [], []
        except PolarsError as e: # Catch Polars-specific errors during processing
            if logger: logger.exception(f"Polars error processing Feather file: {e}")
            self.console.log(f"[bold red]Polars Error:[/bold red] {e}")
            self.progress_status[TodoCode.CHL] = StatusCode.ERROR
            self._refresh_live_display()
            return [], []
        except Exception as e: # Catch other unexpected errors during processing
            if logger: logger.exception(f"Unexpected error during Feather processing: {e}")
            self.console.log(f"[bold red]Unexpected error during Feather processing:[/bold red] {e}")
            self.progress_status[TodoCode.CHL] = StatusCode.ERROR
            self._refresh_live_display()
            return [], []

    def calculate_total_download_size(self, force_recollect: bool = False) -> None:
        """
        Calculates the total size of APKs to be downloaded using cached JSONL files.
        """
        logger = getattr(self, 'logger', None)
        self.console.print("[bold blue]Estimating total download size using cache...[/bold blue]")

        # Ensure cache file paths have been generated
        if not hasattr(self, 'cleanware_cache_file') or not hasattr(self, 'malware_cache_file'):
            self.console.print("[bold red]Error: Cache filenames not generated. Cannot calculate download size.[/bold red]")
            return

        # Check if both cache files exist
        if not self.cleanware_cache_file.exists() or not self.malware_cache_file.exists():
            self.console.print("[bold red]Error: Cache files not found. Cannot calculate download size.[/bold red]")
            return

        try:
            # Read cleanware and malware cache files
            cleanware_size_bytes = 0
            malware_size_bytes = 0

            with self.cleanware_cache_file.open(mode="r", encoding="utf-8") as f:
                for line in f:
                    json_data = json.loads(line)
                    apk_size = json_data.get("apk_size", 0)
                    if isinstance(apk_size, int) and apk_size > 0:
                        cleanware_size_bytes += apk_size

            with self.malware_cache_file.open(mode="r", encoding="utf-8") as f:
                for line in f:
                    json_data = json.loads(line)
                    apk_size = json_data.get("apk_size", 0)
                    if isinstance(apk_size, int) and apk_size > 0:
                        malware_size_bytes += apk_size

            total_size_bytes = cleanware_size_bytes + malware_size_bytes

            # Format and display the sizes
            def format_size(size_bytes: int) -> str:
                if size_bytes >= (1024 ** 3):
                    return f"{size_bytes / (1024 ** 3):.2f} GB"
                elif size_bytes >= (1024 ** 2):
                    return f"{size_bytes / (1024 ** 2):.2f} MB"
                elif size_bytes >= 1024:
                    return f"{size_bytes / 1024:.2f} KB"
                return f"{size_bytes} bytes"

            self.console.print(f"[green]Estimated total size of malware to download:[/green] {format_size(malware_size_bytes)}")
            self.console.print(f"[green]Estimated total size of cleanware to download:[/green] {format_size(cleanware_size_bytes)}")
            self.console.print(f"[bold green]Estimated total download size:[/bold green] {format_size(total_size_bytes)}")

        except (IOError, json.JSONDecodeError) as e:
            if logger: logger.error(f"Error reading cache files for size estimation: {e}")
            self.console.print(f"[bold red]Error reading cache files for size estimation:[/bold red] {e}")
        except Exception as e:
            if logger: logger.exception(f"Unexpected error during size estimation: {e}")
            self.console.print(f"[bold red]Unexpected error during size estimation:[/bold red] {e}")

    def download_handler( self, json_data: Json, task_id: TaskID, download_dir: Path) -> bool:
        """Downloads a single APK file identified by its SHA256 hash."""
        # Safely get logger, event, and progress objects
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        # Extract SHA256, ensuring it's a string
        sha256 = str(json_data.get("sha256", ""))
        if not sha256:
            if logger: logger.error("Missing or empty 'sha256'. Cannot download.")
            return False # Cannot proceed without SHA256

        # Check if termination signal has been received
        if event and event.is_set():
             return False # Stop download if termination requested

        # Construct the expected filename and full download path
        filename = Path(f"{sha256}.apk")
        download_file_path = download_dir / filename

        # Check if the file already exists; skip if it does
        if download_file_path.exists():
            if logger: logger.info(f"APK already exists, skipping: {download_file_path}")
            # Update progress bar to completed and hide it
            if download_progress: download_progress.update(task_id, completed=1, total=1, visible=False)
            return True # Consider existing file a success

        if logger: logger.info(f"Attempting download: {sha256} to {download_file_path}")
        params = {"apikey": self.API_KEY, "sha256": sha256} # API request parameters
        success = False
        response = None
        file_handle = None

        try:
            # Make the GET request with streaming enabled and timeouts
            response = requests.get(self.URL, params=params, stream=True, timeout=(10, 60)) # (connect_timeout, read_timeout)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

            # Get expected file size from headers, default to 0 if not present
            data_size = int(response.headers.get("content-length", 0))

            # Update the progress bar task with the total size and make it visible
            if download_progress:
                 download_progress.update(task_id, total=data_size, visible=True)
                 download_progress.start_task(task_id)

            # Download the file in chunks
            chunk_size = 64 * 1024 # 64 KB chunks
            download_dir.mkdir(parents=True, exist_ok=True) # Ensure target directory exists
            file_handle = download_file_path.open(mode="wb") # Open file in binary write mode
            bytes_downloaded = 0
            for chunk in response.iter_content(chunk_size=chunk_size):
                # Check for termination signal within the loop
                if event and event.is_set():
                    if logger: logger.warning(f"Download interrupted by signal for {sha256}.")
                    success = False
                    break # Exit the loop if interrupted

                if chunk: # Filter out keep-alive new chunks
                    file_handle.write(chunk)
                    bytes_downloaded += len(chunk)
                    # Update progress bar with the downloaded chunk size
                    if download_progress: download_progress.update(task_id, advance=len(chunk))
            else: # This block executes if the loop completed without a 'break'
                if not (event and event.is_set()): # Ensure not interrupted at the very end
                    # Verify downloaded size against content-length if available
                    if data_size > 0 and bytes_downloaded != data_size:
                        if logger: logger.warning(f"Incomplete download for {sha256}: Expected {data_size}, got {bytes_downloaded}.")
                        success = False
                    else:
                        # Download considered successful if loop finished and size matches (or no size given)
                        success = True
                else:
                    success = False # Interrupted

            if success and logger: logger.info(f"Successfully downloaded: {sha256}")

        except requests.exceptions.Timeout as e:
            if logger: logger.error(f"Timeout during download for {sha256}: {e}")
            self.console.log(f"[bold red]Timeout ({sha256[:12]}...):[/bold red] {e}")
            success = False
        except requests.exceptions.RequestException as e:
            # Catch other request-related errors (connection, HTTP errors, etc.)
            if logger: logger.error(f"Download failed for {sha256}: {e}")
            self.console.log(f"[bold red]Download Error ({sha256[:12]}...):[/bold red] {e}")
            success = False
        except IOError as e:
            # Catch errors during file writing
            if logger: logger.error(f"File write error for {download_file_path}: {e}")
            self.console.log(f"[bold red]File Error ({sha256[:12]}...):[/bold red] {e}")
            success = False
        except Exception as e:
            # Catch any other unexpected errors during download
            if logger: logger.exception(f"Unexpected error downloading {sha256}: {e}")
            self.console.log(f"[bold red]Unexpected Error ({sha256[:12]}...):[/bold red] {e}")
            success = False
        finally:
            # --- Cleanup after download attempt ---
            # Hide the progress bar task regardless of outcome
            if download_progress: download_progress.update(task_id, visible=False)
            # Close the file handle if it was opened
            if file_handle is not None and not file_handle.closed: file_handle.close()
            # Close the response connection
            if response is not None: response.close()

            # If the download was not successful, attempt to remove the potentially incomplete file
            if not success and download_file_path.exists():
                if logger: logger.warning(f"Download unsuccessful for {sha256}. Removing incomplete file.")
                try:
                    download_file_path.unlink() # Delete the file
                    if logger: logger.info(f"Removed incomplete file: {download_file_path}")
                except OSError as unlink_err:
                    # Log error if removal fails
                    if logger: logger.error(f"Failed to remove incomplete file {download_file_path}: {unlink_err}")
                    self.console.log(f"[bold red]Error removing file {filename.name}: {unlink_err}[/bold red]")
            elif not success and not download_file_path.exists():
                 if logger: logger.info(f"Download unsuccessful for {sha256}, no file created.")

        return success # Return True if download succeeded, False otherwise


    def download_apks(self, cleanware_list: List[Json], malware_list: List[Json]) -> None:
        """Downloads the selected cleanware and malware APKs concurrently using a thread pool."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        # Check if there are any files to download
        if not cleanware_list and not malware_list:
            if logger: logger.info("No samples selected for download.")
            self.console.log("No samples selected to download.")
            self.progress_status[TodoCode.DA] = StatusCode.SUCCESS # Mark as success (nothing to do)
            self._refresh_live_display()
            return

        # Set status to PROCESSING and refresh display to show the download panel
        self.progress_status[TodoCode.DA] = StatusCode.PROCESSING
        self._refresh_live_display(download_panel=True) # Show the download progress panel

        if logger: logger.info(f"Starting download of {len(cleanware_list)} cleanware and {len(malware_list)} malware samples.")
        total_files = len(cleanware_list) + len(malware_list)

        # --- Setup Summary Progress Bars ---
        overall_apk_progress: Optional[TaskID] = None
        cleanware_progress: Optional[TaskID] = None
        malware_progress: Optional[TaskID] = None
        tasks_added = False
        if download_progress:
            try:
                # Add summary tasks to the download progress bar
                overall_apk_progress = download_progress.add_task("[white]Overall Download:", filename="", total=total_files)
                cleanware_progress = download_progress.add_task("[green]Cleanware:", filename="", total=len(cleanware_list))
                malware_progress = download_progress.add_task("[green]Malware:", filename="", total=len(malware_list))
                tasks_added = True
            except Exception as e:
                # Log error if adding tasks fails
                if logger: logger.error(f"Failed to add download progress tasks: {e}")
                self.console.log(f"[bold red]Error adding progress tasks: {e}[/bold red]")
                # Don't proceed if progress bars couldn't be set up correctly
                self.progress_status[TodoCode.DA] = StatusCode.ERROR
                self._refresh_live_display(download_panel=True)
                return

        cleanware_futures: List[Future[Any]] = []
        malware_futures: List[Future[Any]] = []
        future_to_sha: Dict[Future[Any], str] = {} # Map futures back to SHA256 for logging

        # --- Submit Download Tasks to Thread Pool ---
        with ThreadPoolExecutor(max_workers=self.CONCURRENT_DOWNLOADS, thread_name_prefix="Downloader") as executor:
            clean_dir = self.DOWNLOAD_DIR / "cleanware"
            mal_dir = self.DOWNLOAD_DIR / "malware"

            # Only submit tasks if the progress bars were added successfully
            if tasks_added and download_progress:
                # Submit cleanware download tasks
                for json_data in cleanware_list:
                    sha = str(json_data.get("sha256", "unknown")) # Ensure SHA is string
                    # Add a task for each file (initially invisible)
                    tid = download_progress.add_task("Queued", filename=f"{sha[:12]}...", visible=False, start=False)
                    # Submit the download handler to the executor
                    future = executor.submit(self.download_handler, json_data, tid, clean_dir)
                    cleanware_futures.append(future)
                    future_to_sha[future] = sha

                # Submit malware download tasks
                for json_data in malware_list:
                    sha = str(json_data.get("sha256", "unknown")) # Ensure SHA is string
                    tid = download_progress.add_task("Queued", filename=f"{sha[:12]}...", visible=False, start=False)
                    future = executor.submit(self.download_handler, json_data, tid, mal_dir)
                    malware_futures.append(future)
                    future_to_sha[future] = sha
            else:
                # Fallback if progress task setup failed earlier
                self.console.log("[bold red]Cannot proceed with downloads as progress task setup failed.[/bold red]")
                self.progress_status[TodoCode.DA] = StatusCode.ERROR
                # No need to refresh here, error already logged.
                return # Exit download function

            # --- Monitor Progress ---
            all_futures = cleanware_futures + malware_futures
            completed_futures = set()

            while len(completed_futures) < len(all_futures):
                # Check for termination signal
                if event and event.is_set():
                    if logger: logger.warning("Interrupt signal received during downloads. Stopping monitoring.")
                    # Attempt to cancel pending futures (may not work if already running)
                    for f in all_futures:
                        if not f.done():
                            f.cancel()
                    break # Exit monitoring loop

                # Find futures that completed since the last check
                done_futures = {f for f in all_futures if f.done()}
                newly_completed = done_futures - completed_futures

                # Process newly completed futures (log results/errors)
                for future in newly_completed:
                    sha = future_to_sha.get(future, "unknown_sha")
                    try:
                        result = future.result() # Get result (True/False from download_handler) or raise exception
                        if logger:
                            if result is True: logger.debug(f"Future completed successfully for {sha}")
                            else: logger.warning(f"Future for {sha} completed but download handler returned {result}.")
                    except Exception as e:
                         # Log if the future itself raised an exception
                         if logger: logger.error(f"Future for {sha} completed with an exception: {type(e).__name__}.")

                completed_futures.update(newly_completed)
                n_finished = len(completed_futures)

                # Update summary progress bars if they exist
                if download_progress:
                     if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=n_finished)
                     if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=sum(f.done() for f in cleanware_futures))
                     if malware_progress is not None: download_progress.update(malware_progress, completed=sum(f.done() for f in malware_futures))

                # Refresh the live display
                self._refresh_live_display(download_panel=True)
                # Short sleep to yield control and prevent busy-waiting
                time.sleep(0.5)

            # --- Final Update After Loop ---
            if logger: logger.info("Download monitoring loop finished.")
            # Ensure progress bars reflect the final count of completed tasks
            final_clean_done = sum(f.done() for f in cleanware_futures)
            final_mal_done = sum(f.done() for f in malware_futures)
            final_overall_done = final_clean_done + final_mal_done
            if download_progress:
                if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=final_overall_done)
                if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=final_clean_done)
                if malware_progress is not None: download_progress.update(malware_progress, completed=final_mal_done)
            if logger: logger.info(f"Final check: {final_overall_done}/{total_files} tasks marked as done.")

        # --- Set Final Status based on results ---
        successful_downloads = 0
        failed_downloads = 0
        for future in all_futures:
            # Robustly check future status after executor shutdown
            if future.done() and not future.cancelled():
                try:
                    if future.result() is True: # Check the return value of download_handler
                        successful_downloads += 1
                    else:
                        failed_downloads += 1 # Handler returned False
                except Exception:
                    failed_downloads += 1 # Future raised an exception
            elif future.cancelled():
                failed_downloads += 1 # Task was cancelled
            else:
                # This case should ideally not happen if executor waits properly
                if logger: logger.error(f"Future for {future_to_sha.get(future, 'unknown')} did not complete after executor shutdown.")
                failed_downloads += 1

        if logger: logger.info(f"Final Download results: {successful_downloads} succeeded, {failed_downloads} failed/skipped/interrupted (out of {total_files} selected).")

        # Determine the final status code for the download step
        if event and event.is_set():
            self.progress_status[TodoCode.DA] = StatusCode.STOPPED
            # Log stop message after the loop ends
            self.console.log(f"[bold yellow]Downloads stopped by user. {successful_downloads} completed, {failed_downloads} failed/stopped.[/bold yellow]")
        else:
            if failed_downloads > 0:
                # Mark as SUCCESS even with failures, but log a warning
                self.progress_status[TodoCode.DA] = StatusCode.SUCCESS
                self.console.log(f"[bold yellow]Warning:[/bold yellow] {failed_downloads} downloads failed or were skipped.")
                if logger: logger.warning(f"{failed_downloads} downloads failed or were skipped.")
            elif successful_downloads == total_files:
                # All downloads completed successfully
                self.progress_status[TodoCode.DA] = StatusCode.SUCCESS
                self.console.log("[bold green]All selected downloads completed successfully.[/bold green]")
            else:
                # Handle potential discrepancies (e.g., interruption before all tasks started)
                 if successful_downloads + failed_downloads != total_files:
                      if logger: logger.warning(f"Potential discrepancy in download counts ({successful_downloads}S/{failed_downloads}F/{total_files}T). May have been interrupted early.")
                      # Treat as ERROR if not explicitly stopped by user
                      self.progress_status[TodoCode.DA] = StatusCode.ERROR if not (event and event.is_set()) else StatusCode.STOPPED
                 else:
                      # All tasks accounted for, but some failed (handled by failed_downloads > 0 case)
                      # If we reach here, it implies successful_downloads < total_files and failed_downloads = 0,
                      # which shouldn't happen if counts are correct. Assume success for now.
                      self.progress_status[TodoCode.DA] = StatusCode.SUCCESS

        # Final refresh of the display to show the final status
        self._refresh_live_display(download_panel=True)


    def cleanup(self) -> None:
        """Stops the Rich Live display if it's active."""
        logger = getattr(self, 'logger', None)
        live = getattr(self, 'live', None)

        if live and live._started:
            try:
                live.stop() # Stop the live display updates
                if logger: logger.info("Live display stopped.")
            except Exception as e:
                # Log error if stopping fails
                if logger: logger.error(f"Error stopping live display: {e}", exc_info=True)
        elif logger:
            # Log if cleanup is called but Live display wasn't active
             logger.info("Cleanup called, but Live display was not active or object didn't exist.")


    @staticmethod
    def create_feather_from_csv(csv_path: Path, feather_path: Path, console: Console) -> bool:
        """Converts a CSV file to Feather (Arrow IPC) format using Polars."""
        # Check if Polars is available before attempting conversion
        if not POLARS_AVAILABLE:
            console.print("[bold red]Error: 'polars' library is not installed. Cannot convert CSV to Feather.[/bold red]")
            return False

        print_func = console.print # Use console for printing status messages
        print_func(f"Attempting to convert '{csv_path}' to '{feather_path}' using Polars...")
        try:
            # Ensure the directory for the Feather file exists
            feather_path.parent.mkdir(parents=True, exist_ok=True)
            # Read CSV and write to Feather (IPC format)
            # Consider adding parameters like `ignore_errors=True` or specific `dtypes` if conversion fails often.
            # `low_memory=True` can help with very large CSVs but might be slower.
            pl.read_csv(csv_path, low_memory=True).write_ipc(feather_path)

            print_func(f"[bold green]Successfully converted CSV to Feather: '{feather_path}'[/bold green]")
            try:
                # Log the size of the generated Feather file
                print_func(f"Generated Feather file size: {feather_path.stat().st_size / (1024*1024):.2f} MB")
            except Exception: pass # Ignore errors getting file size
            return True
        except FileNotFoundError:
            print_func(f"[bold red]Error:[/bold red] Input CSV file not found at '{csv_path}'")
            return False
        except PolarsError as e: # Catch Polars-specific errors during conversion
            print_func(f"[bold red]Polars Error during conversion:[/bold red] {e}")
            # Providing more context might be helpful (e.g., schema mismatch, parsing error)
            return False
        except Exception as e: # Catch any other unexpected errors
            print_func(f"[bold red]An unexpected error occurred during conversion:[/bold red] {e}")
            return False

# --- Typer Command Function ---

# Helper to parse date strings from command-line arguments
def parse_date_string(date_str: str) -> datetime:
    """Parses YYYY-MM-DD HH:MM:SS string to timezone-aware datetime (UTC)."""
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc) # Assume input time is UTC
    except ValueError as e:
        # Raise Typer error for invalid format
        raise typer.BadParameter(
            f"Invalid date format '{date_str}'. Use 'YYYY-MM-DD HH:MM:SS'.",
            param_hint="'--date-start' or '--date-end'"
        ) from e

@app.command() # Define the main command for the Typer app
def main(
    # --- Command Line Options defined using Typer ---
    apk_list: Path = typer.Option(
        ..., # Makes this option mandatory
        "--apk-list", "-l",
        help="Path to the input APK list file (Feather format preferred, will auto-convert from .csv if missing).",
        file_okay=True, dir_okay=False, writable=False, readable=True, resolve_path=True, # File validation
    ),
    api_key: Optional[str] = typer.Option( None, "--api-key", "-k", help="AndroZoo API Key (or use API_KEY env var).", show_default=False ),
    url: Optional[str] = typer.Option( None, "--url", "-u", help="AndroZoo API URL (or use URL env var)." ),
    malware_threshold: int = typer.Option( lambda: int(load_env_var("MALWARE_THRESHOLD", str(settings.DEFAULT_MALWARE_THRESHOLD))), "--threshold", "-t", min=0, help="Min VT count for malware (or use MALWARE_THRESHOLD env var)." ),
    n_malware: int = typer.Option( lambda: int(load_env_var("N_MALWARE", str(settings.DEFAULT_N_MALWARE))), "--num-malware", "-m", min=0, help="Number of malware samples to randomly select (or use N_MALWARE env var)." ),
    n_cleanware: int = typer.Option( lambda: int(load_env_var("N_CLEANWARE", str(settings.DEFAULT_N_CLEANWARE))), "--num-cleanware", "-c", min=0, help="Number of cleanware samples to randomly select (or use N_CLEANWARE env var)." ),
    # Use lambdas to load defaults from env vars or settings file
    date_start_str: datetime = typer.Option( lambda: parse_date_string(load_env_var("DATE_START", settings.DEFAULT_DATE_START_STR)), "--date-start", "-ds", help="Start date (YYYY-MM-DD HH:MM:SS, UTC). Uses DATE_START env var or default.", show_default=f"Default: Use env var or {settings.DEFAULT_DATE_START_STR}" ),
    date_end_str: datetime = typer.Option( lambda: parse_date_string(load_env_var("DATE_END", settings.DEFAULT_DATE_END_STR)), "--date-end", "-de", help="End date (YYYY-MM-DD HH:MM:SS, UTC). Uses DATE_END env var or default.", show_default=f"Default: Use env var or {settings.DEFAULT_DATE_END_STR}" ),
    concurrent_downloads: int = typer.Option( lambda: int(load_env_var("CONCURRENT_DOWNLOADS", str(settings.DEFAULT_CONCURRENT_DOWNLOADS))), "--concurrent", "-j", min=1, help="Max concurrent downloads (or use CONCURRENT_DOWNLOADS env var)." ),
    download_dir: Path = typer.Option( lambda: Path(load_env_var("DOWNLOAD_DIR", str(settings.DEFAULT_DOWNLOAD_DIR))), "--download-dir", "-o", help="Base directory to save downloaded APKs (or use DOWNLOAD_DIR env var).", resolve_path=True, file_okay=False ),
    cache_dir: Path = typer.Option( lambda: Path(load_env_var("CACHE_DIR", str(settings.DEFAULT_CACHE_DIR))), "--cache-dir", help="Directory to store cache files (or use CACHE_DIR env var).", resolve_path=True, file_okay=False ),
    log_dir: Path = typer.Option( lambda: Path(load_env_var("LOG_DIR", str(settings.DEFAULT_LOG_DIR))), "--log-dir", help="Directory to save log files (or use LOG_DIR env var).", resolve_path=True, file_okay=False ),
    logger_config: Path = typer.Option( lambda: Path(load_env_var("LOGGER_CONFIG_PATH", str(settings.DEFAULT_LOGGER_CONFIG_PATH))), "--log-config", help="Path to logger config JSON (or use LOGGER_CONFIG_PATH env var).", exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True ),
    force_recollect: bool = typer.Option( False, "--force-recollect", help="Ignore cache and re-collect/re-sample hashes.", is_flag=True ),
) -> None:
    """
    Main application function: Downloads APKs based on specified criteria.
    Uses a Feather input file for APK metadata. If the Feather file specified
    via --apk-list is missing, it checks for a corresponding .csv file with the
    same base name and automatically converts it to Feather format before proceeding.
    Configuration can be provided via command-line options or environment variables.
    """
    # --- Console Setup ---
    # Create a Rich Console instance, using stderr for output
    console = Console(stderr=True)
    # Install pretty traceback handling for better error messages
    pretty.install(console=console)

    # --- Load Environment Variables from .env file ---
    # Determine the path to the .env file (default or from settings)
    DEFAULT_ENV_PATH = getattr(settings, 'DEFAULT_ENV_PATH', Path(".env"))
    env_loaded_successfully = False
    if DEFAULT_ENV_PATH and DEFAULT_ENV_PATH.exists() and DEFAULT_ENV_PATH.is_file():
        try:
            # Load .env file, overriding existing environment variables
            load_dotenv(dotenv_path=DEFAULT_ENV_PATH, override=True)
            console.print(f"[bold green]Loaded environment variables from {DEFAULT_ENV_PATH}.[/bold green]")
            env_loaded_successfully = True
        except Exception as e:
            console.print(f"[bold red]Warning:[/bold red] Failed to load .env file at {DEFAULT_ENV_PATH}: {e}")

    if not env_loaded_successfully:
        console.print(f"[bold yellow]Warning:[/bold yellow] No valid .env file loaded. Relying on existing environment variables and defaults.")

    # --- Check for Polars Installation ---
    if not POLARS_AVAILABLE:
         console.print("\n[bold red]Critical Error: The 'polars' library is required for this script.[/bold red]")
         console.print("[bold yellow]Please install it using: pip install polars pyarrow[/bold yellow]")
         raise typer.Exit(code=1) # Exit if Polars is missing

    # --- Input File Handling (Feather/CSV Auto-Conversion) ---
    target_feather_path = apk_list
    # If the input path doesn't end with .feather, assume it's the base name
    # and construct the target Feather path.
    if target_feather_path.suffix.lower() != ".feather":
          original_input = target_feather_path
          target_feather_path = target_feather_path.with_suffix('.feather')
          console.print(f"[yellow]Input path lacks '.feather' suffix. Assuming target Feather file is: '{target_feather_path}' based on input '{original_input}'[/yellow]")

    # Infer the corresponding CSV path based on the target Feather path
    inferred_csv_path = target_feather_path.with_suffix('.csv')

    # Check if the target Feather file exists
    if not target_feather_path.exists():
        console.print(f"Target Feather file '{target_feather_path}' not found.")
        # If Feather is missing, check for the corresponding CSV file
        if inferred_csv_path.exists():
            console.print(f"Found corresponding CSV file: '{inferred_csv_path}'.")
            console.print("Attempting automatic conversion to Feather format...")
            # Attempt to convert CSV to Feather using the static method
            conversion_success = ApkDownloader.create_feather_from_csv(
                inferred_csv_path, target_feather_path, console # Pass console for status messages
            )
            if not conversion_success:
                console.log("[bold red]Automatic conversion from CSV failed. Exiting.[/bold red]")
                raise typer.Exit(code=1) # Exit if conversion fails
            console.print(f"Successfully created Feather file '{target_feather_path}' from CSV.")
        else:
            # Exit if neither Feather nor CSV file is found
            console.log(f"[bold red]Error:[/bold red] Input file not found.")
            console.log(f"Checked for Feather file: '{target_feather_path}'")
            console.log(f"Checked for CSV file: '{inferred_csv_path}'")
            raise typer.Exit(code=1)
    else:
        # Use the existing Feather file
        console.print(f"Using existing Feather file: '{target_feather_path}'")

    # Set the final input path to the (potentially newly created) Feather file
    feather_input_path = target_feather_path

    # --- Process and Validate Arguments ---
    # Get API key and URL from options or environment variables
    api_key_val = api_key if api_key is not None else load_env_var("API_KEY")
    url_val = url if url is not None else load_env_var("URL", settings.DEFAULT_URL)

    # Validate required arguments
    if not api_key_val:
        console.log("[bold red]Error:[/bold red] API Key is required. Provide via --api-key or API_KEY environment variable.")
        raise typer.Exit(code=1)
    if not url_val:
         console.log("[bold red]Error:[/bold red] AndroZoo API URL is required. Provide via --url or URL environment variable.")
         raise typer.Exit(code=1)

    # Dates are already parsed to datetime objects by Typer's parser
    date_start: datetime = date_start_str
    date_end: datetime = date_end_str
    # Validate date range
    if date_start > date_end:
         console.log(f"[bold red]Error:[/bold red] Start date ({date_start.date()}) cannot be after end date ({date_end.date()}).")
         raise typer.Exit(code=1)

    # --- Construct Log File Path ---
    # Create a timestamped log filename
    log_filename = f"{datetime.now(ZoneInfo('Asia/Tokyo')):%Y%m%d_%H%M%S}_download.log"
    log_file_path = log_dir / log_filename

    # --- Welcome Message ---
    console.print(Align.center(Panel.fit("[bold]APK Downloader[/bold]",
                                        title="Welcome to", subtitle="Auto-Convert Workflow",
                                        padding=(1, 2), border_style="blue")))
    console.print("\n") # Add space after welcome message

    # --- Main Execution Block (within alternate screen buffer) ---
    downloader: Optional[ApkDownloader] = None # Initialize downloader variable
    exit_code = 0
    final_status = StatusCode.ERROR # Default final status

    try:
        # Use Rich Console's screen context manager for a cleaner UI during execution
        with console.screen(style="white on black", hide_cursor=True): # Style is optional
            # --- Create Necessary Directories ---
            try:
                download_dir.mkdir(parents=True, exist_ok=True)
                cache_dir.mkdir(parents=True, exist_ok=True)
                log_dir.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                 # Use console.print inside the screen context
                 console.print(f"[bold red]Error creating directories: {e}. Screen will close.[/bold red]")
                 time.sleep(2) # Allow user to see the error
                 exit_code = 1
                 raise # Re-raise to exit the 'with' block and trigger final cleanup/exit

            # --- Initialize ApkDownloader ---
            # Pass all validated configurations to the downloader class
            downloader = ApkDownloader(
                console=console, # Pass the console object for internal logging/printing
                url=url_val,
                api_key=api_key_val,
                apk_list_path=feather_input_path, # Use the validated Feather path
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

            # Check if initialization was successful
            if not downloader.init_success:
                # Error messages should have been printed by the downloader's __init__
                console.print("[bold red]Initialization failed. Screen will close.[/bold red]")
                time.sleep(2)
                exit_code = 1
                raise typer.Exit(code=1) # Trigger exit

            # --- Execute Core Actions ---
            # 1. Collect APK Hashes (either from cache or by processing the Feather file)
            sampled_cleanware, sampled_malware = downloader.collect_apk_hashes(force_recollect=force_recollect)

            # Check the status of hash collection
            collection_status = downloader.progress_status.get(TodoCode.CHL)

            # 2. Calculate total download size before proceeding to downloads
            if collection_status == StatusCode.SUCCESS:
                downloader.calculate_total_download_size(force_recollect=force_recollect)

            # 3. Download APKs only if hash collection was successful
            if collection_status == StatusCode.SUCCESS:
                downloader.download_apks(sampled_cleanware, sampled_malware)
            elif collection_status == StatusCode.STOPPED:
                console.print("[bold yellow]Process stopped during hash collection. Skipping downloads.[/bold yellow]")
                time.sleep(1)
            else:  # ERROR
                console.print("[bold red]Hash collection failed. Skipping downloads.[/bold red]")
                time.sleep(1)

            # --- Final Status Display Before Screen Closes ---
            if downloader:
                 # Determine the status of the last significant step (Download or Collection)
                 final_step_status = downloader.progress_status.get(TodoCode.DA, StatusCode.WAITING)
                 if final_step_status == StatusCode.WAITING: # If DA didn't run, check CHL status
                      final_step_status = downloader.progress_status.get(TodoCode.CHL, StatusCode.ERROR)

                 # Display a final message based on the outcome
                 if final_step_status == StatusCode.SUCCESS:
                     console.print("[bold green]Processing finished. Screen will close.[/bold green]")
                 elif final_step_status == StatusCode.STOPPED:
                     console.print("[bold yellow]Processing stopped. Screen will close.[/bold yellow]")
                 else: # ERROR or WAITING (e.g., init error)
                     console.print("[bold red]Processing did not complete successfully. Screen will close.[/bold red]")
                 time.sleep(1) # Allow user to read the final message

    except typer.Exit as e:
         # Catch controlled exits (e.g., validation errors, init failure)
         exit_code = e.exit_code
         # Final status will be determined below based on downloader state and exit code
    except Exception as e:
         # Catch unexpected errors during execution within the screen context
         # Rich pretty traceback should handle printing the error outside the screen
         # Log the exception if the logger was successfully initialized
         if downloader and hasattr(downloader, 'logger') and downloader.logger:
              downloader.logger.exception("An unexpected error occurred during execution.")
         else: # Fallback if logger isn't available
             console.print("[bold red]An unexpected error occurred:[/bold red]")
             console.print_exception(show_locals=True) # Print traceback manually
         final_status = StatusCode.ERROR # Mark as error
         exit_code = 1 # Ensure non-zero exit code

    # --- After Exiting the Screen Context ---

    # --- Cleanup ---
    # Stop the Live display if the downloader was initialized
    if downloader:
        downloader.cleanup()

    # --- Final Status Determination (Post-Execution) ---
    # Determine the overall final status based on task progress and exit code
    if downloader and hasattr(downloader, 'progress_status'):
        collection_status = downloader.progress_status.get(TodoCode.CHL)
        download_status = downloader.progress_status.get(TodoCode.DA, StatusCode.WAITING) # Default to WAITING if download didn't run

        # Prioritize STOPPED status if either step was stopped
        if collection_status == StatusCode.STOPPED or download_status == StatusCode.STOPPED:
            final_status = StatusCode.STOPPED
        # If exited with non-zero code and not explicitly stopped, consider it an error
        elif exit_code != 0 and final_status != StatusCode.STOPPED:
             final_status = StatusCode.ERROR
        # If initialization failed
        elif not getattr(downloader, 'init_success', True):
             final_status = StatusCode.ERROR
        # If either collection or download resulted in an error
        elif collection_status == StatusCode.ERROR or download_status == StatusCode.ERROR:
            final_status = StatusCode.ERROR
        # If collection succeeded and download either succeeded or was skipped (WAITING)
        elif collection_status == StatusCode.SUCCESS and download_status in [StatusCode.SUCCESS, StatusCode.WAITING]:
            # Treat as overall success if collection was successful, even if no downloads were
            # needed.
            final_status = StatusCode.SUCCESS
# Otherwise, keep the default ERROR status

    # --- Final Status Message (Printed to standard console) ---
    # Print a final summary message based on the determined final_status
    if final_status == StatusCode.SUCCESS:
         console.print(f"[bold green]APK Downloader finished successfully.[/bold green]")
    elif final_status == StatusCode.STOPPED:
         console.print("[bold yellow]APK Downloader stopped by user.[/bold yellow]")
    else: # ERROR
         console.print("[bold red]APK Downloader finished with errors or did not complete successfully.[/bold red]")
         if exit_code == 0: exit_code = 1 # Ensure non-zero exit code for errors

    # --- Exit Program ---
    # Raise Typer.Exit with the final exit code if it's non-zero
    if exit_code != 0:
         raise typer.Exit(code=exit_code)


# --- Script Entry Point ---
if __name__ == "__main__":
    # Call the Typer application instance
    # Loading .env, checking Polars, and other setup steps are handled within the main() function.
    app()