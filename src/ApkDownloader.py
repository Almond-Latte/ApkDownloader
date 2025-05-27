import json # Added to top-level imports
import logging # Added to top-level imports
import os # Added to top-level imports
import random # Import random module for sampling
import signal # Added to top-level imports
import time # Added to top-level imports
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone # Import timezone for UTC handling
from logging import Logger, config, getLogger
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple

import requests
import typer
from rich import box
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.spinner import Spinner
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.table import Table

import settings # Ensure settings is imported
from utils import Json, make_json_serializable, convert_csv_to_feather, calculate_sha256 # Add calculate_sha256
from cache_handler import CacheHandler # Ensure cache_handler is imported
from progress_manager import ProgressManager, TaskCode, StatusCode # Ensure progress_manager is imported

import polars as pl

# Create a Typer app instance for the command-line interface
app = typer.Typer(
    help="APK Downloader: Downloads APKs using Feather or CSV input. CSV files are auto-converted to Feather.",
    add_completion=False,
)

# --- ApkDownloader Class ---
class ApkDownloader:
    """Handles the process of collecting APK hashes and downloading APK files."""
    HIDE_COMPLETED_TASK_DELAY = 5.0  # タスク完了後に非表示にするまでの秒数
    FILENAME_DISPLAY_MAX_LEN = 8     # ファイル名表示の最大長（SHA部分）

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
        self.console = console
        self.init_success = True
        
        self.progress_manager = ProgressManager(
            status_change_callback=self._on_status_change
        )
        
        self.logger: Optional[Logger] = None
        self.live: Optional[Live] = None
        self.event: Optional[Event] = Event() # Initialize event here
        self.download_progress: Optional[Progress] = None
        
        # Config attributes will be set by _read_and_validate_config
        # Initialize them to None or default values if appropriate before validation
        self.url: Optional[str] = None
        self.api_key: Optional[str] = None
        self.apk_list_path: Optional[Path] = None
        self.malware_threshold: Optional[int] = None
        self.n_malware: Optional[int] = None
        self.n_cleanware: Optional[int] = None
        self.date_start: Optional[datetime] = None
        self.date_end: Optional[datetime] = None
        self.concurrent_downloads: Optional[int] = None
        self.log_file_path: Optional[Path] = log_file_path # Initialize directly
        self.logger_config_path: Optional[Path] = logger_config_path # Initialize directly
        self.download_dir: Optional[Path] = None
        self.cache_dir: Optional[Path] = None
        self.cache_handler: Optional[CacheHandler] = None # Initialize cache_handler
        
        # Run initialization sequence
        self._run_initialization_sequence(url, api_key, apk_list_path, malware_threshold, n_malware, n_cleanware, date_start, date_end, concurrent_downloads, log_file_path, logger_config_path, download_dir, cache_dir)
        
        self.gen_cache_filenames() # Generate cache filenames after config is validated

        # Instantiate CacheHandler after logger is set up and config is validated
        if self.init_success and self.logger and self.cache_handler is None: # Ensure cache_handler is not already set
            if all([self.cache_dir, self.malware_threshold is not None, self.n_cleanware is not None, self.n_malware is not None, self.date_start, self.date_end]):
                self.cache_handler = CacheHandler(
                    console=self.console,
                    logger=self.logger,
                    cache_dir=self.cache_dir,
                    malware_threshold=self.malware_threshold,
                    n_cleanware=self.n_cleanware,
                    n_malware=self.n_malware,
                    date_start=self.date_start,
                    date_end=self.date_end,
                )
            else:
                if self.logger:
                    self.logger.error("CacheHandler could not be initialized due to missing configuration.")
                self.console.print("[bold red]Error: CacheHandler initialization failed due to missing config.[/bold red]")
                self.init_success = False # Indicate initialization failure
        elif not self.init_success and self.logger:
             self.logger.warning("Skipping CacheHandler initialization due to previous errors.")


    def _on_status_change(self, task_code: TaskCode, status: StatusCode) -> None:
        """Handle status changes from progress manager."""
        self._refresh_live_display()

    def _read_and_validate_config(
        self,
        url: str,
        api_key: str,
        apk_list_path: Path,
        malware_threshold: int,
        n_malware: int,
        n_cleanware: int,
        date_start: datetime,
        date_end: datetime,
        concurrent_downloads: int,
        log_file_path: Path, # Already set in __init__
        logger_config_path: Path, # Already set in __init__
        download_dir: Path,
        cache_dir: Path,
    ) -> None:
        """Reads and validates the configuration parameters."""
        # Basic validation (can be expanded)
        if not url or not api_key:
            raise ValueError("URL and API_KEY must be provided.")
        if not apk_list_path.exists():
            raise FileNotFoundError(f"APK list file not found: {apk_list_path}")
        if n_malware < 0 or n_cleanware < 0:
            raise ValueError("Number of malware/cleanware samples cannot be negative.")
        if date_start >= date_end:
            raise ValueError("Start date must be before end date.")

        # Set instance attributes
        self.url = url
        self.api_key = api_key
        self.apk_list_path = apk_list_path
        self.malware_threshold = malware_threshold
        self.n_malware = n_malware
        self.n_cleanware = n_cleanware
        self.date_start = date_start.replace(tzinfo=timezone.utc) if date_start.tzinfo is None else date_start
        self.date_end = date_end.replace(tzinfo=timezone.utc) if date_end.tzinfo is None else date_end
        self.concurrent_downloads = concurrent_downloads
        # self.log_file_path and self.logger_config_path are already set in __init__
        self.download_dir = download_dir
        self.cache_dir = cache_dir

        # Log successful configuration
        if self.logger: # Check if logger is initialized
            self.logger.info("Configuration loaded and validated successfully.")
        else: # Fallback if logger is not yet available (should not happen if called after logger setup)
            self.console.print("[yellow]Configuration loaded (logger not yet available for detailed logging).[/yellow]")
    
    def _run_initialization_sequence(self, url: str, api_key: str, apk_list_path: Path, malware_threshold: int, n_malware: int, n_cleanware: int, date_start: datetime, date_end: datetime, concurrent_downloads: int, log_file_path: Path, logger_config_path: Path, download_dir: Path, cache_dir: Path) -> None:
        """Run the initialization sequence using progress manager."""
        
        if self.progress_manager.start_task(TaskCode.SETUP_PROGRESS):
            try:
                self._setup_progress_display()
                self.progress_manager.complete_task(TaskCode.SETUP_PROGRESS, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.SETUP_PROGRESS, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during setup progress display: {e}[/bold red]")
                return
        
        # Read Configuration (sets self attributes like self.URL, self.API_KEY etc.)
        if self.progress_manager.start_task(TaskCode.READ_CONFIG):
            try:
                # This method should set the instance attributes based on parameters
                self._read_and_validate_config(url, api_key, apk_list_path, malware_threshold, n_malware, n_cleanware, date_start, date_end, concurrent_downloads, log_file_path, logger_config_path, download_dir, cache_dir)
                self.progress_manager.complete_task(TaskCode.READ_CONFIG, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.READ_CONFIG, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during config reading: {e}[/bold red]")
                return
        
        if self.progress_manager.start_task(TaskCode.SETUP_SIGNALS):
            try:
                self._setup_signal_handler()
                self.progress_manager.complete_task(TaskCode.SETUP_SIGNALS, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.SETUP_SIGNALS, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during signal handler setup: {e}[/bold red]")
                return
        
        if self.progress_manager.start_task(TaskCode.SETUP_LOGGER):
            try:
                self.logger = self._setup_logger()
                # Now that logger is set up, log config if it wasn't logged before
                if self.logger and self.url: # Check if config was loaded
                     self.logger.info("Configuration loaded and validated successfully (logged after logger setup).")
                self.progress_manager.complete_task(TaskCode.SETUP_LOGGER, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.SETUP_LOGGER, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during logger setup: {e}[/bold red]")
                return
        
        if self.progress_manager.start_task(TaskCode.MAKE_DIRS):
            try:
                self._make_download_dirs()
                self.progress_manager.complete_task(TaskCode.MAKE_DIRS, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.MAKE_DIRS, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during directory creation: {e}[/bold red]")
                return
    
    def _setup_signal_handler(self) -> None:
        """Sets up signal handlers for graceful termination (SIGINT, SIGTERM)."""
        # Ensure self.event is initialized
        if self.event is None: # Should already be initialized in __init__
            self.event = Event()
            
        # Register the signal handler for SIGINT (Ctrl+C) and SIGTERM
        signal.signal(signal.SIGINT, self.handle_sigint)
        signal.signal(signal.SIGTERM, self.handle_sigint)
        if self.logger:
            self.logger.info("Signal handlers for SIGINT and SIGTERM registered.")
        else:
            self.console.print("[yellow]Signal handlers registered (logger not yet available).[/yellow]")

    def _setup_logger(self) -> Logger:
        """Initializes and configures the logger using a JSON configuration file."""
        if not self.logger_config_path or not self.log_file_path:
            # This should ideally be caught by _read_and_validate_config or __init__
            # but as a safeguard:
            self.console.print("[bold red]Error: Logger configuration path or log file path is not set.[/bold red]")
            raise ValueError("Logger configuration path or log file path is not set.")

        log_dir = self.log_file_path.parent
        try:
            log_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            self.console.print(f"[bold red]Error creating log directory {log_dir}: {e}[/bold red]")
            # Depending on severity, you might want to raise an exception or try a fallback
            raise  # Re-raise the exception if log directory creation is critical

        if self.logger_config_path.exists():
            try:
                with self.logger_config_path.open("rt") as f:
                    log_config_data = json.load(f)
                
                # Ensure the log file path is correctly set in the handler
                # This assumes a standard Python logging config structure
                if 'handlers' in log_config_data:
                    for handler_name, handler_config in log_config_data['handlers'].items():
                        if 'filename' in handler_config: # Check if the handler has a filename attribute
                            # Update the filename to use the path from settings/CLI
                            handler_config['filename'] = str(self.log_file_path) 
                
                config.dictConfig(log_config_data)
                logger = getLogger(__name__) # Get the logger instance
                logger.info(f"Logger initialized using config: {self.logger_config_path}")
                return logger
            except (IOError, json.JSONDecodeError, ValueError) as e:
                # Log error and fall back to basic config if JSON loading/parsing fails
                self.console.print(f"[bold red]Error loading logger config '{self.logger_config_path}': {e}. Using basic logging.[/bold red]")
                # Fallback to basic configuration
                logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=str(self.log_file_path))
                logger = getLogger(__name__)
                logger.warning(f"Fell back to basic logging due to config error. Log file: {self.log_file_path}")
                return logger
        else:
            # If no config file, use basic configuration
            self.console.print(f"[yellow]Logger config file '{self.logger_config_path}' not found. Using basic logging.[/yellow]")
            logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename=str(self.log_file_path))
            logger = getLogger(__name__)
            logger.info(f"Logger initialized with basic configuration. Log file: {self.log_file_path}")
            return logger

    def _setup_progress_display(self) -> None:
        """Sets up the Rich progress display for the download tasks."""
        self.download_progress = Progress(
            TextColumn("[progress.description]{task.description}", justify="right"),
            SpinnerColumn(),
            TextColumn("[bold blue]{task.fields[filename]}", justify="right"), # Expects task.fields['filename']
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TextColumn("[green]{task.completed}/{task.total}", justify="right"),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
            TextColumn("{task.fields[status_text]}"), # Expects task.fields['status_text']
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
        overall_table = Table(box=box.SIMPLE)
        overall_table.add_column("", style="dim", width=3, justify="center")
        overall_table.add_column("Task", style="cyan", no_wrap=True)
        overall_table.add_column("Status", justify="left")
        
        status_display_map = {
            StatusCode.WAITING: {"icon": "[grey50]●", "color": "grey50", "text": "WAITING"},
            StatusCode.PROCESSING: {"icon": None, "color": "blue", "text": "PROCESSING"},
            StatusCode.SUCCESS: {"icon": "[green]✔", "color": "green", "text": "SUCCESS"},
            StatusCode.STOPPED: {"icon": "[yellow]✋", "color": "yellow", "text": "STOPPED"},
            StatusCode.ERROR: {"icon": "[red]✘", "color": "red", "text": "ERROR"},
        }
        
        spinner = Spinner("dots", style="blue", speed=1.0)
        
        # Use progress manager to get task information
        for task_code in TaskCode:
            task_info = self.progress_manager.get_task_info(task_code)
            status = self.progress_manager.get_status(task_code)
            result = self.progress_manager.get_result(task_code)
            
            display_info = status_display_map.get(status, {"icon": "?", "color": "grey50", "text": "UNKNOWN"})
            
            icon_renderable = spinner if status == StatusCode.PROCESSING else display_info["icon"]
            status_text = f"[{display_info['color']}] {display_info['text']} [/]"
            
            # Add message if available
            if result and result.message:
                status_text += f" - {result.message}"
            
            overall_table.add_row(
                icon_renderable,
                task_info.name if task_info else task_code.value,
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
            (self.download_dir / "cleanware").mkdir(parents=True, exist_ok=True)
            (self.download_dir / "malware").mkdir(parents=True, exist_ok=True)
            if logger: logger.info(f"Ensured download directories exist under: {self.download_dir}")
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
            return vt_detection >= self.malware_threshold
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
            return self.date_start <= vt_scan_date <= self.date_end
        except (ValueError, TypeError):
            # Log warning if date format is invalid
            if logger: logger.warning(f"Invalid date format '{scan_date_str}' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
            return False

    def gen_cache_filenames(self) -> None:
        """Generates filenames for cache files based on current parameters."""
        logger = getattr(self, 'logger', None)
        # Create a unique sub-directory name based on filtering/sampling parameters
        info_chain: list[str] = [
            str(self.malware_threshold), str(self.n_cleanware), str(self.n_malware),
            f"{self.date_start:%Y%m%d}", f"{self.date_end:%Y%m%d}",
        ]
        cache_sub_dir_name: str = "_".join(info_chain)
        cache_sub_dir: Path = self.cache_dir / cache_sub_dir_name
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
            if len(cleanware_list) > self.n_cleanware or len(malware_list) > self.n_malware:
                 if logger: logger.warning("Cache contains more samples than currently requested. Using subset.")
                 cleanware_list = cleanware_list[:self.n_cleanware]
                 malware_list = malware_list[:self.n_malware]

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
        if not self.progress_manager.start_task(TaskCode.COLLECT_HASHES, "Starting hash collection..."):
            return [], []
        
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        
        try:
            # --- Cache Check ---
            if not force_recollect:
                cached_result = self.read_cache_file()
                if cached_result is not None:
                    cached_clean, cached_mal = cached_result
                    if logger: logger.info(f"Loaded {len(cached_clean)} cleanware and {len(cached_mal)} malware samples from cache.")
                    self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.SUCCESS)
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
                 self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.ERROR)
                 self._refresh_live_display()
                 return [], [] # Return empty lists on error

            feather_file_path = self.apk_list_path
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
                .filter(pl.col("vt_scan_datetime").is_between(self.date_start, self.date_end, closed="both"))
                .filter(pl.col("markets").is_not_null()) # Ensure 'markets' column exists (used for cleanware)
            )

            # Define malware candidates: vt_detection >= threshold
            malware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") >= self.malware_threshold)
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
                self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.STOPPED)
                self._refresh_live_display()
                return [], []

            malware_df = malware_candidates_lf.collect()

            if event and event.is_set(): # Check again after the first collect
                if logger: logger.warning("Hash collection interrupted by signal after collecting malware candidates.")
                self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.STOPPED)
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
                self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.STOPPED)
                self._refresh_live_display()
                return [], []

            # --- Random Sampling ---
            # Sample the required number of cleanware samples if more candidates were found than needed
            if len(all_cleanware_candidates) > self.n_cleanware:
                if logger: logger.info(f"Randomly sampling {self.n_cleanware} cleanware from {len(all_cleanware_candidates)} candidates.")
                sampled_cleanware = random.sample(all_cleanware_candidates, self.n_cleanware)
            else:
                # Use all found candidates if fewer were found than requested
                if logger: logger.info(f"Using all {len(all_cleanware_candidates)} found cleanware candidates (requested {self.n_cleanware}).")
                sampled_cleanware = all_cleanware_candidates

            # Sample the required number of malware samples
            if len(all_malware_candidates) > self.n_malware:
                if logger: logger.info(f"Randomly sampling {self.n_malware} malware from {len(all_malware_candidates)} candidates.")
                sampled_malware = random.sample(all_malware_candidates, self.n_malware)
            else:
                if logger: logger.info(f"Using all {len(all_malware_candidates)} found malware candidates (requested {self.n_malware}).")
                sampled_malware = all_malware_candidates

            self.console.log(f"Selected {len(sampled_cleanware)} cleanware and {len(sampled_malware)} malware samples.")

            # --- Cache the results ---
            # Save the sampled lists to the cache files for potential reuse.
            self.make_cache_file(sampled_cleanware, sampled_malware)

            # --- Finalize ---
            self.progress_manager.complete_task(
                TaskCode.COLLECT_HASHES, 
                StatusCode.SUCCESS,
                f"Collected {len(sampled_cleanware)} cleanware and {len(sampled_malware)} malware"
            )
            self._refresh_live_display()
            return sampled_cleanware, sampled_malware

        except FileNotFoundError as e:
            if logger: logger.error(f"Input Feather file not found: {e}")
            self.console.log(f"[bold red]Error:[/bold red] {e}")
            self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.ERROR)
            self._refresh_live_display()
            return [], []
        except PolarsError as e: # Catch Polars-specific errors during processing
            if logger: logger.exception(f"Polars error processing Feather file: {e}")
            self.console.log(f"[bold red]Polars Error:[/bold red] {e}")
            self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.ERROR)
            self._refresh_live_display()
            return [], []
        except Exception as e: # Catch other unexpected errors during processing
            if logger: logger.exception(f"Unexpected error during Feather processing: {e}")
            self.console.log(f"[bold red]Unexpected error during Feather processing:[/bold red] {e}")
            self.progress_manager.complete_task(TaskCode.COLLECT_HASHES, StatusCode.ERROR)
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
        """Downloads a single APK file identified by its SHA256 hash and verifies it."""
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        expected_sha256 = str(json_data.get("sha256", "")).lower()
        # filename_str and filename Path object are for actual file operations, so keep the full name.
        filename_str = "UNKNOWN_FN" # Default
        if expected_sha256:
            filename_str = f"{expected_sha256}.apk"
        
        filename = Path(filename_str) # Path object for file operations

        # Shortened filename for progress bar display.
        display_sha_part = expected_sha256[:self.FILENAME_DISPLAY_MAX_LEN]
        display_filename_for_progress = f"{display_sha_part}..." if len(expected_sha256) > self.FILENAME_DISPLAY_MAX_LEN else expected_sha256


        # Initial update of filename in task fields and set a preparing status.
        if download_progress and expected_sha256: 
            download_progress.update(task_id, filename=display_filename_for_progress, status_text="[cyan]Preparing...[/cyan]")


        if not expected_sha256:
            if logger:
                logger.error("SHA256 not found in JSON data. Cannot download or verify.")
            if download_progress:
                download_progress.update(task_id, visible=False, status_text="[red]No SHA256[/red]") 
            return False

        if event and event.is_set():
            if logger: logger.info(f"Download cancelled for {expected_sha256[:12]}... due to termination signal.")
            if download_progress:
                download_progress.update(task_id, visible=False, status_text="[yellow]Cancelled[/yellow]") 
            return False

        download_file_path = download_dir / filename 

        if download_file_path.exists():
            if logger:
                logger.info(f"File {filename.name} already exists. Verifying hash...")
            if download_progress:
                download_progress.update(task_id, status_text="[cyan]Verifying existing...[/cyan]") 

            calculated_sha256 = calculate_sha256(download_file_path)
            if calculated_sha256 == expected_sha256:
                if logger: logger.info(f"Hash match for existing file {filename.name}. Skipping download.")
                if download_progress:
                    file_size = download_file_path.stat().st_size
                    download_progress.update(
                        task_id,
                        completed=file_size,
                        total=file_size,
                        status_text="[green]Exists & Verified[/green]", 
                        completion_time=time.time() # Record completion time
                    )
                return True
            else:
                if logger: logger.warning(f"Hash mismatch for existing file {filename.name} (Expected: {expected_sha256}, Got: {calculated_sha256}). Will attempt re-download.")
                if download_progress:
                    download_progress.update(task_id, status_text="[yellow]Existing file hash mismatch. Re-downloading...[/yellow]") 
                try:
                    download_file_path.unlink()
                except OSError as e:
                    if logger: logger.error(f"Could not delete mismatched existing file {download_file_path}: {e}")

        if logger: logger.info(f"Attempting download: {expected_sha256} to {download_file_path}")
        if download_progress:
            download_progress.update(task_id, status_text="[cyan]Downloading...[/cyan]")

        params = {"apikey": self.api_key, "sha256": expected_sha256}
        success = False
        response = None
        file_handle = None
        bytes_downloaded = 0
        calculated_sha256 = ""

        try:
            response = requests.get(self.url, params=params, stream=True, timeout=(10, 60))
            response.raise_for_status()
            
            content_length_str = response.headers.get("content-length")
            if logger:
                logger.info(f"Task {task_id}: Received Content-Length header for {expected_sha256}: '{content_length_str}'")

            if content_length_str is not None and content_length_str.isdigit():
                data_size = int(content_length_str)
            else:
                data_size = 0 # If header is missing or not a number, default to 0.
                if logger:
                    logger.warning(f"Task {task_id}: Content-Length for {expected_sha256} is missing or invalid ('{content_length_str}'). Download speed may not be shown accurately.")

            if download_progress:
                 if logger: 
                     logger.info(f"Task {task_id}: Updating total to {data_size} for {expected_sha256}.")
                 download_progress.update(task_id, total=data_size, completed=0, visible=True, status_text="[cyan]Downloading...[/cyan]")
            else:
                if logger: logger.warning(f"Task {task_id}: download_progress is None, cannot update total for {expected_sha256}")

            chunk_size = 64 * 1024  # 64KB chunks
            download_dir.mkdir(parents=True, exist_ok=True)
            file_handle = download_file_path.open(mode="wb")
            
            for chunk_idx, chunk in enumerate(response.iter_content(chunk_size=chunk_size)):
                if event and event.is_set():
                    if logger: logger.info(f"Task {task_id}: Download of {expected_sha256} interrupted by event.")
                    if download_progress:
                        download_progress.update(task_id, status_text="[yellow]Interrupted[/yellow]")
                    success = False
                    break
                if chunk:  # filter out keep-alive new chunks
                    file_handle.write(chunk)
                    bytes_downloaded += len(chunk)
                    if download_progress:
                        download_progress.update(task_id, advance=len(chunk))

            else: # for-else: executes if the loop completed without a break
                # Check if download was successful based on bytes downloaded vs expected
                if data_size > 0 and bytes_downloaded == data_size:
                    success = True
                elif data_size == 0 and bytes_downloaded > 0: # Content-Length was 0, but data was received
                    success = True
                    if download_progress:
                        if logger: logger.info(f"Task {task_id}: Content-Length was 0, but {bytes_downloaded} bytes downloaded. Updating total for {expected_sha256}.")
                        download_progress.update(task_id, total=bytes_downloaded) # Update total to actual downloaded size
                elif data_size > 0 and bytes_downloaded < data_size and not (event and event.is_set()):
                    if logger: logger.warning(f"Task {task_id}: Download incomplete for {expected_sha256}. Expected {data_size}, got {bytes_downloaded}.")
                    success = False
                elif bytes_downloaded == 0 and data_size > 0: # No bytes downloaded but expected some
                     if logger: logger.warning(f"Task {task_id}: No bytes downloaded for {expected_sha256}, but expected {data_size}.")
                     success = False
                # If event was set, success should already be False from the break
            
            # If the loop was broken by event, success is already False.
            # If the loop completed but success is still not True (e.g. size mismatch), it remains False.

            if file_handle is not None and not file_handle.closed:
                file_handle.close()
            if response is not None:
                response.close()

            if success:
                if logger: logger.info(f"Download complete for {expected_sha256}. Verifying hash...")
                if download_progress:
                    download_progress.update(task_id, status_text="[cyan]Verifying hash...[/cyan]") 

                calculated_sha256 = calculate_sha256(download_file_path)
                if calculated_sha256 == expected_sha256:
                    if logger: logger.info(f"Hash verification successful for {expected_sha256}.")
                    if download_progress:
                        # Mark as verified and set completion time
                        download_progress.update(task_id, status_text="[green]Verified[/green]", completion_time=time.time()) 
                else:
                    if logger: logger.error(f"Hash mismatch for {expected_sha256}. Expected: {expected_sha256}, Got: {calculated_sha256}")
                    if download_progress:
                        download_progress.update(task_id, status_text="[red]Hash Mismatch![/red]") 
                        # Optionally, set completion_time for auto-hide on error as well
                        # download_progress.update(task_id, status_text="[red]Hash Mismatch![/red]", completion_time=time.time())
                    success = False
            elif not (event and event.is_set()): # If download loop didn't set success and not interrupted
                 if logger: logger.error(f"Download failed for {expected_sha256} before hash verification stage.")
                 if download_progress:
                     download_progress.update(task_id, status_text="[red]Download Failed[/red]") 

        except requests.exceptions.Timeout as e:
            if logger:
                logger.error(f"Timeout during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Timeout ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Timeout[/red]") 
            success = False
        except requests.exceptions.RequestException as e:
            if logger:
                logger.error(f"RequestException during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Download Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Request Error[/red]") 
            success = False
        except IOError as e:
            if logger:
                logger.error(f"IOError during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]File Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]File Error[/red]") 
            success = False
        except Exception as e:
            if logger:
                logger.exception(f"Unexpected error during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Unexpected Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Unexpected Error[/red]") 
            success = False
        finally:
            # Status text should be set by specific conditions above.
            # No generic status update needed here unless a default is desired.

            if file_handle is not None and not file_handle.closed:
                file_handle.close()
            if response is not None:
                response.close()

            if not success and download_file_path.exists():
                if logger: logger.warning(f"Download/Verification failed for {expected_sha256}. Deleting incomplete/corrupt file: {download_file_path}")
                try:
                    download_file_path.unlink()
                except OSError as e:
                    if logger: logger.error(f"Failed to delete incomplete/corrupt file {download_file_path}: {e}")

        return success

    def download_apks(self, cleanware_list: List[Json], malware_list: List[Json]) -> None:
        """Downloads the selected cleanware and malware APKs concurrently using a thread pool."""
        if not self.progress_manager.start_task(TaskCode.DOWNLOAD_APKS, f"Starting download of {len(cleanware_list + malware_list)} files..."):
            return
        
        logger = getattr(self, 'logger', None)
        event = getattr(self, 'event', None)
        download_progress = getattr(self, 'download_progress', None)

        if logger: logger.info(f"Starting download of {len(cleanware_list)} cleanware and {len(malware_list)} malware samples.")
        total_files = len(cleanware_list) + len(malware_list)
        
        all_futures: List[Future[Any]] = [] 
        cleanware_futures: List[Future[Any]] = []
        malware_futures: List[Future[Any]] = []
        future_to_sha: Dict[Future[Any], str] = {}
        overall_apk_progress: Optional[TaskID] = None
        cleanware_progress: Optional[TaskID] = None
        malware_progress: Optional[TaskID] = None

        try:
            tasks_added = False
            if download_progress:
                try:
                    # Add status_text to summary tasks
                    overall_apk_progress = download_progress.add_task("[white]Overall Download:", filename="", total=total_files, status_text="")
                    cleanware_progress = download_progress.add_task("[green]Cleanware:", filename="", total=len(cleanware_list), status_text="")
                    malware_progress = download_progress.add_task("[red]Malware:", filename="", total=len(malware_list), status_text="") # Changed color for malware summary
                    tasks_added = True
                except Exception as e:
                    if logger: logger.error(f"Failed to add download progress tasks: {e}")
                    self.console.log(f"[bold red]Error adding progress tasks: {e}[/bold red]")
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.ERROR, error=e)
                    self._refresh_live_display(download_panel=True)
                    return

            with ThreadPoolExecutor(max_workers=self.concurrent_downloads, thread_name_prefix="Downloader") as executor:
                clean_dir = self.download_dir / "cleanware"
                mal_dir = self.download_dir / "malware"

                if tasks_added and download_progress:
                    for json_data in cleanware_list:
                        sha = str(json_data.get("sha256", "unknown"))
                        # プログレスバー表示用の短縮ファイル名
                        display_sha_part = sha[:self.FILENAME_DISPLAY_MAX_LEN]
                        display_filename = f"{display_sha_part}..." if len(sha) > self.FILENAME_DISPLAY_MAX_LEN else sha
                        
                        tid = download_progress.add_task(
                            "Queued", 
                            filename=display_filename, # 短縮したファイル名を使用
                            visible=False, 
                            start=False, 
                            status_text="Queued"
                        )
                        future = executor.submit(self.download_handler, json_data, tid, clean_dir)
                        cleanware_futures.append(future)
                        future_to_sha[future] = sha

                    for json_data in malware_list:
                        sha = str(json_data.get("sha256", "unknown"))
                        # プログレスバー表示用の短縮ファイル名
                        display_sha_part = sha[:self.FILENAME_DISPLAY_MAX_LEN]
                        display_filename = f"{display_sha_part}..." if len(sha) > self.FILENAME_DISPLAY_MAX_LEN else sha

                        tid = download_progress.add_task(
                            "Queued", 
                            filename=display_filename, # 短縮したファイル名を使用
                            visible=False, 
                            start=False, 
                            status_text="Queued"
                        )
                        future = executor.submit(self.download_handler, json_data, tid, mal_dir)
                        malware_futures.append(future)
                        future_to_sha[future] = sha
                else:
                    self.console.log("[bold red]Cannot proceed with downloads as progress task setup failed.[/bold red]")
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.ERROR, error=Exception("Progress task setup failed"))
                    return

                all_futures = cleanware_futures + malware_futures # Corrected typo here
                completed_futures = set() # Ensure completed_futures is initialized before the loop
                self._refresh_live_display(download_panel=True) 

                # --- Monitor Progress ---
                while len(completed_futures) < len(all_futures):
                    if event and event.is_set():
                        if logger: logger.warning("Interrupt signal received during downloads. Stopping monitoring.")
                        for f_cancel in all_futures: # Use a different variable name
                            if not f_cancel.done():
                                f_cancel.cancel()
                        break

                    done_futures = {f_done for f_done in all_futures if f_done.done()} # Use a different variable name
                    newly_completed = done_futures - completed_futures

                    for future in newly_completed:
                        sha = future_to_sha.get(future, "unknown_sha")
                        try:
                            result = future.result()
                            if logger:
                                if result is True: logger.debug(f"Future completed successfully for {sha}")
                                else: logger.warning(f"Future for {sha} completed but download handler returned {result}.")
                        except Exception as e_future: # Use a different variable name
                             if logger: logger.error(f"Future for {sha} completed with an exception: {type(e_future).__name__}.")

                    completed_futures.update(newly_completed)
                    n_finished = len(completed_futures)

                    if download_progress:
                         if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=n_finished)
                         if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=sum(f.done() for f in cleanware_futures))
                         if malware_progress is not None: download_progress.update(malware_progress, completed=sum(f.done() for f in malware_futures))

                    # --- 完了したタスクの自動非表示 ---
                    if download_progress:
                        current_time = time.time()
                        for task in download_progress.tasks:
                            # 個別のダウンロードタスク（集約タスクではないもの）を確認
                            if task.visible and task.fields.get("completion_time") and not task.description.startswith(("[white]Overall", "[green]Cleanware", "[red]Malware")):
                                if current_time - task.fields["completion_time"] > self.HIDE_COMPLETED_TASK_DELAY:
                                    download_progress.update(task.id, visible=False)
                    
                    self._refresh_live_display(download_panel=True)
                    time.sleep(0.5) # メインループのポーリング間隔

                # --- Final Update After Loop (inside 'with' block) ---
                if logger: logger.info("Download monitoring loop finished.")
                final_clean_done = sum(f.done() for f in cleanware_futures)
                final_mal_done = sum(f.done() for f in malware_futures)
                final_overall_done = final_clean_done + final_mal_done
                if download_progress:
                    if overall_apk_progress is not None: download_progress.update(overall_apk_progress, completed=final_overall_done)
                    if cleanware_progress is not None: download_progress.update(cleanware_progress, completed=final_clean_done)
                    if malware_progress is not None: download_progress.update(malware_progress, completed=final_mal_done)
                if logger: logger.info(f"Final check: {final_overall_done}/{total_files} tasks marked as done.")
            
            # --- Set Final Status based on results (after 'with' block, but still in 'try') ---
            successful_downloads = 0
            failed_downloads = 0
            # Ensure all_futures is accessible; it should be if defined before 'with' or assigned in all paths within 'with'
            for future_item in all_futures: # Renamed to avoid conflict if 'future' is from an outer scope
                if future_item.done() and not future_item.cancelled():
                    try:
                        if future_item.result() is True:
                            successful_downloads += 1
                        else:
                            failed_downloads += 1
                    except Exception:
                        failed_downloads += 1
                elif future_item.cancelled():
                    failed_downloads += 1
                else:
                    if logger: logger.error(f"Future for {future_to_sha.get(future_item, 'unknown')} did not complete after executor shutdown.")
                    failed_downloads += 1

            if logger: logger.info(f"Final Download results: {successful_downloads} succeeded, {failed_downloads} failed/skipped/interrupted (out of {total_files} selected).")

            if event and event.is_set():
                self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.STOPPED, f"Downloads stopped. {successful_downloads}/{total_files} completed.")
                self.console.log(f"[bold yellow]Downloads stopped by user. {successful_downloads} completed, {failed_downloads} failed/stopped.[/bold yellow]")
            else:
                if failed_downloads > 0:
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.SUCCESS, f"Completed with {failed_downloads} failures. {successful_downloads}/{total_files} successful.")
                    self.console.log(f"[bold yellow]Warning:[/bold yellow] {failed_downloads} downloads failed or were skipped.")
                    if logger: logger.warning(f"{failed_downloads} downloads failed or were skipped.")
                elif successful_downloads == total_files:
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.SUCCESS, "All downloads completed")
                    self.console.log("[bold green]All selected downloads completed successfully.[/bold green]")
                else: # Discrepancy
                    status_code = StatusCode.ERROR if not (event and event.is_set()) else StatusCode.STOPPED
                    message = f"Download completed with errors or discrepancies. {successful_downloads}S/{failed_downloads}F/{total_files}T"
                    if logger: logger.warning(message)
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, status_code, message)
            
            self._refresh_live_display(download_panel=True)

        except Exception as e:
            if logger: logger.exception(f"Unexpected error during downloads: {e}")
            self.console.log(f"[bold red]Unexpected error during downloads:[/bold red] {e}")
            self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.ERROR, error=e)
            self._refresh_live_display(download_panel=True)

@app.command()
def main(
    api_key: str = typer.Option(settings.API_KEY, help="Your VirusTotal API key"),
    apk_list: Path = typer.Option(settings.APK_LIST_PATH, exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to the input APK list Feather or CSV file. CSV files are auto-converted to Feather."),
    download_dir: Path = typer.Option(settings.DOWNLOAD_DIR, file_okay=False, dir_okay=True, writable=True, help="Directory to save downloaded APKs"),
    n_cleanware: int = typer.Option(settings.N_CLEANWARE, min=1, help="Number of cleanware samples to download"),
    n_malware: int = typer.Option(settings.N_MALWARE, min=1, help="Number of malware samples to download"),
    date_start: str = typer.Option(settings.DATE_START_STR, help="Start date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    date_end: str = typer.Option(settings.DATE_END_STR, help="End date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    malware_threshold: int = typer.Option(settings.MALWARE_THRESHOLD, min=0, max=100, help="VirusTotal detection threshold for malware candidates (0-100)"),
):
    """Main entry point for the APK Downloader application."""

    console: Console = Console()

    # --- Handle CSV to Feather conversion ---
    processed_apk_list_path = apk_list
    if apk_list.suffix.lower() == ".csv":
        feather_path = apk_list.with_suffix(".feather")
        console.print(f"CSV file provided: {apk_list}")
        if feather_path.exists() and os.access(feather_path, os.R_OK):
            console.print(f"Found existing and readable Feather file: {feather_path}. Using it.")
            processed_apk_list_path = feather_path
        else:
            if feather_path.exists():
                console.print(f"Found existing Feather file {feather_path}, but it's not readable or accessible. Attempting to overwrite.")
            
            console.print(f"Attempting to convert '{apk_list}' to '{feather_path}'...")
            if convert_csv_to_feather(apk_list, feather_path):
                console.print(f"[green]Successfully converted CSV to Feather: {feather_path}[/green]")
                processed_apk_list_path = feather_path
            else:
                console.print(f"[bold red]Error: Failed to convert CSV file '{apk_list}' to Feather format.[/bold red]")
                console.print("Please ensure the CSV file is valid and the application has write permissions to the directory.")
                raise typer.Exit(code=1)
    elif apk_list.suffix.lower() != ".feather":
        console.print(f"[yellow]Warning: APK list file '{apk_list}' is not a .feather or .csv file. Proceeding as if it's a Feather file.[/yellow]")
        # No change to processed_apk_list_path, it remains apk_list

    # Final check for the processed_apk_list_path
    if not processed_apk_list_path.exists() or not os.access(processed_apk_list_path, os.R_OK):
        console.print(f"[bold red]Error: Processed APK list file '{processed_apk_list_path}' not found or not readable.[/bold red]")
        raise typer.Exit(code=1)
    # --- End CSV to Feather conversion ---

    data_start: datetime = datetime.strptime(date_start, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    data_end: datetime = datetime.strptime(date_end, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

    downloader = ApkDownloader(
        console=console,
        url=settings.URL,
        api_key=api_key,
        apk_list_path=processed_apk_list_path, # Use the processed path
        malware_threshold=malware_threshold,
        n_cleanware=n_cleanware,
        n_malware= n_malware,
        date_start=data_start,
        date_end=data_end,
        concurrent_downloads=settings.CONCURRENT_DOWNLOADS,
        log_file_path=settings.LOG_DIR / "apk_downloader.log",
        logger_config_path=settings.LOGGER_CONFIG_PATH,
        download_dir=download_dir,
        cache_dir=settings.CACHE_DIR,
    )

    # Start the hash collection process
    cleanware_list, malware_list = downloader.collect_apk_hashes()
    
    if cleanware_list or malware_list:
        # Calculate total download size
        downloader.calculate_total_download_size()
        
        # Start downloading the selected APKs
        downloader.download_apks(cleanware_list, malware_list)

if __name__ == "__main__":
    app()