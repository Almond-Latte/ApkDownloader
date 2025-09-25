import json
import logging
import os
import random
import signal
import time
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from logging import Logger, config, getLogger
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any, Dict, List, Optional, Tuple

import polars as pl
import requests
import typer
from rich import box
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.spinner import Spinner
from rich.table import Table

import settings
from cache_handler import CacheHandler
from progress_manager import ProgressManager, StatusCode, TaskCode
from utils import Json, calculate_sha256, convert_csv_to_feather, make_json_serializable

# Create a Typer app instance for the command-line interface
app = typer.Typer(
    help="APK Downloader: Analyze and download APK files from AndroZoo. Use 'survey' to analyze before downloading.",
    add_completion=False,
)

# --- ApkDownloader Class ---
class ApkDownloader:
    """Handles the process of collecting APK hashes and downloading APK files."""
    HIDE_COMPLETED_TASK_DELAY = 5.0  # Seconds to hide task after completion
    FILENAME_DISPLAY_MAX_LEN = 8     # Max length of SHA part for filename display

    def __init__(
        self,
        console: Console,
        url: str,
        api_key: str,
        apk_list_path: Path,
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
        random_seed: Optional[int] = None,
        verify_existing_file_hash: bool = True,
    ) -> None:
        """Initializes the ApkDownloader with necessary configurations."""
        super().__init__()
        self.console = console
        self.init_success = True

        self.progress_manager = ProgressManager(
            status_change_callback=self._on_status_change
        )
        
        self.logger: Optional[Logger] = None
        self.live: Optional[Live] = None
        self.event: Event = Event()
        self.download_progress: Optional[Progress] = None
        
        self.url: str = url 
        self.api_key: str = api_key
        self.apk_list_path: Path = apk_list_path
        self.malware_threshold: int = malware_threshold
        self.n_malware: int = n_malware
        self.n_cleanware: int = n_cleanware
        self.date_start: datetime = date_start 
        self.date_end: datetime = date_end
        self.concurrent_downloads: int = concurrent_downloads
        self.log_file_path: Path = log_file_path
        self.logger_config_path: Path = logger_config_path
        self.download_dir: Path = download_dir
        self.cache_dir: Path = cache_dir
        self.random_seed: Optional[int] = random_seed
        self.verify_existing_file_hash: bool = verify_existing_file_hash
        
        self.cache_handler: Optional[CacheHandler] = None
        self.cleanware_cache_file: Optional[Path] = None
        self.malware_cache_file: Optional[Path] = None
        
        self._run_initialization_sequence()

        if self.init_success:
            self.gen_cache_filenames()

            # Instantiate CacheHandler after logger is set up and config is validated.
            if self.logger and self.cache_handler is None:
                # All dependent config attributes (cache_dir, malware_threshold, etc.)
                # are now non-Optional instance members.
                self.cache_handler = CacheHandler(
                    console=self.console,
                    logger=self.logger, # Logger must be successfully initialized
                    cache_dir=self.cache_dir,
                    malware_threshold=self.malware_threshold,
                    n_cleanware=self.n_cleanware,
                    n_malware=self.n_malware,
                    date_start=self.date_start,
                    date_end=self.date_end,
                )
            elif not self.logger and self.init_success: 
                 # This case implies init_success was true but logger somehow failed to set,
                 # which should be caught by _run_initialization_sequence setting init_success to False.
                 self.console.print("[bold red]Error: Logger not initialized, cannot set up CacheHandler.[/bold red]")
                 self.init_success = False 
            elif not self.init_success and self.logger: 
                 self.logger.warning("Skipping CacheHandler initialization due to previous errors.")
            # If self.logger is None and init_success is False, it's already handled by the above.

    def _on_status_change(self, task_code: TaskCode, status: StatusCode) -> None:
        """Handle status changes from progress manager."""
        self._refresh_live_display()

    def _read_and_validate_config(self) -> None:
        """
        Validates the configuration parameters already set as instance attributes.
        This method is now called without arguments as attributes are pre-assigned in __init__.
        """
        # Basic validation for non-Optional attributes
        if not self.url or not self.api_key:
            raise ValueError("URL and API_KEY must be provided.")
        if not self.apk_list_path.exists():
            raise FileNotFoundError(f"APK list file not found: {self.apk_list_path}")
        if self.n_malware < 0 or self.n_cleanware < 0:
            raise ValueError("Number of malware/cleanware samples cannot be negative.")
        if self.date_start >= self.date_end:
            raise ValueError("Start date must be before end date.")
        if self.concurrent_downloads <= 0:
             raise ValueError("Concurrent downloads must be a positive integer.")
        if not self.download_dir: # Path objects are True if not empty, but check for robustness
            raise ValueError("Download directory must be specified.")
        if not self.cache_dir:
            raise ValueError("Cache directory must be specified.")

        # Ensure dates are timezone-aware (UTC)
        self.date_start = self.date_start.replace(tzinfo=timezone.utc) if self.date_start.tzinfo is None else self.date_start
        self.date_end = self.date_end.replace(tzinfo=timezone.utc) if self.date_end.tzinfo is None else self.date_end
        
        # Logging of successful configuration is now handled in _run_initialization_sequence
        # after the logger itself is confirmed to be set up.
    
    def _run_initialization_sequence(self) -> None:
        """
        Run the initialization sequence using progress manager.
        Uses instance attributes for configuration.
        """
        # Setup Progress Display first as other steps might log to console via progress manager
        if self.progress_manager.start_task(TaskCode.SETUP_PROGRESS):
            try:
                self._setup_progress_display()
                self.progress_manager.complete_task(TaskCode.SETUP_PROGRESS, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.SETUP_PROGRESS, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during setup progress display: {e}[/bold red]")
                return # Stop initialization if progress display fails

        # Validate Configuration (uses self attributes)
        if self.progress_manager.start_task(TaskCode.READ_CONFIG):
            try:
                self._read_and_validate_config() # Validates pre-assigned self attributes
                self.progress_manager.complete_task(TaskCode.READ_CONFIG, StatusCode.SUCCESS)
            except (ValueError, FileNotFoundError) as e: # Catch specific validation errors
                self.progress_manager.complete_task(TaskCode.READ_CONFIG, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Configuration error: {e}[/bold red]")
                return # Stop initialization if config is invalid

        # Setup Signal Handlers
        if self.progress_manager.start_task(TaskCode.SETUP_SIGNALS):
            try:
                self._setup_signal_handler()
                self.progress_manager.complete_task(TaskCode.SETUP_SIGNALS, StatusCode.SUCCESS)
            except Exception as e: 
                self.progress_manager.complete_task(TaskCode.SETUP_SIGNALS, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during signal handler setup: {e}[/bold red]")
                return

        # Setup Logger
        if self.progress_manager.start_task(TaskCode.SETUP_LOGGER):
            try:
                self.logger = self._setup_logger()
                # Now that logger is set up, log config validation success
                self.logger.info("Configuration loaded and validated successfully (logged after logger setup).")
                self.progress_manager.complete_task(TaskCode.SETUP_LOGGER, StatusCode.SUCCESS)
            except Exception as e:
                self.progress_manager.complete_task(TaskCode.SETUP_LOGGER, StatusCode.ERROR, error=e)
                self.init_success = False
                self.console.print(f"[bold red]Critical error during logger setup: {e}[/bold red]")
                if self.logger: 
                    self.logger.critical(f"Logger setup failed: {e}", exc_info=True)
                return

        # Make Download Directories
        if self.progress_manager.start_task(TaskCode.MAKE_DIRS):
            try:
                self._make_download_dirs() # Uses self.download_dir
                self.progress_manager.complete_task(TaskCode.MAKE_DIRS, StatusCode.SUCCESS)
            except (ValueError, OSError) as e: 
                self.progress_manager.complete_task(TaskCode.MAKE_DIRS, StatusCode.ERROR, error=e)
                self.init_success = False
                if self.logger: # Logger should be available here
                    self.logger.error(f"Failed to create download directories: {e}", exc_info=True)
                else: # Fallback if logger somehow isn't set despite previous step
                    self.console.print(f"[bold red]Error creating download directories (logger not available): {e}[/bold red]")
                return
    
    def _setup_signal_handler(self) -> None:
        """Sets up signal handlers for graceful termination (SIGINT, SIGTERM)."""
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
                    for _, handler_config in log_config_data['handlers'].items():
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
            DownloadColumn(),  # Automatically formats bytes to MB/GB
            TransferSpeedColumn(),  # Shows speed in appropriate units
            TimeRemainingColumn(),  # Shows estimated time remaining
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
                renderables.append(Panel("[bold red]Download progress not available.[/bold red]", title="Download Progress", border_style="red", padding=(1,1)))

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

    def _make_download_dirs(self) -> None:
        """Creates the necessary download subdirectories ('cleanware', 'malware').
        Raises ValueError if download_dir is not set, or OSError on directory creation failure.
        """
        logger = getattr(self, 'logger', None)

        if self.download_dir is None:
            err_msg = "Download directory (self.download_dir) is not configured. Cannot create subdirectories."
            if logger:
                logger.critical(err_msg)
            self.console.log(f"[bold red]Internal Error:[/bold red] {err_msg}")
            raise ValueError(err_msg)

        try:
            # Create directories, including parents, if they don't exist
            cleanware_dir = self.download_dir / "cleanware"
            malware_dir = self.download_dir / "malware"
            
            cleanware_dir.mkdir(parents=True, exist_ok=True)
            malware_dir.mkdir(parents=True, exist_ok=True)
            
            if logger: logger.info(f"Ensured download directories exist: {cleanware_dir}, {malware_dir}")
        except OSError as e:
            # Log and report error if directory creation fails
            err_msg = f"Failed to create download directories under {self.download_dir}: {e}"
            if logger: logger.error(err_msg)
            self.console.log(f"[bold red]Error creating download directories:[/bold red] {e}")
            raise # Re-raise OSError to be caught by the caller

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
            
            if self.malware_threshold is None:
                if logger: logger.warning(f"Malware threshold is not configured. Cannot determine if {json_data.get('sha256', 'Unknown')} is malware. Treating as cleanware.")
                return False
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
            if self.date_start is not None and self.date_end is not None:
                return self.date_start <= vt_scan_date <= self.date_end
            else:
                if logger: logger.warning(f"Date range not configured. Skipping date filter for {json_data.get('sha256', 'Unknown')}.")
                return False # Or True, depending on desired behavior when range is not set
        except (ValueError, TypeError):
            # Log warning if date format is invalid
            if logger: logger.warning(f"Invalid date format '{scan_date_str}' for {json_data.get('sha256', 'Unknown')}. Skipping date filter.")
    def gen_cache_filenames(self) -> None:
        """Generates filenames for cache files based on current parameters."""
        logger = getattr(self, 'logger', None)

        # Ensure all necessary configuration attributes are available before proceeding.
        # These attributes are typically set during _read_and_validate_config.
        # If any are None, it indicates an incomplete or failed configuration.
        if not all([
            self.cache_dir is not None,
            self.malware_threshold is not None,
            self.n_cleanware is not None,
            self.n_malware is not None,
            self.date_start is not None,
            self.date_end is not None,
        ]):
            if logger:
                logger.warning(
                    "Cannot generate cache filenames due to missing essential configuration "
                    "(cache_dir, malware_threshold, n_cleanware, n_malware, date_start, or date_end). "
                    "Cache functionality will be impaired."
                )
            # self.cleanware_cache_file and self.malware_cache_file remain None (as initialized in __init__)
            return

        # Create a unique sub-directory name based on filtering/sampling parameters
        # At this point, checked attributes are guaranteed to be non-None.
        info_chain: list[str] = [
            str(self.malware_threshold), str(self.n_cleanware), str(self.n_malware),
            f"{self.date_start:%Y%m%d}", f"{self.date_end:%Y%m%d}",
        ]
        cache_sub_dir_name: str = "_".join(info_chain)
        
        # self.cache_dir is now known to be a Path object due to the check above.
        cache_sub_dir: Path = self.cache_dir / cache_sub_dir_name
        
        # Define the full paths for cleanware and malware cache files
        self.cleanware_cache_file = cache_sub_dir / "cleanware_samples.jsonl"
        self.malware_cache_file = cache_sub_dir / "malware_samples.jsonl"
        if logger: 
            logger.info(f"Cache filenames generated. Cleanware cache: {self.cleanware_cache_file}, Malware cache: {self.malware_cache_file}")
            logger.info(f"Cache sub-directory: {cache_sub_dir}")

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

        # Set the random seed for reproducibility if provided
        if self.random_seed is not None:
            random.seed(self.random_seed)
            if logger: logger.info(f"Using random seed: {self.random_seed} for hash collection.")
        
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

            # Define cleanware candidates: vt_detection == 0 and optionally from Google Play Store
            cleanware_candidates_lf = (
                base_filtered_lf
                .filter(pl.col("vt_detection_int") == 0)
            )

            # Apply Google Play Store filter if enabled in settings
            if settings.GOOGLE_PLAY_ONLY:
                cleanware_candidates_lf = cleanware_candidates_lf.filter(
                    pl.col("markets").str.strip_chars() == "play.google.com"
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


        # Initial update but keep hidden until actual download
        if download_progress and expected_sha256:
            download_progress.update(task_id, filename=display_filename_for_progress, status_text="[grey50]Waiting...[/grey50]", visible=False)


        if not expected_sha256:
            if logger:
                logger.error("SHA256 not found in JSON data. Cannot download or verify.")
            if download_progress:
                download_progress.update(task_id, visible=False, status_text="[red]No SHA256[/red]") 
            return False

        if event and event.is_set():
            if logger: logger.info(f"Download cancelled for {expected_sha256[:12]}... due to termination signal.")
            # Don't show cancelled tasks at all - they stay hidden
            return False

        download_file_path = download_dir / filename 

        if download_file_path.exists():
            if self.verify_existing_file_hash: # Check if hash verification is enabled
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
            else: # Hash verification is disabled
                if logger:
                    logger.info(f"File {filename.name} already exists. Skipping download as hash verification is disabled.")
                if download_progress:
                    file_size = download_file_path.stat().st_size
                    download_progress.update(
                        task_id,
                        completed=file_size,
                        total=file_size,
                        status_text="[green]Exists (No Verify)[/green]",
                        completion_time=time.time() # Record completion time
                    )
                return True # Skip download if file exists and verification is off

        if logger: logger.info(f"Attempting download: {expected_sha256} to {download_file_path}")
        if download_progress:
            # ここで初めて表示し、説明を設定
            download_progress.update(task_id, description="Downloading", visible=True, status_text="[cyan]Downloading...[/cyan]")
            download_progress.start_task(task_id)  # タイマー開始

        params = {"apikey": self.api_key, "sha256": expected_sha256}
        success = False
        response = None
        file_handle = None
        bytes_downloaded = 0
        # calculated_sha256 = "" # This variable is defined later, no need to pre-define here

        try:
            response = requests.get(self.url, params=params, stream=True, timeout=(10, 60))
            response.raise_for_status()
            
            content_length_str = response.headers.get("content-length")
            data_size = int(content_length_str) if content_length_str and content_length_str.isdigit() else 0

            if download_progress:
                 download_progress.update(task_id, total=data_size, completed=0, visible=True, status_text="[cyan]Downloading...[/cyan]")

            chunk_size = 64 * 1024  # 64KB chunks
            download_dir.mkdir(parents=True, exist_ok=True)
            file_handle = download_file_path.open(mode="wb")
            
            for chunk_idx, chunk in enumerate(response.iter_content(chunk_size=chunk_size)):
                if event and event.is_set():
                    if logger: logger.info(f"Task {task_id}: Download of {expected_sha256} interrupted by event.")
                    if download_progress:
                        download_progress.update(task_id, status_text="[yellow]Interrupted[/yellow]", completion_time=time.time())
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
                        download_progress.update(task_id, status_text="[red]Hash Mismatch![/red]", completion_time=time.time())
                    success = False
            elif not (event and event.is_set()): # If download loop didn't set success and not interrupted
                 if logger: logger.error(f"Download failed for {expected_sha256} before hash verification stage.")
                 if download_progress:
                     download_progress.update(task_id, status_text="[red]Download Failed[/red]", completion_time=time.time()) 

        except requests.exceptions.Timeout as e:
            if logger:
                logger.error(f"Timeout during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Timeout ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Timeout[/red]", completion_time=time.time()) 
            success = False
        except requests.exceptions.RequestException as e:
            if logger:
                logger.error(f"RequestException during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Download Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Request Error[/red]", completion_time=time.time()) 
            success = False
        except IOError as e:
            if logger:
                logger.error(f"IOError during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]File Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]File Error[/red]", completion_time=time.time()) 
            success = False
        except Exception as e:
            if logger:
                logger.exception(f"Unexpected error during download of {expected_sha256}: {e}")
            self.console.log(f"[bold red]Unexpected Error ({expected_sha256[:12]}...):[/bold red] {e}")
            if download_progress: download_progress.update(task_id, status_text="[red]Unexpected Error[/red]", completion_time=time.time()) 
            success = False
        finally:
            if file_handle is not None and not file_handle.closed:
                file_handle.close()
            if response is not None:
                response.close()

            if not success and download_file_path.exists():
                try:
                    download_file_path.unlink()
                    if logger: logger.debug(f"Deleted incomplete file: {download_file_path}")
                except OSError:  # Ignore deletion errors
                    pass

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
                    # Calculate total bytes for progress display
                    total_cleanware_bytes = sum(int(item.get("apk_size", 0)) for item in cleanware_list)
                    total_malware_bytes = sum(int(item.get("apk_size", 0)) for item in malware_list)
                    total_bytes = total_cleanware_bytes + total_malware_bytes

                    # Add summary tasks - Rich will automatically format byte sizes
                    overall_apk_progress = download_progress.add_task(
                        "[white]Overall Download:",
                        filename="",
                        total=total_bytes,
                        status_text=f"[cyan]{total_files} files[/cyan]"
                    )
                    cleanware_progress = download_progress.add_task(
                        "[green]Cleanware:",
                        filename="",
                        total=total_cleanware_bytes,
                        status_text=f"[cyan]{len(cleanware_list)} files[/cyan]"
                    )
                    malware_progress = download_progress.add_task(
                        "[red]Malware:",
                        filename="",
                        total=total_malware_bytes,
                        status_text=f"[cyan]{len(malware_list)} files[/cyan]"
                    )
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
                    # Helper function to reduce code duplication
                    def create_download_task(json_data, target_dir, futures_list):
                        sha = str(json_data.get("sha256", "unknown"))
                        display_sha = sha[:self.FILENAME_DISPLAY_MAX_LEN]
                        display_filename = f"{display_sha}..." if len(sha) > self.FILENAME_DISPLAY_MAX_LEN else sha

                        tid = download_progress.add_task(
                            "",
                            filename=display_filename,
                            total=json_data.get("apk_size", 0),
                            visible=False,
                            start=False,
                            status_text="Queued"
                        )
                        future = executor.submit(self.download_handler, json_data, tid, target_dir)
                        futures_list.append(future)
                        future_to_sha[future] = sha

                    # Process cleanware
                    for json_data in cleanware_list:
                        create_download_task(json_data, clean_dir, cleanware_futures)

                    # Process malware
                    for json_data in malware_list:
                        create_download_task(json_data, mal_dir, malware_futures)
                else:
                    self.console.log("[bold red]Cannot proceed with downloads as progress task setup failed.[/bold red]")
                    self.progress_manager.complete_task(TaskCode.DOWNLOAD_APKS, StatusCode.ERROR, error=Exception("Progress task setup failed"))
                    return

                all_futures = cleanware_futures + malware_futures
                completed_futures = set()
                self._refresh_live_display(download_panel=True) 

                # --- Monitor Progress ---
                while len(completed_futures) < len(all_futures):
                    if event and event.is_set():
                        if logger: logger.warning("Interrupt signal received during downloads. Stopping monitoring.")
                        # Hide all queued (not yet started) tasks before cancelling
                        if download_progress:
                            for task in download_progress.tasks:
                                # Hide tasks that never started (description is empty and status is "Queued")
                                if task.fields.get("status_text") == "Queued" and task.description == "":
                                    download_progress.update(task.id, visible=False)
                        for future in all_futures:
                            if not future.done():
                                future.cancel()
                        break

                    done_futures = {f for f in all_futures if f.done()}
                    newly_completed = done_futures - completed_futures

                    for future in newly_completed:
                        sha = future_to_sha.get(future, "unknown_sha")
                        try:
                            result = future.result()
                            if logger and result is not True:
                                logger.warning(f"Download failed for {sha}: returned {result}")
                        except Exception as e:
                             if logger: logger.error(f"Future for {sha} failed: {type(e).__name__}")

                    completed_futures.update(newly_completed)
                    n_finished = len(completed_futures)

                    if download_progress:
                        # Track completed bytes (simplified with safe result check)
                        def get_completed_bytes(futures_list, data_list):
                            total = 0
                            for i, f in enumerate(futures_list):
                                if f.done():
                                    try:
                                        if f.result() == True:
                                            total += int(data_list[i].get("apk_size", 0))
                                    except Exception:
                                        pass  # Skip failed downloads
                            return total

                        cleanware_bytes = get_completed_bytes(cleanware_futures, cleanware_list)
                        malware_bytes = get_completed_bytes(malware_futures, malware_list)

                        if overall_apk_progress is not None:
                            download_progress.update(overall_apk_progress, completed=cleanware_bytes + malware_bytes)
                        if cleanware_progress is not None:
                            download_progress.update(cleanware_progress, completed=cleanware_bytes)
                        if malware_progress is not None:
                            download_progress.update(malware_progress, completed=malware_bytes)

                    # Hide completed tasks after delay
                    if download_progress:
                        current_time = time.time()
                        for task in download_progress.tasks:
                            if (task.visible and
                                task.fields.get("completion_time") and
                                not task.description.startswith(("[white]Overall", "[green]Cleanware", "[red]Malware")) and
                                current_time - task.fields["completion_time"] > self.HIDE_COMPLETED_TASK_DELAY):
                                download_progress.update(task.id, visible=False)
                    
                    self._refresh_live_display(download_panel=True)
                    time.sleep(0.5)

                if logger: logger.info("Download monitoring loop finished.")
            
            # --- Set Final Status based on results (after 'with' block, but still in 'try') ---
            successful_downloads = 0
            failed_downloads = 0
            # Ensure all_futures is accessible; it should be if defined before 'with' or assigned in all paths within 'with'
            for future_item in all_futures:
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

@app.command(name="download")
def download(
    api_key: str = typer.Option(settings.API_KEY, help="Your VirusTotal API key"),
    apk_list: Path = typer.Option(settings.APK_LIST_PATH, exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to the input APK list Feather or CSV file. CSV files are auto-converted to Feather."),
    download_dir: Path = typer.Option(settings.DOWNLOAD_DIR, file_okay=False, dir_okay=True, writable=True, help="Directory to save downloaded APKs"),
    n_cleanware: int = typer.Option(settings.N_CLEANWARE, min=1, help="Number of cleanware samples to download"),
    n_malware: int = typer.Option(settings.N_MALWARE, min=1, help="Number of malware samples to download"),
    date_start: str = typer.Option(settings.DATE_START_STR, help="Start date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    date_end: str = typer.Option(settings.DATE_END_STR, help="End date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    malware_threshold: int = typer.Option(settings.MALWARE_THRESHOLD, min=0, max=100, help="VirusTotal detection threshold for malware candidates (0-100)"),
    random_seed: Optional[int] = typer.Option(settings.RANDOM_SEED, help="Seed for random number generation to ensure reproducibility. If None, seed is not fixed."), # Add random_seed option
    verify_hash: bool = typer.Option(settings.VERIFY_EXISTING_FILE_HASH, help="Verify hash of existing files. If False, existing files are skipped without verification."),
):
    """Download APK files based on the specified criteria."""

    console: Console = Console()

    # --- Handle CSV to Feather conversion with validation ---
    processed_apk_list_path = apk_list
    if apk_list.suffix.lower() == ".csv":
        feather_path = apk_list.with_suffix(".feather")
        console.print(f"CSV file provided: {apk_list}")

        # Check if we have a valid Feather cache
        from utils import is_feather_cache_valid
        if is_feather_cache_valid(apk_list, feather_path):
            console.print(f"[green]Found valid Feather cache: {feather_path}[/green]")
            processed_apk_list_path = feather_path
        else:
            # Need to convert or re-convert
            if feather_path.exists():
                console.print(f"[yellow]Feather cache is outdated or invalid. Re-converting...[/yellow]")
            else:
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

    # Generate log file name with current timestamp
    current_time_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = f"apk_downloader_{current_time_str}.log"
    dynamic_log_file_path = settings.LOG_DIR / log_filename

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
        log_file_path=dynamic_log_file_path, # Use dynamically generated log file path
        logger_config_path=settings.LOGGER_CONFIG_PATH,
        download_dir=download_dir,
        cache_dir=settings.CACHE_DIR,
        random_seed=random_seed, # Pass the random_seed
        verify_existing_file_hash=verify_hash, # Pass the hash verification setting
    )

    # Start the hash collection process
    cleanware_list, malware_list = downloader.collect_apk_hashes()
    
    if cleanware_list or malware_list:
        # Calculate total download size
        downloader.calculate_total_download_size()
        
        # Start downloading the selected APKs
        downloader.download_apks(cleanware_list, malware_list)

@app.command(name="survey")
def survey(
    api_key: str = typer.Option(settings.API_KEY, help="Your AndroZoo API key"),
    apk_list: Path = typer.Option(settings.APK_LIST_PATH, exists=True, file_okay=True, dir_okay=False, readable=True, help="Path to the input APK list Feather or CSV file"),
    n_cleanware: int = typer.Option(settings.N_CLEANWARE, min=1, help="Target number of cleanware samples"),
    n_malware: int = typer.Option(settings.N_MALWARE, min=1, help="Target number of malware samples"),
    date_start: str = typer.Option(settings.DATE_START_STR, help="Start date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    date_end: str = typer.Option(settings.DATE_END_STR, help="End date for filtering APKs (YYYY-MM-DD HH:MM:SS)"),
    malware_threshold: int = typer.Option(settings.MALWARE_THRESHOLD, min=0, max=100, help="VirusTotal detection threshold (0-100)"),
    export_hashes: Optional[Path] = typer.Option(None, help="Export hash list to CSV file"),
    show_distribution: bool = typer.Option(True, help="Show temporal distribution of samples"),
    distribution_granularity: str = typer.Option("year", help="Distribution granularity: year, quarter, or month"),
):
    """Survey and analyze APK samples without downloading.

    This command allows you to:
    - Check how many samples match your criteria
    - View the temporal distribution of samples
    - Export hash lists for later use
    """

    console: Console = Console()

    # Handle CSV to Feather conversion with validation
    processed_apk_list_path = apk_list
    if apk_list.suffix.lower() == ".csv":
        feather_path = apk_list.with_suffix(".feather")
        console.print(f"CSV file provided: {apk_list}")

        # Check if we have a valid Feather cache
        from utils import is_feather_cache_valid
        if is_feather_cache_valid(apk_list, feather_path):
            console.print(f"[green]Found valid Feather cache: {feather_path}[/green]")
            processed_apk_list_path = feather_path
        else:
            # Need to convert or re-convert
            if feather_path.exists():
                console.print(f"[yellow]Feather cache is outdated or invalid. Re-converting...[/yellow]")
            else:
                console.print(f"Converting '{apk_list}' to '{feather_path}'...")

            if convert_csv_to_feather(apk_list, feather_path):
                console.print(f"[green]Successfully converted CSV to Feather: {feather_path}[/green]")
                processed_apk_list_path = feather_path
            else:
                console.print(f"[bold red]Error: Failed to convert CSV file '{apk_list}'[/bold red]")
                raise typer.Exit(code=1)

    # Parse dates
    data_start: datetime = datetime.strptime(date_start, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    data_end: datetime = datetime.strptime(date_end, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

    # Create analyzer instance
    console.print("\n[bold cyan]Starting APK Survey Analysis...[/bold cyan]\n")

    # Load and filter data
    try:
        import polars as pl
        df = pl.read_ipc(processed_apk_list_path)

        # Convert vt_scan_date to datetime if it's a string
        if df["vt_scan_date"].dtype == pl.Utf8:
            df = df.with_columns(
                pl.col("vt_scan_date").str.strptime(pl.Datetime, "%Y-%m-%d %H:%M:%S").dt.replace_time_zone("UTC")
            )

        # Apply date filter
        df = df.filter(
            (pl.col("vt_scan_date").is_not_null()) &
            (pl.col("vt_scan_date") >= data_start) &
            (pl.col("vt_scan_date") <= data_end)
        )

        # Split into malware and cleanware
        malware_df = df.filter(
            (pl.col("vt_detection").is_not_null()) &
            (pl.col("vt_detection") >= malware_threshold)
        )

        cleanware_df = df.filter(
            (pl.col("vt_detection").is_not_null()) &
            (pl.col("vt_detection") == 0) &  # Clean apps have 0 detections
            (pl.col("markets").is_not_null())
        )

        # Apply Google Play Store filter if enabled in settings
        if settings.GOOGLE_PLAY_ONLY:
            cleanware_df = cleanware_df.filter(
                pl.col("markets").str.strip_chars() == "play.google.com"  # Only Google Play Store apps
            )

        # Display summary statistics
        summary_table = Table(title="APK Sample Analysis Summary", box=box.ROUNDED)
        summary_table.add_column("Category", style="cyan")
        summary_table.add_column("Available", justify="right", style="green")
        summary_table.add_column("Requested", justify="right", style="yellow")
        summary_table.add_column("Percentage", justify="right", style="magenta")

        total_malware = len(malware_df)
        total_cleanware = len(cleanware_df)

        malware_pct = min(100, (n_malware / total_malware * 100)) if total_malware > 0 else 0
        cleanware_pct = min(100, (n_cleanware / total_cleanware * 100)) if total_cleanware > 0 else 0

        summary_table.add_row(
            "Malware",
            f"{total_malware:,}",
            f"{min(n_malware, total_malware):,}",
            f"{malware_pct:.1f}%"
        )
        summary_table.add_row(
            "Cleanware",
            f"{total_cleanware:,}",
            f"{min(n_cleanware, total_cleanware):,}",
            f"{cleanware_pct:.1f}%"
        )

        console.print(summary_table)
        console.print()

        # Show temporal distribution
        if show_distribution:
            console.print("[bold cyan]Temporal Distribution of Samples:[/bold cyan]\n")

            # Validate granularity
            if distribution_granularity not in ["year", "quarter", "month"]:
                console.print(f"[yellow]Warning: Invalid granularity '{distribution_granularity}'. Using 'year'.[/yellow]")
                distribution_granularity = "year"

            if "vt_scan_date" in df.columns:
                # Add temporal columns based on granularity
                if distribution_granularity == "year":
                    df_with_time = df.with_columns(
                        pl.col("vt_scan_date").dt.year().alias("period")
                    )
                    title = "Yearly Distribution"
                    period_label = "Year"

                elif distribution_granularity == "quarter":
                    df_with_time = df.with_columns([
                        pl.col("vt_scan_date").dt.year().alias("year"),
                        pl.col("vt_scan_date").dt.quarter().alias("quarter")
                    ]).with_columns(
                        pl.format("{}-Q{}", pl.col("year"), pl.col("quarter")).alias("period")
                    )
                    title = "Quarterly Distribution"
                    period_label = "Quarter"

                else:  # month
                    df_with_time = df.with_columns([
                        pl.col("vt_scan_date").dt.year().alias("year"),
                        pl.col("vt_scan_date").dt.month().alias("month")
                    ]).with_columns(
                        (pl.col("year").cast(pl.Utf8) + "-" +
                         pl.col("month").cast(pl.Utf8).str.pad_start(2, "0")).alias("period")
                    )
                    title = "Monthly Distribution"
                    period_label = "Month"

                # Group by period and calculate distribution
                if settings.GOOGLE_PLAY_ONLY:
                    cleanware_filter = ((pl.col("vt_detection") == 0) &
                                       (pl.col("markets").str.strip_chars() == "play.google.com"))
                else:
                    cleanware_filter = ((pl.col("vt_detection") == 0) &
                                       pl.col("markets").is_not_null())

                period_dist = df_with_time.group_by("period").agg([
                    pl.col("sha256").count().alias("total"),
                    (pl.col("vt_detection") >= malware_threshold).sum().alias("malware"),
                    cleanware_filter.sum().alias("cleanware")
                ]).sort("period")

                # Create distribution table
                dist_table = Table(title=title, box=box.SIMPLE)
                dist_table.add_column(period_label, style="cyan")
                dist_table.add_column("Total", justify="right")
                dist_table.add_column("Malware", justify="right", style="red")
                dist_table.add_column("Cleanware", justify="right", style="green")

                # Get all rows
                rows = list(period_dist.iter_rows(named=True))

                for row in rows:
                    dist_table.add_row(
                        str(row["period"]),
                        f"{row['total']:,}",
                        f"{row['malware']:,}",
                        f"{row['cleanware']:,}"
                    )

                console.print(dist_table)
                console.print()

        # Export hash lists if requested
        if export_hashes:
            console.print(f"\n[bold cyan]Exporting hash lists to {export_hashes}...[/bold cyan]")

            # Sample the data
            sampled_malware = malware_df.sample(n=min(n_malware, len(malware_df)), shuffle=True)
            sampled_cleanware = cleanware_df.sample(n=min(n_cleanware, len(cleanware_df)), shuffle=True)

            # Combine and add labels
            export_df = pl.concat([
                sampled_malware.with_columns(pl.lit("malware").alias("classification")),
                sampled_cleanware.with_columns(pl.lit("cleanware").alias("classification"))
            ])

            # Select relevant columns and export
            export_df = export_df.select([
                "sha256",
                "classification",
                "vt_detection",
                "vt_scan_date",
                "apk_size",
                "pkg_name"
            ])

            export_df.write_csv(export_hashes)
            console.print(f"[green]Successfully exported {len(export_df)} hash entries to {export_hashes}[/green]")

        # Size estimation
        console.print("\n[bold cyan]Estimated Download Size:[/bold cyan]\n")

        # Calculate average sizes
        avg_malware_size = malware_df["apk_size"].mean() if "apk_size" in malware_df.columns and len(malware_df) > 0 else 0
        avg_cleanware_size = cleanware_df["apk_size"].mean() if "apk_size" in cleanware_df.columns and len(cleanware_df) > 0 else 0

        est_malware_total = avg_malware_size * min(n_malware, total_malware) / (1024 * 1024)  # Convert to MB
        est_cleanware_total = avg_cleanware_size * min(n_cleanware, total_cleanware) / (1024 * 1024)
        est_total = est_malware_total + est_cleanware_total

        size_table = Table(title="Estimated Download Sizes", box=box.SIMPLE)
        size_table.add_column("Category", style="cyan")
        size_table.add_column("Average Size", justify="right")
        size_table.add_column("Total Size", justify="right", style="yellow")

        size_table.add_row(
            "Malware",
            f"{avg_malware_size / (1024 * 1024):.2f} MB",
            f"{est_malware_total:.2f} MB"
        )
        size_table.add_row(
            "Cleanware",
            f"{avg_cleanware_size / (1024 * 1024):.2f} MB",
            f"{est_cleanware_total:.2f} MB"
        )
        size_table.add_row(
            "[bold]Total[/bold]",
            "",
            f"[bold]{est_total:.2f} MB[/bold]"
        )

        console.print(size_table)
        console.print()

        # Final recommendations
        if total_malware < n_malware or total_cleanware < n_cleanware:
            console.print("[yellow]Warning: Not enough samples available for your criteria.[/yellow]")
            if total_malware < n_malware:
                console.print(f"  - Malware: Only {total_malware} available, requested {n_malware}")
            if total_cleanware < n_cleanware:
                console.print(f"  - Cleanware: Only {total_cleanware} available, requested {n_cleanware}")
            console.print("\nConsider:")
            console.print("  - Expanding the date range")
            console.print("  - Adjusting the malware threshold")
            console.print("  - Using a different APK list")
        else:
            console.print("[green]Sufficient samples available for your criteria![/green]")
            console.print(f"\nRun 'download' command with the same parameters to start downloading.")

    except Exception as e:
        console.print(f"[bold red]Error during analysis: {e}[/bold red]")
        raise typer.Exit(code=1)

if __name__ == "__main__":
    app()