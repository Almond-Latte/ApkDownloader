import json
from pathlib import Path
from typing import List, Optional, Tuple, Any
from logging import Logger
from rich.console import Console
from datetime import datetime

from utils import Json, format_size, make_json_serializable

class CacheHandler:
    def __init__(
        self,
        console: Console,
        logger: Optional[Logger],
        cache_dir: Path,
        malware_threshold: int,
        n_cleanware: int,
        n_malware: int,
        date_start: datetime,
        date_end: datetime,
    ):
        self.console = console
        self.logger = logger
        self.CACHE_DIR = cache_dir
        self.MALWARE_THRESHOLD = malware_threshold
        self.N_CLEANWARE = n_cleanware
        self.N_MALWARE = n_malware
        self.DATE_START = date_start
        self.DATE_END = date_end
        self.cleanware_cache_file: Optional[Path] = None
        self.malware_cache_file: Optional[Path] = None
        self._gen_cache_filenames()

    def _gen_cache_filenames(self) -> None:
        """Generates filenames for cache files based on current parameters."""
        info_chain: list[str] = [
            str(self.MALWARE_THRESHOLD),
            str(self.N_CLEANWARE),
            str(self.N_MALWARE),
            f"{self.DATE_START:%Y%m%d}",
            f"{self.DATE_END:%Y%m%d}",
        ]
        cache_sub_dir_name: str = "_".join(info_chain)
        cache_sub_dir: Path = self.CACHE_DIR / cache_sub_dir_name
        self.cleanware_cache_file = cache_sub_dir / "cleanware_samples.jsonl"
        self.malware_cache_file = cache_sub_dir / "malware_samples.jsonl"
        if self.logger:
            self.logger.info(f"Cache directory set to: {cache_sub_dir}")

    def make_cache_file(
        self, cleanware_samples: List[Json], malware_samples: List[Json]
    ) -> bool:
        """Saves the selected samples to cache files (JSON Lines format)."""
        if not self.cleanware_cache_file or not self.malware_cache_file:
            if self.logger:
                self.logger.error(
                    "Cache filenames not generated. Cannot make cache file."
                )
            return False

        if not cleanware_samples and not malware_samples:
            if self.logger:
                self.logger.info("No samples selected to cache.")
            return True

        cache_dir: Path = self.cleanware_cache_file.parent
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            if self.logger:
                self.logger.error(f"Failed to create cache directory {cache_dir}: {e}")
            self.console.log(
                f"[bold red]Error:[/bold red] Could not create cache directory: {e}"
            )
            return False

        try:
            with self.cleanware_cache_file.open(mode="w", encoding="utf-8") as f:
                for json_data in cleanware_samples:
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if self.logger:
                self.logger.info(
                    f"Successfully wrote {len(cleanware_samples)} cleanware samples to cache: {self.cleanware_cache_file}"
                )
        except (IOError, TypeError) as e:
            if self.logger:
                self.logger.exception(
                    f"Failed to write cleanware cache: {self.cleanware_cache_file}"
                )
            self.console.log(f"[bold red]Cleanware cache write error:[/bold red] {e}")
            return False

        try:
            with self.malware_cache_file.open(mode="w", encoding="utf-8") as f:
                for json_data in malware_samples:
                    serializable_dict = make_json_serializable(json_data)
                    f.write(json.dumps(serializable_dict) + "\n")
            if self.logger:
                self.logger.info(
                    f"Successfully wrote {len(malware_samples)} malware samples to cache: {self.malware_cache_file}"
                )
        except (IOError, TypeError) as e:
            if self.logger:
                self.logger.exception(
                    f"Failed to write malware cache: {self.malware_cache_file}"
                )
            self.console.log(f"[bold red]Malware cache write error:[/bold red] {e}")
            return False
        return True

    def read_cache_file(self) -> Optional[Tuple[List[Json], List[Json]]]:
        """Reads selected samples from existing cache files if they exist."""
        if not self.cleanware_cache_file or not self.malware_cache_file:
            if self.logger:
                self.logger.error(
                    "Cache filenames not generated. Cannot read cache file."
                )
            return None

        if (
            not self.cleanware_cache_file.exists()
            or not self.malware_cache_file.exists()
        ):
            if self.logger:
                self.logger.info("Sample cache files not found.")
            return None

        if self.logger:
            self.logger.info(
                f"Attempting to read samples from cache files in {self.cleanware_cache_file.parent}"
            )
        cleanware_list: List[Json] = []
        malware_list: List[Json] = []

        try:
            with self.cleanware_cache_file.open(mode="r", encoding="utf-8") as f:
                cleanware_list = [json.loads(line) for line in f if line.strip()]
            if self.logger:
                self.logger.info(
                    f"Successfully read {len(cleanware_list)} cleanware samples from cache: {self.cleanware_cache_file}"
                )

            with self.malware_cache_file.open(mode="r", encoding="utf-8") as f:
                malware_list = [json.loads(line) for line in f if line.strip()]
            if self.logger:
                self.logger.info(
                    f"Successfully read {len(malware_list)} malware samples from cache: {self.malware_cache_file}"
                )
            
            if len(cleanware_list) > self.N_CLEANWARE:
                if self.logger: self.logger.info(f"Cache has {len(cleanware_list)} cleanware samples, requested {self.N_CLEANWARE}. Using subset.")
                cleanware_list = cleanware_list[:self.N_CLEANWARE]
            if len(malware_list) > self.N_MALWARE:
                if self.logger: self.logger.info(f"Cache has {len(malware_list)} malware samples, requested {self.N_MALWARE}. Using subset.")
                malware_list = malware_list[:self.N_MALWARE]

            return cleanware_list, malware_list
        except (IOError, json.JSONDecodeError) as e:
            if self.logger:
                self.logger.error(f"Error reading cache files: {e}. Re-collecting hashes.")
            self.console.log(
                f"[bold red]Error reading cache files:[/bold red] {e}. Cache will be ignored."
            )
            return None
        except Exception as e:
            if self.logger:
                self.logger.exception(f"Unexpected error reading cache files: {e}")
            self.console.log(f"[bold red]Unexpected error reading cache:[/bold red] {e}")
            return None

    def calculate_total_download_size(self) -> None:
        """Calculates the total size of APKs to be downloaded using cached JSONL files."""
        self.console.print(
            "[bold blue]Estimating total download size using cache...[/bold blue]"
        )
        if not self.cleanware_cache_file or not self.malware_cache_file:
            self.console.print(
                "[bold red]Error: Cache filenames not available. Cannot calculate download size.[/bold red]"
            )
            return

        if (
            not self.cleanware_cache_file.exists()
            or not self.malware_cache_file.exists()
        ):
            self.console.print(
                "[bold red]Error: Cache files not found. Cannot calculate download size.[/bold red]"
            )
            return

        try:
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

            self.console.print(
                f"[green]Estimated total size of malware to download:[/green] {format_size(malware_size_bytes)}"
            )
            self.console.print(
                f"[green]Estimated total size of cleanware to download:[/green] {format_size(cleanware_size_bytes)}"
            )
            self.console.print(
                f"[bold green]Estimated total download size:[/bold green] {format_size(total_size_bytes)}"
            )

        except (IOError, json.JSONDecodeError) as e:
            if self.logger:
                self.logger.error(
                    f"Error reading cache files for size estimation: {e}"
                )
            self.console.print(
                f"[bold red]Error reading cache files for size estimation:[/bold red] {e}"
            )
        except Exception as e:
            if self.logger:
                self.logger.exception(f"Unexpected error during size estimation: {e}")
            self.console.print(
                f"[bold red]Unexpected error during size estimation:[/bold red] {e}"
            )