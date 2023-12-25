import csv
import json
import signal
from collections.abc import Generator
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime
from enum import IntEnum, StrEnum, auto
from logging import Logger, config, getLogger
from pathlib import Path
from threading import Event
from types import FrameType
from typing import Any
from zoneinfo import ZoneInfo

import requests
from rich import box, pretty, print
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.table import Table

import settings

type Json = dict[str, str]


class StatusCode(IntEnum):
    WAITING = auto()
    PROCESSING = auto()
    SUCCESS = auto()
    STOPPED = auto()
    ERROR = auto()

    @classmethod
    def get_names(cls) -> list[str]:
        return [i.name for i in cls]

    @classmethod
    def get_values(cls) -> list[int]:
        return [i.value for i in cls]


class TodoCode(StrEnum):
    SP = "Setup Progress Display"
    REF = "Read .env File"
    SE = "Setup Event"
    SL = "Setup Logger"
    MDD = "Make Download Directory"
    CHL = "Collect Hash values in a List"
    DA = "Download APKs"

    @classmethod
    def get_names(cls) -> list[str]:
        return [i.name for i in cls]

    @classmethod
    def get_values(cls) -> list[str]:
        return [i.value for i in cls]


class ApkDownloader:
    def __init__(
        self,
    ) -> None:
        """Initialize"""
        self.init_succsess: bool = True

        # Setup Progress Display
        self.err_console = Console(stderr=True)
        pretty.install()
        self.download_progress = Progress(
            TextColumn(
                "[progress.description]{task.description}",
                justify="right",
            ),
            SpinnerColumn(),
            TextColumn("[bold blue]{task.fields[filename]}", justify="right"),
            BarColumn(),
            "[progress.percentage]{task.percentage:>3.1f}%",
            TextColumn(
                "[green]{task.completed}/{task.total}",
                justify="right",
            ),
            TransferSpeedColumn(),
            TimeElapsedColumn(),
        )
        todo_list: list[str] = TodoCode.get_values()
        self.progress_status: dict[str, StatusCode] = {
            todo: StatusCode.WAITING for todo in todo_list
        }

        self.overall_table = Table()
        with Live(
            self.generate_table(),
            auto_refresh=False,
            transient=False,
            console=self.err_console,
        ) as live:
            self.progress_status[TodoCode.SP] = StatusCode.SUCCESS

            self.progress_status[TodoCode.REF] = StatusCode.PROCESSING
            # Read .env File
            self.URL: str = settings.URL
            self.API_KEY: str = settings.API_KEY
            self.APK_LIST_PATH: Path = settings.APK_LIST_PATH
            self.MALWARE_THRESHOLD: int = settings.MALWARE_THRESHOLD
            self.N_MALWARE: int = settings.N_MALWARE
            self.N_CLEANWARE: int = settings.N_CLEANWARE
            self.DATE_AFTER: datetime = settings.DATE_AFTER
            self.CONCURRENT_DOWNLOADS = settings.CONCURRENT_DOWNLOADS
            if not self.APK_LIST_PATH.exists():
                self.err_console.log(f"APK List is not Exists:{self.APK_LIST_PATH}")
                self.progress_status[TodoCode.REF] = StatusCode.ERROR
            else:
                self.progress_status[TodoCode.REF] = StatusCode.SUCCESS

            # Generate cache filename
            self.gen_cache_filename()

            # Setup Event
            self.progress_status[TodoCode.SE] = StatusCode.PROCESSING
            live.update(self.generate_table(), refresh=True)

            try:
                self.event = Event()
                signal.signal(signal.SIGINT, self.handle_sigint)
            except Exception as e:
                self.err_console.log(e)
                self.progress_status[TodoCode.SE] = StatusCode.ERROR
            else:
                self.progress_status[TodoCode.SE] = StatusCode.SUCCESS

            live.update(self.generate_table(), refresh=True)

            # Setup Logger
            self.progress_status[TodoCode.SL] = StatusCode.PROCESSING
            live.update(self.generate_table(), refresh=True)

            self.LOG_FILE_PATH: Path = Path(settings.LOG_FILE_PATH)
            self.LOGGER_CONFIG_PATH: Path = Path(settings.LOGGER_CONFIG_PATH)

            try:
                with self.LOGGER_CONFIG_PATH.open(mode="r") as f:
                    logger_conf = json.load(f)
                    logger_conf["handlers"]["fileHandler"]["filename"] = self.LOG_FILE_PATH
                    config.dictConfig(logger_conf)
                self.logger: Logger = getLogger(__name__)
            except Exception as e:
                self.progress_status[TodoCode.SL] = StatusCode.ERROR
                self.err_console.log(e)
                self.init_succsess = False
            else:
                self.progress_status[TodoCode.SL] = StatusCode.SUCCESS

            live.update(self.generate_table(), refresh=True)

            # Make Download Directory
            self.progress_status[TodoCode.MDD] = StatusCode.PROCESSING
            live.update(self.generate_table(), refresh=True)

            self.make_download_dir()
            self.progress_status[TodoCode.MDD] = StatusCode.SUCCESS
            live.update(self.generate_table(), refresh=True)

            # Collect Hash values in a List
            self.progress_status[TodoCode.CHL] = StatusCode.PROCESSING
            live.update(self.generate_table(), refresh=True)

            self.cleanware_list, self.malware_list = self.collect_apk_hashes()

            self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
            live.update(self.generate_table(), refresh=True)

    def generate_table(self, *, download_panel: bool = False) -> Align:
        """Generate Progress Table

        Args:
        ----
            download_panel (bool, optional): If the download panel is required,
            set to True. Defaults to False.

        Returns:
        -------
            Align: Progress Table
        """
        self.overall_table = Table(box=box.SIMPLE)
        self.overall_table.add_column("ToDo")
        self.overall_table.add_column("Status")
        status_list = StatusCode.get_values()
        color_list = [
            "[gray0]WAITING",
            "[blue]PROCESSING",
            "[green]SUCCESS",
            "[red]STOPPED",
            "[red]ERROR",
        ]
        status_print: dict[int, str] = dict(zip(status_list, color_list, strict=True))
        for todo, status in self.progress_status.items():
            self.overall_table.add_row(f"{todo}", f"{status_print[status]}")
        full_table = Table.grid()
        if download_panel:
            full_table.add_row(
                Panel(
                    self.overall_table,
                    title="Overall Progress",
                    border_style="green",
                    padding=(1, 1),
                ),
                Panel(
                    self.download_progress,
                    title="Download Progress",
                    border_style="blue",
                    padding=(1, 2),
                ),
            )
        else:
            full_table.add_row(
                Panel(
                    self.overall_table,
                    title="Overall Progress",
                    border_style="green",
                    padding=(1, 1),
                ),
            )

        return Align.center(full_table, vertical="middle")

    def handle_sigint(self, signum: int, frame: FrameType | None) -> None:
        """Set event when Ctrl + C is pressed.

        Args:
        ----
            signum (int):
            frame (FrameType | None):
        """
        signame: str = signal.Signals(signum).name
        self.err_console.log(f"Signal handler called with signal {signame} ({signum}), {frame!s}")
        self.logger.warning("Signal handler called with signal %s (%d), %s", signame, signum, str(frame))
        self.event.set()

    def get_records(self) -> Generator[Json, None, None]:
        """Read Json data from APK_LIST_PATH, and Return Generator

        Yields
        ------
            Generator[Json, None, None]: Json data Generator
        """

        try:
            with self.APK_LIST_PATH.open(mode="r") as f:
                jsonl_data = csv.DictReader(f)
                yield from jsonl_data

        except Exception as e:
            self.err_console.log(e)
        finally:
            pass

    def make_download_dir(self) -> None:
        """Create a directory to store the downloaded apk

        Create a cleanware dir and a malware dir to store the downloaded
        apk filesCreate

        """
        # Create a cleanware directory
        if Path("Downloads/cleanware").exists():
            self.logger.info("Directory Exists: Downloads/cleanware, skip creating")
        else:
            Path("Downloads/cleanware").mkdir(parents=True)
            self.logger.info("Created Directory: Downloads/cleanware")

        # Create a malware directory
        if Path("Downloads/malware").exists():
            self.logger.info("Directory Exists: Downloads/malware, skip creating")
        else:
            Path("Downloads/malware").mkdir(parents=True)
            self.logger.info("Created Directory: Downloads/malware")

    @classmethod
    def has_vt_detection(cls, json_data: Json) -> bool:
        """Check to see if there is the vt_detection

        Args:
        ----
            json_data (Json): Json data representing an APK file

        Returns:
        -------
            bool: True for it has vt_detection, False otherwise.
        """

        return json_data["vt_detection"] != ""

    def is_malware(self, json_data: Json) -> bool:
        """Determine if the Json data is from malware.

        Args:
        ----
            json_data (Json): Json data for a single APK

        Returns:
        -------
            bool: True for malware, False otherwise
        """

        return int(json_data["vt_detection"]) >= self.MALWARE_THRESHOLD

    def date_filter(self, json_data: Json) -> bool:
        """Determine if the Json data is from a specified date or later

        Args:
        ----
            json_data (Json): Json data for a single APK

        Returns:
        -------
            bool: True if the Json data is after the specified date,
                False otherwise.
        """

        # Convert string to datetime
        vt_scan_date: datetime = datetime.strptime(json_data["vt_scan_date"], "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=ZoneInfo("Europe/Paris"),
        )

        return vt_scan_date >= self.DATE_AFTER

    def gen_cache_filename(self) -> None:
        """Set cache file name based on MALWARE_THRESHOLD, N_CLEANWARE,
        N_MALWARE, and DATE_AFTER information
        """

        cache_dir: Path = Path("_cache")
        info_chain: list[str] = [
            str(self.MALWARE_THRESHOLD),
            str(self.N_CLEANWARE),
            str(self.N_MALWARE),
            str(self.DATE_AFTER.year),
            str(self.DATE_AFTER.month),
            str(self.DATE_AFTER.day),
        ]
        cache_sub_dir: Path = Path("_".join(info_chain))

        # store cache file name
        self.cleanware_cache_file: Path = Path.joinpath(cache_dir, cache_sub_dir, Path("cleanware.jsonl"))
        self.malware_cache_file: Path = Path.joinpath(cache_dir, cache_sub_dir, Path("malware.jsonl"))

    def make_cache_file(self, cleanware_list: list[Json], malware_list: list[Json]) -> bool:
        """Create a cache file in jsonl format

        Args:
        ----
            cleanware_list (list[Json]): jsonl on cleanware
            malware_list (list[Json]): jsonl on malware

        Returns:
        -------
            bool: True if successful, False otherwise.
        """

        # make cache file directory
        dir_path: Path = self.cleanware_cache_file.parent
        dir_path.mkdir(parents=True)

        try:
            with self.cleanware_cache_file.open(mode="w") as f:
                f.writelines([json.dumps(json_data) + "\n" for json_data in cleanware_list])
        except Exception as e:
            self.err_console.log(e)
            self.logger.exception("Failed to create cache file. file: %s", self.cleanware_cache_file)
            return False

        try:
            with self.malware_cache_file.open(mode="w") as f:
                f.writelines([json.dumps(json_data) + "\n" for json_data in malware_list])

        except Exception as e:
            self.err_console.log(e)
            self.logger.exception("Failed to create cache file. file: %s", self.malware_cache_file)
            return False
        else:
            self.logger.info("Cache file created successfully. file: %s, %s", self.cleanware_cache_file, self.malware_cache_file)
            return True

    def read_cache_file(
        self,
    ) -> tuple[list[Json], list[Json]]:
        """Read cache files

        Returns
        -------
            tuple[list[Json], list[Json]]: returns information read from
                cache files, in the order of cleanware_list, malware_list
        """
        cleanware_list: list[Json]
        malware_list: list[Json]
        try:
            with self.cleanware_cache_file.open(mode="r") as f:
                cleanware_list = [json.loads(json_data) for json_data in f.readlines()]

            with self.malware_cache_file.open(mode="r") as f:
                malware_list = [json.loads(json_data) for json_data in f.readlines()]
        except Exception as e:
            self.err_console.log(e)
            return [], []
        else:
            self.logger.info("Cache file loaded successfully. file: %s, %s", self.cleanware_cache_file, self.malware_cache_file)
            return cleanware_list, malware_list

    def collect_apk_hashes(self) -> tuple[list[Json], list[Json]]:
        """Returns apk that matches the set conditions

        if there are cache files, return them

        Returns
        -------
            tuple[list[Json], list[Json]]: (cleanware_list, malware_list)
        """
        self.progress_status[TodoCode.CHL] = StatusCode.PROCESSING
        self.logger.info("Collecting APK Hashes...")
        # If there are cache files, return them.
        if self.cleanware_cache_file.exists() and self.malware_cache_file.exists():
            self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
            return self.read_cache_file()

        progress = Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        )
        with progress:
            cleanware_progress: TaskID = progress.add_task(
                "[green]Collecting Cleanware APK Hash Values...",
                total=self.N_CLEANWARE,
            )
            malware_progress: TaskID = progress.add_task(
                "[green]Collecting  Malware  APK Hash Values...",
                total=self.N_MALWARE,
            )

            records = self.get_records()
            malware_list: list[Json] = []
            cleanware_list: list[Json] = []
            for json_data in records:
                if self.event.is_set():
                    # When C is pressed, do nothing and return empty list
                    return [], []

                if (
                    len(cleanware_list) >= self.N_CLEANWARE
                    and len(malware_list) >= self.N_MALWARE
                ):
                    # When enough samples are collected, exit the loop
                    break
                if not self.has_vt_detection(json_data):
                    # Skip if there is no vt_detection
                    continue
                if not self.date_filter(json_data):
                    # Skip those excluded by date_filter
                    continue

                if self.is_malware(json_data):
                    if len(malware_list) < self.N_MALWARE:
                        malware_list.append(json_data)
                        progress.update(malware_progress, advance=1)
                # if it is cleanware and list is not full
                elif len(cleanware_list) < self.N_CLEANWARE:
                        cleanware_list.append(json_data)
                        progress.update(cleanware_progress, advance=1)

            progress.update(cleanware_progress, visible=False)
            progress.update(malware_progress, visible=False)
            self.logger.info("Finished collecting hash values.")

        # Keep in cache file.
        self.make_cache_file(cleanware_list, malware_list)

        self.progress_status[TodoCode.CHL] = StatusCode.SUCCESS
        return cleanware_list, malware_list

    def download_handler(
        self,
        json_data: Json,
        task_id: TaskID,
        *,
        is_malware: bool = False,
    ) -> bool:
        """Download apk based on json data.

        Args:
        ----
            json_data (Json): Json data for a single APK
            task_id (TaskID): TaskID for Progress bar
            is_malware (bool, optional): Set True if the APK is malware.
                Default to False

        Returns:
        -------
            bool: True for successful, False otherwise.
        """
        if self.event.is_set():
            # When C is pressed but the file has not yet been created,
            # do nothing and return False
            return False

        if is_malware:
            self.logger.info("Trying to Download Malware Samples: %s", json_data["sha256"])
        else:
            self.logger.info("Trying to Download Cleanware Samples: %s", json_data["sha256"])

        success: bool = True
        sub_dir: Path = Path("malware" if is_malware else "cleanware")
        filename: Path = Path(json_data["sha256"] + ".apk")
        download_file_path: Path = Path.joinpath(
            Path("Downloads"),
            sub_dir,
            filename,
        )
        if download_file_path.exists():
            return True
        params = {
            "apikey": self.API_KEY,
            "sha256": json_data["sha256"],
        }
        response = requests.get(url=self.URL, params=params, stream=True, timeout=10)
        chunk_size: int = 1024
        if response.status_code == requests.codes.ok:
            data_size: int = int(response.headers.get("content-length", 0))
            self.logger.info("Saving data as %s, size: %d" ,download_file_path.name, data_size)
            with download_file_path.open(mode="wb") as f:
                self.download_progress.start_task(task_id)
                self.download_progress.update(task_id, visible=True)
                for chunk in response.iter_content(chunk_size=chunk_size):
                    # if pressed Ctrl + C (SIGINT)
                    if self.event.is_set():
                        success = False
                        break

                    f.write(chunk)
                    # update progress bar
                    self.download_progress.update(task_id, advance=len(chunk), total=data_size)

                self.download_progress.update(task_id, visible=False)

        else:
            self.logger.error("Error: %d - %s", response.status_code, response.reason)
            success = False
        if success is False:
            # if faild to download apk, remove the file
            download_file_path.unlink(missing_ok=True)
        return success

    def download_apks(self, cleanware_list: list[Json], malware_list: list[Json]) -> None:
        """Parallel download of apks by multi-thread processing

        Args:
        ----
            cleanware_list (list[Json]): Jsonl data about cleanware APKs
                you want to download
            malware_list (list[Json]): Jsonl data about malware APKs
                you want to download
        """
        # update progress table
        self.progress_status[TodoCode.DA] = StatusCode.PROCESSING
        with Live(
            self.generate_table(),
            refresh_per_second=4,
            transient=False,
            console=self.err_console,
        ) as live:
            live.update(self.generate_table(download_panel=True))
            cleanware_futures: list[Future[Any]] = []
            malware_futures: list[Future[Any]] = []
            overall_apk_progress = self.download_progress.add_task(
                "[green]Overall Progress:",
                filename="",
                total=len(cleanware_list) + len(malware_list),
            )
            cleanware_progress = self.download_progress.add_task(
                "[green]Cleanware Download Progress:",
                filename="",
                total=len(cleanware_list),
            )
            malware_progress = self.download_progress.add_task(
                "[green]Malware Download Progress:",
                filename="",
                total=len(malware_list),
            )
            with ThreadPoolExecutor(max_workers=self.CONCURRENT_DOWNLOADS) as executor:
                # Download Cleanware APKs
                for json_data in cleanware_list:
                    task_id: TaskID = self.download_progress.add_task(
                        "Downloading",
                        filename=json_data["sha256"][:12] + "...",
                        visible=False,
                        start=False,
                    )
                    cleanware_futures.append(executor.submit(self.download_handler, json_data, task_id))
                # Download Malware APKs
                for json_data in malware_list:
                    task_id: TaskID = self.download_progress.add_task(
                        "Downloading",
                        filename=json_data["sha256"][:12] + "...",
                        visible=False,
                        start=False,
                    )
                    malware_futures.append(
                        executor.submit(self.download_handler, json_data, task_id, is_malware=True),
                    )

                # Wait for all downloads to complete
                while (
                    n_finished := sum(
                        [future.done() for future in cleanware_futures + malware_futures],
                    )
                ) < len(cleanware_futures + malware_futures):
                    self.download_progress.update(overall_apk_progress, completed=n_finished)

                    self.download_progress.update(
                        cleanware_progress,
                        completed=sum(
                            [future.done() for future in cleanware_futures],
                        ),
                    )

                    self.download_progress.update(
                        malware_progress,
                        completed=sum(
                            [future.done() for future in malware_futures],
                        ),
                    )

                self.download_progress.update(
                    overall_apk_progress,
                    completed=n_finished,
                )

            if self.event.is_set():
                self.progress_status[TodoCode.DA] = StatusCode.STOPPED
            else :
                self.progress_status[TodoCode.DA] = StatusCode.SUCCESS

            live.update(self.generate_table(download_panel=True), refresh=True)


def main() -> None:
    print(
        Align.center(
            Panel.fit(
                "[bold] APK Downloader via AndroZoo for Malware Analysis",
                title="Welcome to",
                subtitle="2023 Almond-Latte",
                padding=(4, 4),
            ),
            vertical="middle",
        ),
    )
    print("\n\n\n")
    apk_downloader = ApkDownloader()
    cleanware_list, malware_list = apk_downloader.collect_apk_hashes()
    apk_downloader.download_apks(cleanware_list, malware_list)

if __name__ == "__main__":
    main()
