"""Configuration management for APK Downloader."""

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich import box


@dataclass
class DownloadConfig:
    """Configuration for download command."""
    api_key: str
    apk_list: Path
    download_dir: Path
    n_cleanware: int
    n_malware: int
    date_start: datetime
    date_end: datetime
    malware_threshold: int
    verify_hash: bool
    random_seed: Optional[int]
    concurrent_downloads: int
    cache_dir: Path
    log_dir: Path
    export_hashes: Optional[Path] = None

    @classmethod
    def from_args(cls, **kwargs):
        """Create config from command arguments."""
        # Parse dates
        date_start = datetime.strptime(kwargs['date_start'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        date_end = datetime.strptime(kwargs['date_end'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        return cls(
            api_key=kwargs['api_key'],
            apk_list=kwargs['apk_list'],
            download_dir=kwargs['download_dir'],
            n_cleanware=kwargs['n_cleanware'],
            n_malware=kwargs['n_malware'],
            date_start=date_start,
            date_end=date_end,
            malware_threshold=kwargs['malware_threshold'],
            verify_hash=kwargs['verify_hash'],
            random_seed=kwargs.get('random_seed'),
            concurrent_downloads=kwargs['concurrent_downloads'],
            cache_dir=kwargs['cache_dir'],
            log_dir=kwargs['log_dir'],
            export_hashes=kwargs.get('export_hashes')
        )

    def display(self, console: Console) -> None:
        """Display configuration as a table."""
        console.print("\n[bold cyan]Download Configuration:[/bold cyan]")
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("APK List", str(self.apk_list))
        table.add_row("Download Directory", str(self.download_dir))
        table.add_row("Cleanware Samples", f"{self.n_cleanware:,}")
        table.add_row("Malware Samples", f"{self.n_malware:,}")
        table.add_row("Date Range", f"{self.date_start.strftime('%Y-%m-%d %H:%M:%S')} to {self.date_end.strftime('%Y-%m-%d %H:%M:%S')}")
        table.add_row("Malware Threshold", f"{self.malware_threshold}")
        table.add_row("Hash Verification", "Enabled" if self.verify_hash else "Disabled")
        table.add_row("Random Seed", str(self.random_seed) if self.random_seed else "Not set")
        table.add_row("Concurrent Downloads", str(self.concurrent_downloads))
        if self.export_hashes:
            table.add_row("Export Hashes To", str(self.export_hashes))

        console.print(table)
        console.print()


@dataclass
class SurveyConfig:
    """Configuration for survey command."""
    api_key: str
    apk_list: Path
    n_cleanware: int
    n_malware: int
    date_start: datetime
    date_end: datetime
    malware_threshold: int
    random_seed: Optional[int]
    export_hashes: Optional[Path]
    show_distribution: bool
    distribution_granularity: str

    @classmethod
    def from_args(cls, **kwargs):
        """Create config from command arguments."""
        # Parse dates
        date_start = datetime.strptime(kwargs['date_start'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        date_end = datetime.strptime(kwargs['date_end'], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)

        return cls(
            api_key=kwargs['api_key'],
            apk_list=kwargs['apk_list'],
            n_cleanware=kwargs['n_cleanware'],
            n_malware=kwargs['n_malware'],
            date_start=date_start,
            date_end=date_end,
            malware_threshold=kwargs['malware_threshold'],
            random_seed=kwargs.get('random_seed'),
            export_hashes=kwargs.get('export_hashes'),
            show_distribution=kwargs.get('show_distribution', True),
            distribution_granularity=kwargs.get('distribution_granularity', 'year')
        )

    def display(self, console: Console) -> None:
        """Display configuration as a table."""
        console.print("\n[bold cyan]Survey Configuration:[/bold cyan]")
        table = Table(box=box.ROUNDED, show_header=False)
        table.add_column("Parameter", style="cyan")
        table.add_column("Value", style="yellow")

        table.add_row("APK List", str(self.apk_list))
        table.add_row("Cleanware Samples", f"{self.n_cleanware:,}")
        table.add_row("Malware Samples", f"{self.n_malware:,}")
        table.add_row("Date Range", f"{self.date_start.strftime('%Y-%m-%d %H:%M:%S')} to {self.date_end.strftime('%Y-%m-%d %H:%M:%S')}")
        table.add_row("Malware Threshold", f"{self.malware_threshold}")
        table.add_row("Random Seed", str(self.random_seed) if self.random_seed else "Not set")
        if self.export_hashes:
            table.add_row("Export Hashes To", str(self.export_hashes))
        if self.show_distribution:
            table.add_row("Distribution", f"Show by {self.distribution_granularity}")

        console.print(table)
        console.print()


class ConfigManager:
    """Manages configurations for APK Downloader commands."""

    @staticmethod
    def create_download_config(**kwargs) -> DownloadConfig:
        """Create and validate download configuration."""
        config = DownloadConfig.from_args(**kwargs)
        ConfigManager._validate_common_config(config)

        # Download-specific validations
        if not config.download_dir.exists():
            config.download_dir.mkdir(parents=True, exist_ok=True)

        return config

    @staticmethod
    def create_survey_config(**kwargs) -> SurveyConfig:
        """Create and validate survey configuration."""
        config = SurveyConfig.from_args(**kwargs)
        ConfigManager._validate_common_config(config)
        return config

    @staticmethod
    def _validate_common_config(config):
        """Validate common configuration parameters."""
        # Date validation
        if config.date_start >= config.date_end:
            raise ValueError("Start date must be before end date")

        # Threshold validation
        if not 0 <= config.malware_threshold <= 100:
            raise ValueError("Malware threshold must be between 0 and 100")

        # Sample count validation
        if config.n_cleanware < 1 or config.n_malware < 1:
            raise ValueError("Sample counts must be at least 1")

        # APK list validation
        if not config.apk_list.exists():
            raise FileNotFoundError(f"APK list file not found: {config.apk_list}")