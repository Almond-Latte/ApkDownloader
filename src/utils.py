import hashlib  # Add hashlib import
import json
import os
from datetime import datetime
from pathlib import Path  # Add Path import
from typing import Any, Dict, Optional

import polars as pl  # Add polars import

# Type alias for JSON-like data structure
type Json = Dict[str, Any]

def format_size(size_bytes: int) -> str:
    """Converts a size in bytes to a human-readable string (KB, MB, GB)."""
    if size_bytes >= (1024 ** 3):
        return f"{size_bytes / (1024 ** 3):.2f} GB"
    elif size_bytes >= (1024 ** 2):
        return f"{size_bytes / (1024 ** 2):.2f} MB"
    elif size_bytes >= 1024:
        return f"{size_bytes / 1024:.2f} KB"
    return f"{size_bytes} bytes"

def make_json_serializable(data: Json) -> Json:
    """Converts datetime objects within a dictionary to ISO strings for JSON serialization."""
    serializable_data = {}
    for key, value in data.items():
        if isinstance(value, datetime):
            serializable_data[key] = value.isoformat()
        else:
            serializable_data[key] = value
    return serializable_data

def convert_csv_to_feather(csv_path: Path, feather_path: Path, force: bool = False) -> bool:
    """Converts a CSV file to a Feather file with metadata tracking.

    Args:
        csv_path: Path to the input CSV file.
        feather_path: Path to save the output Feather file.
        force: If True, force conversion even if valid cache exists.

    Returns:
        True if conversion was successful, False otherwise.
    """
    try:
        # Check if we need to convert (unless forced)
        if not force and is_feather_cache_valid(csv_path, feather_path):
            return True

        # Ensure the parent directory for the feather file exists
        feather_path.parent.mkdir(parents=True, exist_ok=True)

        df = pl.read_csv(csv_path)
        df.write_ipc(feather_path)

        # Save metadata after successful conversion
        save_feather_metadata(csv_path, feather_path)

        return True
    except pl.exceptions.PolarsError as e:
        # Consider logging this error if a logger is available/passed
        print(f"Polars error during CSV to Feather conversion: {e}")
        return False
    except Exception as e:
        # Consider logging this error
        print(f"An unexpected error occurred during CSV to Feather conversion: {e}")
        return False

def calculate_sha256(file_path: Path) -> str:
    """Calculates the SHA256 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        The hex digest of the SHA256 hash.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            # Read and update hash string value in blocks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:
        # Handle file not found or other I/O errors
        return ""


def get_metadata_path(feather_path: Path) -> Path:
    """Get the path for the metadata file associated with a Feather file."""
    return feather_path.with_suffix('.feather.meta')


def save_feather_metadata(csv_path: Path, feather_path: Path) -> None:
    """Save metadata about the CSV to Feather conversion.

    Args:
        csv_path: Path to the source CSV file.
        feather_path: Path to the generated Feather file.
    """
    metadata = {
        'csv_path': str(csv_path),
        'csv_sha256': calculate_sha256(csv_path),
        'csv_size': csv_path.stat().st_size,
        'csv_mtime': csv_path.stat().st_mtime,
        'conversion_time': datetime.now().isoformat(),
        'feather_path': str(feather_path)
    }

    metadata_path = get_metadata_path(feather_path)
    try:
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
    except IOError as e:
        print(f"Warning: Could not save metadata file: {e}")


def is_feather_cache_valid(csv_path: Path, feather_path: Path) -> bool:
    """Check if the Feather cache is valid for the given CSV file.

    Args:
        csv_path: Path to the CSV file.
        feather_path: Path to the Feather file.

    Returns:
        True if the Feather file exists and is up-to-date, False otherwise.
    """
    # Check if Feather file exists
    if not feather_path.exists():
        return False

    # Check if metadata file exists
    metadata_path = get_metadata_path(feather_path)
    if not metadata_path.exists():
        return False

    try:
        # Load metadata
        with open(metadata_path, 'r') as f:
            metadata = json.load(f)

        # Check if CSV path matches
        if metadata.get('csv_path') != str(csv_path):
            return False

        # Check CSV modification time
        current_mtime = csv_path.stat().st_mtime
        if abs(current_mtime - metadata.get('csv_mtime', 0)) > 0.1:  # Allow small float differences
            print(f"CSV file has been modified since Feather cache was created")
            return False

        # Check CSV size
        current_size = csv_path.stat().st_size
        if current_size != metadata.get('csv_size', 0):
            print(f"CSV file size has changed since Feather cache was created")
            return False

        # Optionally check SHA256 (more thorough but slower)
        # Uncomment the following lines for hash verification
        # current_sha256 = calculate_sha256(csv_path)
        # if current_sha256 != metadata.get('csv_sha256', ''):
        #     print(f"CSV file content has changed since Feather cache was created")
        #     return False

        return True

    except (IOError, json.JSONDecodeError, KeyError) as e:
        print(f"Warning: Could not validate metadata: {e}")
        return False