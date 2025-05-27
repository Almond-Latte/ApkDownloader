from typing import Any, Dict
from datetime import datetime
from pathlib import Path # Add Path import
import polars as pl # Add polars import
import hashlib # Add hashlib import

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

def convert_csv_to_feather(csv_path: Path, feather_path: Path) -> bool:
    """Converts a CSV file to a Feather file.

    Args:
        csv_path: Path to the input CSV file.
        feather_path: Path to save the output Feather file.

    Returns:
        True if conversion was successful, False otherwise.
    """
    try:
        # Ensure the parent directory for the feather file exists
        feather_path.parent.mkdir(parents=True, exist_ok=True)
        
        df = pl.read_csv(csv_path)
        df.write_ipc(feather_path)
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