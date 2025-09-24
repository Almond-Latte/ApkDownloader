# ApkDownloader

![Static Badge](https://img.shields.io/badge/Python-3.13-blue) ![VirusTotal](https://img.shields.io/badge/AndroZoo-API-orange)

This script allows you to easily download APK files from a list of hash values using the [AndroZoo API](https://androzoo.uni.lu/).

The APK hash list uses [Lists of APKs](https://androzoo.uni.lu/lists) published by AndroZoo.

[**日本語版はこちら**](README-ja.md)

## 🚀 Features

- **Easy APK Retrieval:** Easily obtain APK files using the AndroZoo API.
- **Automation:** Automatically retrieve APK files based on the hash value list ([Lists of APKs](https://androzoo.uni.lu/lists)).
- **Rich CLI Display:** Utilizes the `rich` library for a GUI-like output of the download status.
- **Parallel Downloads:** Enables parallel downloads through multithreading.
  - The number of parallel downloads can be configured according to your environment.
- **`vt_detection` Threshold Setting:** Set the VirusTotal detection threshold for considering an APK as malware. Downloads malware with a detection count of **at least** the specified threshold.
- **`vt_scan_date` Threshold Setting:** Set the latest scan date threshold on VirusTotal for considering an APK as malware. Downloads APKs scanned **after** the specified date.
- **Sample Count Specification:** Specify the number of benign applications and malware samples that meet the criteria.
- **Google Play Store Filtering:** Option to filter benign samples to only those from Google Play Store (configurable via `collection.google_play_only` in config.yaml).
- **Filtering Result Caching:** With around 23 million records published by AndroZoo, filtering can be time-consuming. Cache the results of executed conditions to reduce filtering execution time to less than a second.
- **Log Output:** Outputs execution logs to the `log` directory. Log names are recorded in Japan Standard Time.
- **Data Storage:** Saves cleanware and malware separately in the `Downloads` directory.

## Usage

This is suitable for wide-ranging collection of APKs rather than downloading from specific hash values.

## 📦 Installation

Clone from GitHub and install the required packages.

### Using uv (Recommended)
```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
uv sync
cp .env.sample .env
```

### Using pip
```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
pip install -r requirements.txt
cp .env.sample .env
```

## 🔑 Configuration

### 1. API Key Setup
In the `.env` file, set your AndroZoo API key:

```bash
# .env
API_KEY = 'YOUR_ANDROZOO_API_KEY'
```

> [!NOTE]
> If you don't have an AndroZoo API Key, obtain one by following [AndroZoo Access](https://androzoo.uni.lu/access).

### 2. Configuration File Setup
Copy the example configuration file and customize it:

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml` to customize the default settings:

```yaml
# config.yaml
# Sample Collection Settings
collection:
  min_detections_for_malware: 5  # VirusTotal detection threshold
  benign_samples: 1000            # Default number of clean samples
  malware_samples: 500             # Default number of malware samples
  google_play_only: true           # Filter benign samples to Google Play Store only

# Filtering Period
filtering:
  date_from: "2021-04-01 00:00:00"   # Start date for filtering
  date_until: "2024-12-31 23:59:59"  # End date for filtering

# Performance Settings
performance:
  parallel_downloads: 12           # Number of concurrent downloads

# Behavior Options
behavior:
  skip_hash_verification: false    # Set to true to skip SHA256 verification
  random_seed: 42                  # Seed for reproducibility (null for random)
```

> [!IMPORTANT]
> There are restrictions on the number of parallel downloads. Be careful not to overload AndroZoo. Please check the [AndroZoo API Documentation](https://androzoo.uni.lu/api_doc).

## ▶ Execution

### Survey Mode (Analyze before downloading)
```bash
# Analyze samples without downloading
uv run python src/ApkDownloader.py survey --n-cleanware 1000 --n-malware 500

# Export hash list for analysis
uv run python src/ApkDownloader.py survey --export-hashes analysis.csv

# Survey with custom date range
uv run python src/ApkDownloader.py survey \
    --date-start "2023-01-01 00:00:00" \
    --date-end "2024-12-31 23:59:59" \
    --export-hashes survey_results.csv
```

### Download Mode
```bash
# Basic download
uv run python src/ApkDownloader.py download --apk-list latest.csv --n-cleanware 100 --n-malware 50

# Using python directly
python src/ApkDownloader.py download --apk-list latest.csv --n-cleanware 100 --n-malware 50
```

### Advanced Usage with Custom Parameters
```bash
# First, survey to check availability
python src/ApkDownloader.py survey \
    --apk-list latest.csv \
    --n-cleanware 2000 \
    --n-malware 1000 \
    --date-start "2023-01-01 00:00:00" \
    --date-end "2024-12-01 00:00:00" \
    --malware-threshold 10 \
    --export-hashes candidates.csv

# Then download if satisfied with results
python src/ApkDownloader.py download \
    --apk-list latest.csv \
    --n-cleanware 2000 \
    --n-malware 1000 \
    --date-start "2023-01-01 00:00:00" \
    --date-end "2024-12-01 00:00:00" \
    --malware-threshold 10 \
    --verify-hash
```

### Commands

| Command | Description |
|---------|-------------|
| `survey` | Analyze APK samples without downloading. Shows statistics, distribution, and can export hash lists |
| `download` | Download APK files based on specified criteria |

### Command Line Options

| Option | Description | Default (from config.yaml) | Commands |
| `--apk-list` | Path to APK list (CSV or Feather file) | Value from config.yaml | Both |
| `--n-cleanware` | Number of cleanware samples | benign_samples value | Both |
| `--n-malware` | Number of malware samples | malware_samples value | Both |
| `--date-start` | Start date for filtering (YYYY-MM-DD HH:MM:SS) | date_from value | Both |
| `--date-end` | End date for filtering (YYYY-MM-DD HH:MM:SS) | date_until value | Both |
| `--malware-threshold` | VirusTotal detection threshold (0-100) | min_detections_for_malware value | Both |
| `--export-hashes` | Export hash list to CSV file | None | survey |
| `--show-distribution` | Show temporal distribution | True | survey |
| `--distribution-granularity` | Time period granularity (year/quarter/month) | year | survey |
| `--download-dir` | Directory to save downloaded APKs | ./downloads | download |
| `--random-seed` | Seed for reproducibility | 42 | download |
| `--verify-hash` | Verify hash of existing files | False | download |

It will automatically set up logging, create directories, and start downloading APKs.

![state of progress](https://github.com/Almond-Latte/ApkDownloader/assets/147462539/ee5924a3-1f2b-400a-85e8-3b82c0139665)

To interrupt execution, press `Ctrl + C`. The currently downloading APK will be interrupted, and incompletely downloaded APKs will be deleted.

## 📁 Directory Structure

```
downloads/
├── cleanware/     # Benign APK files
└── malware/       # Malicious APK files

logs/              # Execution logs

_cache/            # Filtered data cache
```

## 🔧 Development

### Running Tests
```bash
uv run ruff check src/
uv run pyright src/
```

### Code Formatting
```bash
uv run ruff format src/
```

🙏 Have a great security life! If you have any questions or feedback, feel free to post them on [Issues](https://github.com/Almond-Latte/ApkDownloader/issues).