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

### 2. Default Settings (Optional)
Default settings are managed in `config.yaml`. You can customize these defaults:

```yaml
# config.yaml
# Sample Selection
samples:
  malware_threshold: 4        # VirusTotal detection count threshold
  default_cleanware_count: 1000
  default_malware_count: 500

# Date Range
date_range:
  start: "2022-04-01 00:00:00"
  end: "2024-12-01 00:00:00"

# Performance
performance:
  concurrent_downloads: 12
```

> [!IMPORTANT]
> There are restrictions on the number of parallel downloads. Be careful not to overload AndroZoo. Please check the [AndroZoo API Documentation](https://androzoo.uni.lu/api_doc).

## ▶ Execution

### Basic Usage
```bash
# Using uv
uv run python src/ApkDownloader.py --apk-list latest.csv --n-cleanware 100 --n-malware 50

# Using python directly
python src/ApkDownloader.py --apk-list latest.csv --n-cleanware 100 --n-malware 50
```

### Advanced Usage with Custom Parameters
```bash
python src/ApkDownloader.py \
    --apk-list latest.csv \
    --n-cleanware 2000 \
    --n-malware 1000 \
    --date-start "2023-01-01 00:00:00" \
    --date-end "2024-12-01 00:00:00" \
    --malware-threshold 10 \
    --verify-hash
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `--apk-list` | Path to APK list (CSV or Feather file) | Required |
| `--n-cleanware` | Number of cleanware samples to download | 1000 |
| `--n-malware` | Number of malware samples to download | 500 |
| `--date-start` | Start date for filtering (YYYY-MM-DD HH:MM:SS) | 2022-04-01 00:00:00 |
| `--date-end` | End date for filtering (YYYY-MM-DD HH:MM:SS) | 2024-12-01 00:00:00 |
| `--malware-threshold` | VirusTotal detection threshold (0-100) | 4 |
| `--download-dir` | Directory to save downloaded APKs | ./downloads |
| `--random-seed` | Seed for reproducibility | None |
| `--verify-hash` | Verify hash of existing files | False |

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