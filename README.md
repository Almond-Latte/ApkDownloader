# ApkDownloader

![Static Badge](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue) ![VirusTotal](https://img.shields.io/badge/AndroZoo-API-orange)

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

```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
pip3 install -r requirements.txt
mv .env.sample .env
```
## 🔑 API Key and Hash List Configuration
In the .env file, specify your AndroZoo API key and the path to the hash list file you want to investigate.

> [!NOTE]
> If you do not have an AndroZoo API Key, obtain it by following AndroZoo Access.

For example, if the API Key is SAMPLE_API_KEY, the hash list to use is latest.csv, you want to download cleanware and detect at least 4 as malware scanned after 2023-01-01, with 2000 cleanware and 1000 malware samples, using 8 parallel threads, configure it as follows:

```bash
# General Settings
API_KEY = 'SAMPLE_API_KEY'
APK_LIST = 'latest.csv'
URL = "https://androzoo.uni.lu/api/download"

# Value of Virus Total Detection to determine if it is malware
MALWARE_THRESHOLD = 4

# Number of Samples
N_CLEANWARE = 2000
N_MALWARE = 1000

# Date Filtering
DATE_AFTER = '2023-01-01 00:00:00'

# Multi Threading
CONCURRENT_DOWNLOADS = 8
```

> [!IMPORTANT]
> There are restrictions on the number of parallel downloads. Be careful not to overload AndroZoo. Please check the AndroZoo API Documentation.

## ▶ Execution
Run the script with the following command:

```bash
python3 ApkDownloader.py
```

It will automatically set up logging, create directories, and start downloading APKs.

![state of progress](https://github.com/Almond-Latte/ApkDownloader/assets/147462539/ee5924a3-1f2b-400a-85e8-3b82c0139665)

To interrupt execution, press Ctrl + C. The currently downloading APK will be interrupted, and incompletely downloaded APKs will be deleted.

🙏 Have a great security life! If you have any questions or feedback, feel free to post them on Issues.
