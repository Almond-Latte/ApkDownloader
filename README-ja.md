# ApkDownloader

![Static Badge](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue) ![VirusTotal](https://img.shields.io/badge/AndroZoo-API-orange)

このスクリプトは [AndroZoo API](https://androzoo.uni.lu/) を用いて、ハッシュ値リストから簡単にAPKファイルをダウンロードすることができます。

APKハッシュ値リストはAndroZooが公開している [Lists of APKs](https://androzoo.uni.lu/lists) を使用します。


## 🚀 特徴

- **APKファイルの簡単取得:** AndroZoo API を利用して、簡単にAPKファイルを取得できます。
- **自動化**: ハッシュ値リスト([Lists of APKs](https://androzoo.uni.lu/lists))をもとに、自動的にAPKファイルを取得します。
- **リッチなCLI表示**: `rich`ライブラリを採用し、ダウンロード状況をまるでGUIかのように出力します。
- **並列ダウンロード**: マルチスレッド処理により、並列ダウンロードを可能にします。
  - 並列ダウンロード数の設定ができます。各環境に合わせて設定してください。

- **`vt_detection`のしきい値設定**: マルウェアとして採用するAPKのVirusTotal検知数のしきい値を設定できます。指定した検知数**以上**のマルウェアをダウンロードします。
- **`vt_scan_date`のしきい値設定**: マルウェアとして採用するAPKのVirusTotal最新スキャン日時のしきい値を設定できます。指定した日時**以降**のAPKをダウンロードします。
- **検体数指定**: 条件に当てはまる良性アプリケーション、マルウェアの収集検体数を指定することができます。 
- **フィルタリング結果のキャッシュ化**: AndroZooが公表しているレコードは2300万レコードほどあり、上記フィルタリングに時間が掛かります。一度実行した条件のものはキャッシュ化することでフィルタリング実行時間を1秒未満に削減します。
- **ログ出力**: `log` ディレクトリに実行ログを出力。ログ名は日本標準時で記録されます。
- **データ保存**: `Downloads` ディレクトリに、良性アプリケーションとマルウェアを分けて保存します。

## 用途

特定の決まっているハッシュ値を元にダウンロードするのではなく、APKを無差別に広く収集することに適しています。

## 📦 インストール

GitHubからクローンし、必要なパッケージをインストールしてください。

```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
pip3 install -r requirements.txt
mv .env.sample .env
```

## 🔑 APIキーとハッシュ値リストの設定

`.env` ファイルにAndroZooのAPIキーと、調べたいファイルのハッシュ値リストファイルのパスを記述してください。

> [!NOTE]
> AndroZoo API Keyを取得していない場合は、[AndroZoo Access](https://androzoo.uni.lu/access)に従いAPI Keyを取得してください。

例えば、API Keyが`SAMPLE_API_KEY` , 使用するハッシュ値リストが `latest.csv`であり、`2023-01-01`以降に最新スキャンがされたAPKのうち良性アプリケーションを`2000`, 検知数`4`以上のものをマルウェアとして`1000`件, 並列に`8`スレッドでダウンロードする場合は以下のように設定します。

 ```bash:.env
# General Settings
API_KEY = 'SAMPLE_APK_KEY'
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
>
> 並列ダウンロード数には制約があります。AndroZooに負荷をかけてしまわぬようご注意ください。必ず [AndroZoo API Documentation](https://androzoo.uni.lu/api_doc) をご確認ください。



## ▶ 実行方法

下記のコマンドでスクリプトを実行します。

```bash
python3 ApkDownloader.py
```

![state of progress](https://github.com/Almond-Latte/ApkDownloader/assets/147462539/ee5924a3-1f2b-400a-85e8-3b82c0139665)

自動でログの設定、ディレクトリ作成、APKのダウンロードが開始されます。

実行中断する際には`Ctrl + C`を押してください。現在ダウンロード中のAPKは中断され、不完全にダウンロードしたAPKは削除されます。

🙏 よいセキュリティライフを！
質問やフィードバックがある場合は、お気軽に[Issues](https://github.com/almond-latte/fetching-virustotal-file-report/issues)に投稿してください。
