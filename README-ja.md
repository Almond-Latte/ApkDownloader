# ApkDownloader

![Static Badge](https://img.shields.io/badge/Python-3.13-blue) ![VirusTotal](https://img.shields.io/badge/AndroZoo-API-orange)

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

### uvを使用する場合（推奨）
```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
uv sync
cp .env.sample .env
```

### pipを使用する場合
```sh
git clone https://github.com/Almond-Latte/ApkDownloader.git
cd ApkDownloader
pip install -r requirements.txt
cp .env.sample .env
```

## 🔑 設定

### 1. APIキーの設定
`.env` ファイルにAndroZooのAPIキーを設定してください：

```bash
# .env
API_KEY = 'YOUR_ANDROZOO_API_KEY'
```

> [!NOTE]
> AndroZoo API Keyを取得していない場合は、[AndroZoo Access](https://androzoo.uni.lu/access)に従いAPI Keyを取得してください。

### 2. デフォルト設定（オプション）
デフォルト設定は `config.yaml` で管理されています。これらのデフォルト値をカスタマイズできます：

```yaml
# config.yaml
# サンプル選択
samples:
  malware_threshold: 4        # VirusTotal検知数のしきい値
  default_cleanware_count: 1000
  default_malware_count: 500

# 日付範囲
date_range:
  start: "2022-04-01 00:00:00"
  end: "2024-12-01 00:00:00"

# パフォーマンス
performance:
  concurrent_downloads: 12
```

> [!IMPORTANT]
> 並列ダウンロード数には制約があります。AndroZooに負荷をかけてしまわぬようご注意ください。必ず [AndroZoo API Documentation](https://androzoo.uni.lu/api_doc) をご確認ください。

## ▶ 実行方法

### 基本的な使用方法
```bash
# uvを使用
uv run python src/ApkDownloader.py --apk-list latest.csv --n-cleanware 100 --n-malware 50

# pythonを直接使用
python src/ApkDownloader.py --apk-list latest.csv --n-cleanware 100 --n-malware 50
```

### カスタムパラメータを使用した高度な使用方法
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

### コマンドラインオプション

| オプション | 説明 | デフォルト |
|--------|-------------|---------|
| `--apk-list` | APKリストへのパス（CSVまたはFeatherファイル） | 必須 |
| `--n-cleanware` | ダウンロードするクリーンウェアサンプル数 | 1000 |
| `--n-malware` | ダウンロードするマルウェアサンプル数 | 500 |
| `--date-start` | フィルタリング開始日（YYYY-MM-DD HH:MM:SS） | 2022-04-01 00:00:00 |
| `--date-end` | フィルタリング終了日（YYYY-MM-DD HH:MM:SS） | 2024-12-01 00:00:00 |
| `--malware-threshold` | VirusTotal検知しきい値（0-100） | 4 |
| `--download-dir` | APK保存ディレクトリ | ./downloads |
| `--random-seed` | 再現性のためのシード値 | None |
| `--verify-hash` | 既存ファイルのハッシュ検証 | False |

自動でログの設定、ディレクトリ作成、APKのダウンロードが開始されます。

![state of progress](https://github.com/Almond-Latte/ApkDownloader/assets/147462539/ee5924a3-1f2b-400a-85e8-3b82c0139665)

実行中断する際には`Ctrl + C`を押してください。現在ダウンロード中のAPKは中断され、不完全にダウンロードしたAPKは削除されます。

## 📁 ディレクトリ構造

```
downloads/
├── cleanware/     # 良性APKファイル
└── malware/       # 悪性APKファイル

logs/              # 実行ログ

_cache/            # フィルタリングデータのキャッシュ
```

## 🔧 開発

### テストの実行
```bash
uv run ruff check src/
uv run pyright src/
```

### コードフォーマット
```bash
uv run ruff format src/
```

🙏 よいセキュリティライフを！
質問やフィードバックがある場合は、お気軽に[Issues](https://github.com/Almond-Latte/ApkDownloader/issues)に投稿してください。