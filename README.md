# GV-M2TV Windows CLI

I-O DATA GV-M2TVのチャンネル探索とMPEG-TS取得を行うWindows向けCLIツールです。
[sh1ma/wanimochi-tv](https://github.com/sh1ma/wanimochi-tv) をもとに、Windows標準のWinUSBを使用して実装しています。

## 動作要件

| 必要なもの | 用途・条件 |
| --- | --- |
| Windows 11 x64のPC | 実行環境。USBポートが必要です |
| I-O DATA GV-M2TV本体 | 対象のUSB VID:PIDは `04BB:053A` |
| 地デジを受信できるアンテナと接続ケーブル | 本体へ接続できる変換ケーブル等も含みます |
| 本体で使えるB-CASカード | GV-M2TVへ挿入します |
| Python 3.11以上とpip | `python` コマンドが利用できること。受信処理の確認環境はPython 3.13です |
| GV-M2TVサポートソフトVer.1.30のDMG、または抽出済みのファームウェア2個 | 正規に入手したサポートソフトを使用します。確認済みのDMGファイル名は `gvm2tv130.dmg` です |
| 7-Zip等の展開ソフト | DMGからファームウェアを取り出す場合に使います。以下は7-Zipの例です |
| FFmpegのffplay（任意） | TSをその場で再生したい場合に使います。探索とTSファイル保存だけなら省略できます |

DMG・ファームウェア・Python・FFmpegは同梱していません。
DMGはファームウェアの抽出に使用します。実行時に読み込むのは、下記の `.bin` 2個です。
抽出済みの2ファイルがある場合は、DMGと展開ソフトを省略できます。ファームウェアの抽出はWindows上で行えます。

## セットアップ

### 1. Pythonの依存ライブラリを入れる

プロジェクトのルートディレクトリで実行します。以下のパスは保存先に合わせて変更してください。

```powershell
cd 'C:\path\gv-m2tv-minimal'
python --version
python -m pip install -r requirements.txt
```

`cryptography` と `pycryptodome` がインストールされます。

### 2. DMGからファームウェアを取り出す

`gvm2tv130.dmg` を7-Zip等で開き、`GVM2TV_130/m2TV.app/Contents/Resources/` にある次の2ファイルを、
プロジェクト内の `firmware/` ディレクトリへコピーします。

- `mb86h57_h58_aac_idle.bin`
- `mb86h57_h58_aac_trc.bin`

PowerShellで取り出す場合の例です。DMGのパスと7-Zipの場所は実際の保存先に読み替えてください。
このコマンドも `gv-m2tv-minimal` フォルダーで実行します。

```powershell
& 'C:\Program Files\7-Zip\7z.exe' e 'C:\path\gvm2tv130.dmg' `
  'GVM2TV_130\m2TV.app\Contents\Resources\mb86h57_h58_aac_idle.bin' `
  'GVM2TV_130\m2TV.app\Contents\Resources\mb86h57_h58_aac_trc.bin' `
  '-o.\firmware'
```

`firmware/` の直下に2ファイルを配置します。

```text
gv-m2tv-minimal/
  gvm2tv.py
  ...
  firmware/
    mb86h57_h58_aac_idle.bin
    mb86h57_h58_aac_trc.bin
```

ファームウェアを別の場所へ置く場合は、各コマンドに `--firmware "X:\firmware"` を付けて指定できます。

### 3. 本体を接続してWinUSBを割り当てる

GV-M2TVへアンテナとB-CASを接続し、本体をPCのUSBポートへ挿します。
まず通常のPowerShellで、接続した機器が対象になっているか確認します。

```powershell
python install_winusb.py
```

次に**管理者として開いたPowerShell**で、同じフォルダーへ移動して実行します。

```powershell
cd 'C:\path\gv-m2tv-minimal'
python install_winusb.py --install
```

Windows同梱のWinUSBをGV-M2TVに割り当てます。既存の別ドライバがある場合は置換を拒否します。
通常の探索・受信は管理者権限不要です。以下は通常のPowerShellから実行できます。

## チャンネル探索

```powershell
python gvm2tv.py scan
python gvm2tv.py scan --channels 21,22,24-27
```

物理UHFチャンネル13〜52を探索し、`channel`・`locked`・`strength` をJSONで1行ずつ出します。
ロック判定と信号の目安であり、番組や映像の受信を保証するものではありません。
以下のコマンドの `25` は例です。受信する地域の物理チャンネル番号を指定してください。

## TS取得

```powershell
# 12秒保存
python gvm2tv.py stream --channel 25 --seconds 12 --output capture.ts
# Ctrl+Cまで保存
python gvm2tv.py stream --channel 25 --output capture.ts
```

`--output` を省略するか `-` を指定すると、バイナリTSを標準出力に送ります。
ログは標準エラーへ出します。ファイル保存には `--output` を使ってください。
外部プレイヤーへ渡す場合の例（**cmd.exeで実行**、ffplayは別途用意）：

```bat
python gvm2tv.py stream --channel 25 | ffplay -i -
```

終了コードは成功 `0`、受信失敗 `2`、エラー `1`、Ctrl+C `130` です。
同じ機器を複数プロセスから同時に使わないでください。

## 動作の概要

WinUSBでファームウェアを転送し、機器認証・B-CASカードの初期化・I2Cでの選局を行います。
USBからTSを読み、PAT/PMTを解析して本体との通信用AESを処理します。
放送の条件付きアクセス処理は本体と挿入済みカードが担います。機器認証は15秒ごとに更新します。

## 検証状況

機器制御・TS受信処理は、Windows 11 / Python 3.13でCH25の映像・音声と停止手順を確認しています。
このCLI版での実機受信、別PC・良好なアンテナ・他局・長時間受信は未検証です。
USBエラーが続く場合は受信を終了してUSBを抜き、5秒待って挿し直してください。

## ライセンス

コードは [MIT License](LICENSE) で提供します。出典・依存物・ライセンスの確認範囲は [NOTICE.md](NOTICE.md) を参照してください。
メーカーソフト、ファームウェア、録画、実機ログは同梱していません。
