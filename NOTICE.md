# 出典・第三者通知

## 参照実装

[sh1ma/wanimochi-tv](https://github.com/sh1ma/wanimochi-tv) — Copyright (c) 2026 sh1ma — MIT License。
認証・B-CAS通信・MJ111制御・TS処理等の参照元です。
上流の著作権表示とMIT許諾文を `LICENSE` に記載しています。参照したソースのコミットIDは未記録です。
Windows向けのUSB処理を実装し、Intel Mac版アプリとの動作照合に基づくロック判定・認証更新・B-CAS応答・STOP処理の変更を含みます。

上流コメントには `gvm2tv-init.c` / `gvm2tv-stream.c` への参照があります。
これらの原ファイルの公開URL・著作権者・独立したライセンスは未確認です。
上流のMITライセンスの確認は、それ以前の出典に関する権利確認を含みません。

## 別途取得する依存物

- cryptography: Apache-2.0 OR BSD-3-Clause。[上流LICENSE](https://github.com/pyca/cryptography/blob/main/LICENSE)
- PyCryptodome: BSD-2-ClauseとPublic Domainの部分。[公式ライセンス](https://www.pycryptodome.org/src/license)
- Python: PSF License等。[公式ライセンス](https://docs.python.org/3/license.html)
- WinUSB / SetupAPI: Windows同梱コンポーネントを使用し、DLLやINFをコピー配布しません。

これらの実行環境・バイナリは同梱していません。同梱して再配布する場合には、各コンポーネントのライセンス条件が適用されます。

## 同梱しないもの

I-O DATA / MAKIのDMG、Macアプリ、kext、ファームウェアには、本プロジェクトのMITライセンスは適用されません。
これらの再配布許諾は未確認であり、利用者が別途正規に入手したファイルを使用します。
録画・音声・番組画像・実機ログ・実機セッション鍵・カード識別子も同梱しません。
