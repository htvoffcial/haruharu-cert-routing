# HCRT Rust 版

`../hcrt.py`（Python 版）の Rust 移植。仕様の正本は上位の `README.md` と
`config.example.hcrt` で、設定ファイル・証明書・サイトは Python 版と
そのまま共有できる。

## ビルドと起動

```
cargo build --release
./target/release/hcrt ../config.hcrt   # 引数省略時は ./config.hcrt
```

依存は暗号プリミティブのみ（`aes-gcm` / `x25519-dalek` / `p256` / `sha2` /
`hmac` / `base64` / `rand`）。TLS 1.3 のレコード層・ハンドシェイク・
鍵スケジュール・セッションチケット・ChronoCert 巻き戻し、HTTP/2 の
フレーム層と HPACK はすべて `src/main.rs` に自前実装した
（Python 版における `cryptography` + `h2` の役割分担に対応）。

- `src/main.rs` — 本体（単一ファイル）
- `src/huffman_table.rs` — HPACK Huffman 表（RFC 7541 Appendix B。
  Python 版が使う `hpack` パッケージの定数から生成）

## Python 版との対応

| 機構 | 実装 |
| --- | --- |
| config.hcrt パーサ | `listen` / `host` / `default` / `route`、相対パスは config 基準、最長一致、未知 SNI は先頭 host |
| CertBundle | PEM 読み込み（ECDSA P-256 のみ）、serial（16進）・issuer/subject（RFC4514）・SHA-256 フィンガープリント保持、20 秒ごとの mtime 監視でホットリロード |
| TLS 1.3 | 自前実装。TLS_AES_128_GCM_SHA256 + X25519 のみ。クライアント Finished 検証あり。PSK は常に拒否してフルハンドシェイク |
| セッションチケット | AES-256-GCM 封緘（系列ID 8B + resumption_master_secret + nonce + 24h 有効期限）。鍵は `.hcrt-ticket-key.bin`（`HCRT_TICKET_KEY` で変更可、0600）。NewSessionTicket は 2 枚、early_data 拡張（16384）付き |
| ChronoCert 巻き戻し | ナビゲーションで証明書が食い違えば RST_STREAM(REFUSED_STREAM) + GOAWAY(NO_ERROR)、系列ID→目標証明書を TTL 30 秒、同一IPフォールバック TTL 10 秒 |
| 0-RTT 覗き見 | early data を復号してパスを読み、そのルートの証明書でフルハンドシェイク |
| HTTP/2 | フレーム層 + HPACK 自前実装（デコードは静的/動的テーブル + Huffman、エンコードはリテラル中心）。ALPN は h2 優先。KeyUpdate 透過処理 |
| HTTP/1.1・静的配信 | 1 リクエストで閉じる。プレースホルダ置換、404 ページ、トラバーサル 403、GET/HEAD のみ |

## 検証済み（2026-11-17、テスト証明書 a/b + sites/ で実施）

- `cargo build --release` 成功
- curl HTTP/1.1 / HTTP/2 ともに 200、プレースホルダ置換・404・403・405・HEAD を確認
- `openssl s_client`: TLSv1.3 / TLS_AES_128_GCM_SHA256 を確認
- `sslgateway/test_h2_client.py`（ポートだけ変更）でチケット系列の巻き戻し
  一往復が Python 版と同一結果（conn2 で RST_STREAM error=7 + GOAWAY、
  conn3 で系列IDにより証明書B のページ）
- `test_noticket_client.py` で同一IPフォールバックを確認（単独実行・
  テスト間干渉込みの連続実行とも Python 版と同一の挙動）
- `openssl s_client -early_data` で 0-RTT 覗き見を確認
  （パス /b/ を読んで証明書B を提示、PSK は拒否されフルハンドシェイク）
- 証明書ファイルの mtime 更新でホットリロードのログを確認

## 未検証・既知の差異

- 実ブラウザ（Chrome / Safari）での往復は未検証（Python 版で実証済みの
  シナリオを、プロトコル検証クライアントで再現した範囲）
- HTTP/2 の送信側フロー制御は最小実装（16K チャンク分割のみで、
  ウィンドウ枯渇時の待機はしない）。大きなファイルの配信では
  Python 版（h2 ライブラリ）より制約が強い
- パストラバーサル検査は、存在するパスは canonicalize、存在しないパスは
  字句的な正規化で判定する（シンボリックリンク経由の逃げ道の扱いが
  Python 版の realpath と厳密には異なる）
- SNI の IDNA デコードは UTF-8 lossy + 小文字化で近似
  （Python 版は IDNA デコードを行う。ASCII 名では同一結果）
