# mori CLI フラグ仕様 (sbx 参照)

## 目的
- `sbx` のフラグ体系を参考にしつつ、mori の macOS / Linux 共通 CLI を設計する。
- 各フラグのカテゴリ・挙動・引数型・内部表現への変換方針を明確にする。

---

## フラグ一覧（実装対象）

| フラグ                     | カテゴリ     | 引数                      | デフォルト挙動 | 説明                                                               |
|----------------------------|--------------|---------------------------|----------------|--------------------------------------------------------------------|
| `--allow-all`              | 全体         | bool (フラグ)             | すべて拒否     | すべての操作を許可に切り替える。開発・デバッグ用途。               |
| `--allow-file`             | ファイル     | パス (カンマ区切り)       | 拒否           | 指定パスの読み書き許可。                                           |
| `--allow-file-all`         | ファイル     | bool                      | 拒否           | すべてのファイル操作を許可。                                       |
| `--allow-file-read`        | ファイル読取 | パス                      | 拒否           | 指定パスの読み取りを許可。                                         |
| `--allow-file-read-all`    | ファイル読取 | bool                      | 拒否           | すべての読み取りを許可。                                           |
| `--allow-file-write`       | ファイル書込 | パス                      | 拒否           | 指定パスの書き込みを許可。                                         |
| `--allow-file-write-all`   | ファイル書込 | bool                      | 拒否           | すべての書き込みを許可。                                           |
| `--allow-network-all`      | ネットワーク | bool                      | 拒否           | すべてのネットワーク操作を許可。                                   |
| `--allow-network-inbound`  | ネットワーク | `host` または `host:port` | 拒否           | インバウンド接続を許可。FQDN / IP / CIDR いずれも許容する。        |
| `--allow-network-outbound` | ネットワーク | `host` または `host:port` | 拒否           | アウトバウンド接続を許可。FQDN / IP / CIDR いずれも許容する。      |
| `--allow-network`          | ネットワーク | `host[:port]`             | 拒否           | 指定ホスト・(任意ポート)の通信を許可。ポート省略時は any。         |
| `--allow-process-exec`     | プロセス     | パス                      | 拒否           | 指定パス配下の実行を許可。                                         |
| `--allow-process-exec-all` | プロセス     | bool                      | 拒否           | すべての実行を許可。                                               |

- deny 系フラグ（`--deny-*`）は実装しない。入力された場合はエラー終了とする。
- パス指定は相対・絶対どちらも許容し、カンマ区切りで複数指定可能。
- ネットワーク指定では FQDN / IP アドレス / CIDR を許容し、macOS / Linux で同じ解釈を行う。
- `host[:port]` のポートは整数、指定がない場合は「任意ポート」を意味する。複数ポート指定は将来拡張として別フラグで検討。

---

## mori 固有の設計方針
- **FQDN 対応**: macOS / Linux どちらでも FQDN をそのまま指定可能にし、TTL を尊重した再解決を行う。
- **暗黙許可**: システムライブラリ（dylib など）の読み込みは暗黙に許可する。ユーザー指定の `--allow-file*` はこれに追加される形。
- **設定ファイル**: mori 独自の設定フォーマット（YAML or TOML 想定）を定義し、CLI フラグと同じ構造で宣言できるようにする。設定→内部表現→OS別実装への変換を共通処理化。
- **互換性**: `sbx` と完全互換は目指さず、挙動は参考にするに留める。互換モードは提供しない。
- **エラー処理**: 未定義フラグ・想定外の値・フォーマットエラーは即時エラー終了させる。警告で継続はしない。
- **フラグ優先順位**: allow 系のみをサポートするため、優先順位の衝突は発生しない。`--allow-all` 指定時はその他指定よりも優先。

---

## 中間表現へのマッピング

```
struct CliPolicy {
    allow_all: bool,
    file: FilePolicy,
    network: NetworkPolicy,
    process: ProcessPolicy,
}
```

- `FilePolicy`
  - `allow_read_paths: Vec<PathSpec>`
  - `allow_write_paths: Vec<PathSpec>`
  - `allow_all: bool`
  - システムライブラリの暗黙許可は内部でデフォルトセットとして保持。
- `NetworkPolicy`
  - `allow_outbound: Vec<NetworkRule>`
  - `allow_inbound: Vec<NetworkRule>`
  - `allow_all: bool`
  - `NetworkRule` = { host: HostSpec, port: Option<PortRange>, protocol: Tcp }
  - FQDN は Linux では Hickory で解決し eBPF マップへ、macOS では sandbox-exec の `(allow network-outbound (remote tcp "example.com" :port 443))` 等へ変換。
- `ProcessPolicy`
  - `allow_exec_paths: Vec<PathSpec>`
  - `allow_all: bool`
  - macOS / Linux で実装優先度は低いが、仕様として保持。

---

## 設定ファイルフォーマット（案）
YAML 例:

```yaml
allow_all: false
file:
  allow_all: false
  allow_read:
    - ./data
  allow_write:
    - /tmp/mori
network:
  allow_all: false
  allow_outbound:
    - host: example.com
      port: 443
    - host: 10.0.0.0/8
process:
  allow_all: true
```

- CLI フラグと設定ファイルを併用した場合は CLI が優先。
- 設定ファイルは `--config <path>` で指定。未指定時はプロジェクトルートや `$XDG_CONFIG_HOME/mori/config.yaml` を探索する。
- フォーマットエラーや未知キーは即エラー終了。
- LSP用に設定ファイルのスキーマ定義を提供する。

---

## フェーズ TODO との対応
- フェーズ0 TODO の「CLI エントリポイント骨格」「設定フォーマット設計」タスクは本仕様をベースに詳細化する。
- フェーズ1/2 で OS 別の変換ロジックを実装する際、本ファイルの中間表現を参照して機能追加を行う。
