# mori 設計ドキュメント

## 目的
- macOS / Linux 双方で、指定したプロファイルと mori 独自の CLI フラグ（sbx 参照ベース）に基づきアウトバウンド通信とファイルIOを制御する。
- ファイルIO制御は Linux では Landlock、macOS では sandbox-exec を利用する。
- 通信制御は Linux では cgroup v2 + eBPF、macOS では sandbox-exec のネットワーク制御機構を利用する。
- Rust 製シングルバイナリとして配布可能な実装を目指す。
- ロードマップおよび進行状況は `docs/roadmap.md`、CLI 詳細は `docs/cli_spec.md`、外部実装調査は `docs/reuse_plan.md` を参照する。

---

## MVP スコープ
- Linux: cgroup + eBPF による FQDN ベースのネットワーク許可、Landlock によるファイルIO制限を mori CLI から実現する。
- macOS: sandbox-exec によるネットワーク／ファイルIO制限を同一 CLI インターフェイスで提供する。
- 共通 CLI: mori 独自の allow 系フラグをサポートし、単一コマンドで両OSに同等の制約を適用できること。
- 設定ファイルフォーマットを提供し、CLI フラグと同等のポリシーを宣言できるようにする。

---

## CLI / 設定仕様
- CLI ルートコマンド: `mori [flags] -- <command> [args...]`
- サポートするのは allow 系フラグのみ。deny 系フラグを指定された場合はエラー終了。
- FQDN / IP / CIDR を許可先として指定可能にし、macOS / Linux 両方で同じ表現が使えるようにする。
- 設定ファイル（YAML 固定）を読み込み、CLI フラグと同じポリシーを記述できるようにする。CLI が優先。
- システムライブラリ（dylib 等）は暗黙に許可する。

---

## アーキテクチャ概要
- CLI レイヤーはフラグ解析・設定ファイル読み込みを行い、共通中間表現 `Policy` を構築する（詳細は `docs/cli_architecture.md` 参照）。
- OS ごとの実装は `Policy` を受け取り、各 OS 用のポリシー（Landlock ルール、eBPF マップ、sandbox-exec プロファイル）へ変換する。

### Linux 側 (eBPF + Hickory)
```
+-----------------------------+
| mori (Rust, Aya)           |
|                             |
|  +-----------------------+  |
|  | eBPF プログラム       |  |
|  | (aya-bpf)             |  |
|  |  - connect4 hook      |  |
|  |  - connect6 hook      |  |
|  |  - ALLOW_V4/V6 map    |  |
|  +-----------------------+  |
|                             |
|  +-----------------------+  |
|  | ユーザー空間          |  |
|  | (Aya + Hickory)       |  |
|  |  - DNS解決 (FQDN→IP)  |  |
|  |  - マップ更新         |  |
|  |  - 子プロセス実行     |  |
|  +-----------------------+  |
+-----------------------------+
```

### macOS 側 (sandbox-exec ラッパー)
- mori の中間表現から sandbox-exec S式を生成し、`sandbox-exec` をラップしてコマンドを実行する。
- `sbx` の挙動を参考にしつつ、mori 独自ルール（FQDN 指定、暗黙許可など）を適用する。

---

## 機能仕様

### Linux ネットワーク制御 (eBPF)
- タイプ: `CgroupSockAddr`
- attach: `connect4` (IPv4), `connect6` (IPv6)
- マップ:
  - `ALLOW_V4: HashMap<V4Key, u8>`
  - `ALLOW_V6: HashMap<V6Key, u8>`
- 判定:
  - `connect()` の宛先IPとポートをキーに検索
  - マップに存在すれば `PROCEED`
  - 存在しなければ `REJECT`
- mori CLI の `--allow-network*` フラグで指定された FQDN / IP / CIDR を Hickory で解決し、TTL を尊重してマップを更新する。

### Linux ユーザー空間 (Aya + Hickory Resolver)
- 引数:
  - allow 系ネットワークフラグ (`--allow-network`, `--allow-network-outbound` 等)
  - allow 系ファイルフラグ (`--allow-file-read` 等)
  - 設定ファイルからのポリシー
  - `cmd...` 実行するコマンド
- 処理:
  1. BPF ELF を埋め込み (`include_bytes_aligned!`) でロード
  2. cgroup v2 サブディレクトリを作成
  3. `connect4/6` プログラムを attach
  4. Hickory DNS を用いた非同期タスクで FQDN を再解決し、TTL を尊重した IP + Port を ALLOW マップに挿入
  5. 子プロセスを spawn し、PID を対象 cgroup に移動
  6. 子プロセス終了まで待機し、終了コードをそのまま返す

### Linux ファイルIO制御 (Landlock)
- allow 系フラグ / 設定ファイルで指定されたパスを Landlock の AccessFs へマッピングする。
- deny 系指定はサポートしない。未対応フラグを受け取った場合はエラー終了。
- システムライブラリの暗黙許可セットを Landlock ルールに含める。

### macOS 全体制御 (sandbox-exec)
- CLI / 設定ファイルで構築した中間表現から sandbox-exec S式を生成。
- FQDN や CIDR 指定を sandbox-exec の `(remote ...)` ルールへ変換する。
- 実行時は `sandbox-exec` をラップし、エラーを mori 側で整形して返す。

### 共通機能
- CLI は OS を自動判定し、内部実装を切り替える。
- `Policy` を OS 別実装へ渡す共通モジュールを提供する。
- 拒否イベントや内部エラーを構造化ログで出力し、必要に応じて JSON / 人間可読形式を選択できるようにする。
- 未定義フラグや設定値エラーは即時エラー終了。

---

## 配布形態
- **シングルバイナリ**
  - `aya-bpf` でビルドした eBPF ELF を `build.rs` で `OUT_DIR` にコピー
  - `include_bytes_aligned!(env!("BPF_ELF_PATH"))` で埋め込み
  - 実行時に外部ファイル不要
- macOS では `sandbox-exec` が利用可能な環境であることを前提とする。

---

## 依存ライブラリのバージョン固定と更新ポリシー
- **Rust クレート**
  - `Cargo.lock` でバージョン固定。`clap` / `serde` / `serde_yaml` / `aya` / `aya-bpf` といった主要依存はセマンティックバージョニングに従いパッチ更新は随時反映、マイナー以上の更新は兼互換性の確認後に採用する。
  - eBPF/Landlock 周辺 (`aya` 系) はカーネル互換の影響が大きいため、メジャーアップデートは専用ブランチで検証してからマージする。
  - `cargo update -p <crate>` で個別更新→`cargo test` と macOS / Linux スモークテストを必須化する。
- **システムパッケージ**
  - Ubuntu VM: `clang`, `llvm`, `bpftool`, `libbpf-dev` は OS の LTS リポジトリを利用し、セキュリティアップデートのみ追従。`linux-headers` が入手できない場合はソースヘッダーをマウントするなど代替策を採用。
  - macOS: Homebrew で `llvm`、`rustup` をインストールし、`rustup` の stable チャンネルを四半期ごとに更新チェック。`sandbox-exec` の非推奨化動向もウォッチする。
- **更新フロー**
  1. 更新候補を issue 化し、影響範囲を記載。
  2. 依存更新を反映後、`cargo test` + 主要スモークテスト（macOS / Ubuntu）を実行。
  3. 挙動差が出た場合は回帰テストを追加し、`CHANGELOG` に更新理由と影響範囲を残す。

---

## 運用フロー
1. ユーザーが以下の形式で実行 (Linux 例):
   ```bash
   sudo ./mori --allow-file-read='.' --allow-network='example.com:443' -- curl https://example.com
   ```
2. `--allow-network` で指定した FQDN / IP / CIDR 以外の outbound TCP connect は `REJECT`
3. FQDN は TTL に従い再解決され、IP 変動に追随
4. macOS では同一 CLI から sandbox-exec プロファイルを生成・適用し、同じフラグで制御を提供する

---

## 制約・注意点
- **権限**: Linux では CAP_BPF、CAP_SYS_ADMIN 相当が必要
- **cgroup v2 必須**: unified hierarchy が有効であること
- **FQDN→IP の限界**:
  - CDN などで IP が頻繁に変わると追随が必要
  - DNS TTL を尊重する拡張が望ましい
- **プロセス移動のタイミング**:
  - 現状は `spawn→PIDをcgroupへ移動`
  - race を避けるなら fork→cgroup投入→exec が理想
- **macOS 固有の制約**:
  - sandbox-exec のプロファイル構文に依存するため、未対応のルールは明確にエラーにする
  - コード署名や notarization が必要になる場合がある
- **CLI 設計**:
  - allow 系のみサポートするため、deny の指定はエラーで終了
  - CLI / 設定ファイルのパースエラーは即時終了

---

## 今後の検討事項
- 設定ファイルフォーマットの詳細設計（YAML スキーマ、バリデーション）
- UDP / QUIC など TCP 以外のプロトコル制御
- 拒否イベントの可視化（レポートコマンド、GUI 連携など）
- Landlock 非対応カーネルや sandbox-exec 非搭載環境へのフォールバック
