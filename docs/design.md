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
- CLI レイヤーはフラグ解析・設定ファイル読み込みを行い、`NetworkPolicy` 構造体を構築する。
- Linux 実装が `NetworkPolicy` を受け取り、eBPF マップへ変換してネットワーク制御を行う。

### 実装済み: Linux 側 (eBPF + tokio + Hickory)
```
+--------------------------------------------+
| mori (Rust, Aya, tokio)                   |
|                                            |
|  +--------------------------------------+  |
|  | eBPF プログラム (aya-bpf)            |  |
|  |  - connect4 hook (IPv4)              |  |
|  |  - ALLOW_V4 HashMap                  |  |
|  +--------------------------------------+  |
|                                            |
|  +--------------------------------------+  |
|  | ユーザー空間 (tokio async)           |  |
|  |  - CLI フラグ / 設定ファイル解析     |  |
|  |  - NetworkPolicy 構築                |  |
|  |  - 非同期 DNS 解決 (Hickory)         |  |
|  |  - TTL ベースの定期更新タスク        |  |
|  |  - eBPF マップの動的更新             |  |
|  |  - cgroup への子プロセス配置         |  |
|  +--------------------------------------+  |
+--------------------------------------------+
```

### 未実装: macOS 側 / connect6 (IPv6)
- roadmap.md を参照

---

## 機能仕様（現在の実装）

### Linux ネットワーク制御 (eBPF)
**実装済み:**
- タイプ: `CgroupSockAddr`
- attach: `connect4` (IPv4)
- マップ: `ALLOW_V4: HashMap<u32, u8>` (IPv4 アドレスをキーとする許可リスト)
- 判定:
  - `connect()` の宛先 IP アドレスをキーに検索
  - マップに存在すれば `PROCEED`
  - 存在しなければ `REJECT`

**未実装 (今後の拡張):**
- `connect6` (IPv6)
- ポート番号による制御
- CIDR 範囲指定

### Linux ユーザー空間（実装済み）
**入力:**
- CLI フラグ: `--allow-network <target>`（複数指定可能）
- 設定ファイル: `--config <path>` (TOML 形式)
- 実行コマンド: `-- <command> [args...]`

**処理フロー:**
1. NetworkPolicy 構築
   - CLI フラグと設定ファイルをパース
   - FQDN と IPv4 アドレスに分類
   - 重複を排除してマージ
2. 初期 DNS 解決
   - Hickory Resolver で FQDN → IPv4 アドレス解決
   - TTL 情報を DNS キャッシュに保存
   - DNS サーバー自体の IPv4 アドレスも許可リストに追加
3. cgroup 作成と eBPF プログラムアタッチ
   - `/sys/fs/cgroup/mori-{pid}` ディレクトリ作成
   - BPF ELF を埋め込み (`include_bytes_aligned!`) でロード
   - `connect4` プログラムを cgroup にアタッチ
   - 許可 IPv4 アドレスを ALLOW_V4 マップに挿入
4. 子プロセス起動
   - `Command::spawn` でコマンド実行
   - PID を対象 cgroup に移動
5. 非同期 DNS 更新タスク起動（ドメイン指定時のみ）
   - tokio::spawn で非同期タスク起動
   - DNS キャッシュの TTL を監視
   - 期限切れ前に再解決を実行
   - IP アドレス変更を検出して eBPF マップを更新
6. 子プロセス終了待機
   - 子プロセスが終了したらシャットダウンシグナル送信
   - DNS 更新タスクを停止
   - 終了コードを返す

### データ構造

**NetworkPolicy (`src/policy.rs`):**
```rust
pub struct NetworkPolicy {
    pub allowed_ipv4: Vec<Ipv4Addr>,    // 直接指定された IPv4 アドレス
    pub allowed_domains: Vec<String>,    // ドメイン名
}
```

**ConfigFile (`src/config.rs`):**
```toml
[network]
allow = ["example.com", "192.0.2.1"]
```

**DnsCache (`src/net/cache.rs`):**
- ドメインごとに IPv4 アドレスと有効期限を管理
- 次回更新時刻の計算
- IP アドレス変更の差分検出

### 非同期実装の詳細

**tokio ランタイム:**
- `#[tokio::main]` でメイン関数を非同期化
- DNS 解決: `hickory-resolver` の tokio 統合
- 定期更新: `tokio::spawn` + `tokio::select!` + `tokio::time::sleep`

**ShutdownSignal (`src/runtime/linux/sync.rs`):**
- `tokio::sync::Notify` + `AtomicBool` による非同期シャットダウン通知
- タイムアウトとシャットダウンシグナルを `tokio::select!` で競合
- 通知の取りこぼしを防ぐ設計

**エラーハンドリング:**
- DNS 解決失敗時: エラーログを出力して継続（非致命的）
- eBPF マップ更新失敗時: エラーログを出力して継続（非致命的）
- シャットダウンシグナル受信時: 正常終了

---

## 配布形態（実装済み）
- **シングルバイナリ**
  - `aya-bpf` でビルドした eBPF ELF を `build.rs` で `OUT_DIR` にコピー
  - `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/mori"))` で埋め込み
  - 実行時に外部ファイル不要
  - Linux 専用（macOS 対応は未実装）

---

## 依存ライブラリ（現在の実装）
**システム要件:**
- Linux カーネル 5.7+ (cgroup v2 + eBPF `CgroupSockAddr` サポート)
- Rust 1.87+ (rust-toolchain.toml で固定)
- ビルドツール: `clang`, `llvm`, `bpf-linker`

---

## 使用例（現在の実装）

### 基本的な使用
```bash
# IPv4 アドレスを直接指定
sudo ./mori --allow-network 192.0.2.1 -- curl http://192.0.2.1

# ドメイン名を指定（DNS 解決 + TTL ベース自動更新）
sudo ./mori --allow-network example.com -- curl https://example.com

# 複数の許可先を指定
sudo ./mori --allow-network example.com --allow-network 192.0.2.1 -- curl https://example.com
```

### 設定ファイルを使用
```bash
# config.toml:
# [network]
# allow = ["example.com", "192.0.2.1"]

sudo ./mori --config config.toml -- curl https://example.com

# CLI フラグと設定ファイルの併用（両方がマージされる）
sudo ./mori --config config.toml --allow-network test.example -- curl https://test.example
```

### 動作
1. 指定されたドメイン名を DNS 解決
2. 解決された IPv4 アドレスと直接指定された IPv4 アドレスを eBPF マップに登録
3. DNS サーバーの IPv4 アドレスも自動的に許可リストに追加
4. 子プロセス（curl など）を cgroup に配置して起動
5. 許可リスト以外への接続は EPERM エラーで拒否
6. ドメイン名が指定されている場合、TTL に基づいて定期的に再解決し eBPF マップを更新
7. 子プロセス終了後、DNS 更新タスクを停止して終了

---

## 制約・注意点（現在の実装）

### 権限
- Linux では root 権限（または CAP_BPF + CAP_NET_ADMIN）が必要
- cgroup v2 が有効であること (`/sys/fs/cgroup` が unified hierarchy)

### プロトコル
- **IPv4 のみ対応**: IPv6 は未実装
- **TCP のみ**: UDP, ICMP などは未対応
- **ポート制御なし**: 全ポートが許可対象

### DNS 解決
- **システムリゾルバを使用**: `/etc/resolv.conf` の設定に従う
- **TTL ベース更新**: TTL が短い（数秒）場合、頻繁に再解決が発生する可能性
- **DNS 失敗時の挙動**: エラーログを出力するが、既存の IP アドレスは維持される（非致命的エラー）

### プロセス管理
- **spawn 後に cgroup 移動**: 理想的には fork → cgroup 移動 → exec だが、現状は spawn 後に移動
- **子プロセスのみ制御**: 孫プロセス以降も cgroup に自動的に含まれる

### その他
- **CIDR 表記未対応**: `192.168.1.0/24` のような範囲指定は未実装
- **ポート指定未対応**: `example.com:443` のようなポート限定は未実装
- **設定ファイル形式**: TOML 固定（YAML は非対応）

---

## 今後の拡張（roadmap.md 参照）
- **IPv6 対応**: `connect6` フックの実装
- **CIDR 表記**: IP 範囲指定のサポート
- **ポート制御**: ポート番号による細かい制御
- **UDP/QUIC**: TCP 以外のプロトコル対応
- **拒否イベント可視化**: ログ出力、構造化ログ、レポート機能
- **macOS 対応**: sandbox-exec ラッパーの実装
- **Landlock 統合**: ファイル IO 制御の追加
