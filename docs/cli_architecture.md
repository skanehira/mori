# mori CLI エントリポイント設計メモ

## 全体像
```
mori
├── src
│   ├── lib.rs        // ライブラリクレートのルート。モジュールを統括し公開APIを定義
│   ├── cli
│   │   ├── args.rs        // clap ベースのフラグ定義・パース
│   │   ├── config.rs      // 設定ファイル読み込み (YAML)
│   │   ├── loader.rs      // フラグと設定ファイルを統合し Policy を生成
│   │   └── mod.rs
│   ├── policy
│   │   ├── mod.rs         // ポリシー全体の組み立てと公開インターフェイス
│   │   ├── file.rs        // ファイル系ポリシー構造体と検証ロジック
│   │   ├── net.rs         // ネットワーク系ポリシー構造体と検証ロジック
│   │   ├── process.rs     // プロセスポリシー構造体と検証ロジック
│   │   └── model.rs       // Policy など共通モデル定義
│   ├── runtime
│   │   ├── linux.rs       // eBPF + Landlock 実装
│   │   ├── macos.rs       // sandbox-exec ラッパー
│   │   └── mod.rs
│   ├── share
│   │   ├── mod.rs         // 共有ユーティリティのエントリポイント
│   │   ├── proc.rs        // プロセス実行・監視まわり
│   │   ├── fs.rs          // ファイルパス操作や暗黙許可リスト
│   │   ├── net.rs         // DNS 解決やルール変換の共通処理
│   │   └── logging.rs     // ログ出力やエラーフォーマット
│   ├── bin
│   │   └── mori.rs        // CLI 実行エントリ。ライブラリAPIを呼び出す薄いラッパー
├── mori-bpf
│   ├── Cargo.toml         // eBPF 専用サブクレート（bpfel-unknown-none ターゲット）
│   └── src/main.rs        // connect4/connect6 フックなど eBPF プログラム本体
├── build.rs               // Linux ビルド時に mori-bpf をコンパイルし ELF を埋め込む
└── Cargo.toml             // ワークスペース定義 + Linux 限定依存
```

- `cli::args` で clap によるフラグ定義 (`--allow-network`, `--config` など)。
- `cli::config` で YAML 設定ファイルを読み込みパース。`serde` + `serde_yaml` を想定。
- `cli::loader` で CLI と設定ファイルをマージし、中間表現 `Policy` を生成。
- `policy::model` で `Policy` の土台を定義し、`policy::file` / `policy::net` / `policy::process` がそれぞれ固有の検証メソッドを実装。`policy::mod` から一括で呼び出し最終ポリシーを確定。
- OS 依存の処理は `runtime` モジュール、OS 非依存の共通処理は `share::*` へ配置し、`runtime` から再利用する。
- `bin/mori.rs` は最小限の CLI エントリポイントとして `Args::parse()` → ライブラリ公開 API を呼び出し、他ツールからは `lib.rs` 経由で mori を再利用できる構成にする。
- eBPF コードは `mori-bpf` サブクレートとして分離し、`build.rs` で `aya_build::build_ebpf` を用いて ELF を生成。生成物は `include_bytes_aligned!` でホスト側ランタイムに埋め込む。

## エントリポイントのフロー
`bin/mori.rs` は `Args::parse()` 等を呼び出した上で、ライブラリ側のエントリ関数へ処理を委譲する。以下はライブラリ側で実行される主なステップ。

1. `cli::args::parse()` で clap による引数解析。
2. `cli::config::load()` で `--config` 指定 or 既定の検索パスから設定ファイルを読み込む（任意）。
3. `cli::loader::merge()` で CLI フラグを優先しつつ設定ファイルをマージし `PolicyDraft` を生成。
4. `policy::validate()` が各ポリシーモジュールの検証メソッドを呼び出してバリデーション・標準化を実行。エラーがあれば即終了。
5. `runtime::dispatch()` で OS 判定し、`runtime::linux::run(policy, command)` などを呼び出す。
6. コマンド実行後の終了コードをそのまま返す。

## 設定ファイル検索順
1. `--config <path>` が指定されていれば最優先。
2. `./mori.config.(yaml|yml)` を検索。
3. `${XDG_CONFIG_HOME:-$HOME/.config}/mori/config.yaml` を検索。
4. 見つからない場合は設定なしとして扱う。

## CLI/設定のマージルール
- `--allow-all` 指定がある場合は設定ファイルの allow 指定より優先。
- 同じカテゴリに複数ソースから値がある場合は `Vec` に結合し、重複は正規化時に除去。
- 未対応フラグ・設定キーはパース段階でエラーにする。

## ログとエラー
- `env_logger` or `tracing` を用いてログ出力。`--verbose` フラグでレベル切り替え。
- CLI/設定パースエラー・バリデーションエラーは `thiserror` で定義したアプリケーションエラー列挙体へ集約し、sandbox-exec や rust-landlock 等の外部エラーは `anyhow` でコンテキスト付きラップを行う。
- 実行時エラーは exit code を 1 (一般エラー) か eBPF 限定コードなどにマッピング。

---

## CLI エントリポイント骨格

```rust
pub fn run_cli<I, T>(args: I) -> Result<ExitCode, MoriError>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let args = cli::args::Args::parse_from(args);
    let cfg = cli::config::load(&args.config)?; // YAML → ConfigDraft
    let draft = cli::loader::merge(&args, cfg)?; // PolicyDraft (生値)
    let policy = policy::validate(draft)?;      // Policy（検証済み）
    runtime::dispatch(&policy, &args.command)
}
```

- `bin/mori.rs` では `run_cli(std::env::args())` を呼び出し、`ExitCode` を `std::process::exit` に渡す。
- `lib.rs` から `run_cli` / `Policy` を公開し、他クレートが CLI なしで再利用できる API を提供する。
- `command` が空の場合はエラー (`MoriError::MissingCommand`) を返し、ヘルプを促す。
- `--config` はパス解決のみ行い、読み込み失敗時は `MoriError::ConfigLoad`（`thiserror`）で包む。

---

## 設定フォーマット検証手順

1. `cli::config::load()` が `serde_yaml::from_reader` で `ConfigDraft` を生成。
2. `cli::loader::merge()` が `Args` の値と `ConfigDraft` をマージし `PolicyDraft` を作成。
   - CLI 優先。例: `allow_network` が CLI にあれば設定値を上書き。
   - ベクタ値は `VecDraft` に結合し、正規化は後段で担当。
3. `policy::validate()` が以下の順に実行:
   - `policy::file::FilePolicy::from_draft(&draft.file)`：パス正規化（絶対パス化、重複除去、暗黙許可との重複検査）。
   - `policy::net::NetworkPolicy::from_draft(&draft.network)`：FQDN/IP/CIDR の解析、ポート範囲チェック、重複ルールマージ。
   - `policy::process::ProcessPolicy::from_draft(&draft.process)`：実行パス存在チェック（オプション）、暗黙許可の追加。
4. それぞれ `Result<_, DomainError>` を返し、`policy::validate()` が `thiserror`/`MoriError` に変換。
5. 成功した `Policy` を `runtime::dispatch` に渡し、OS 別の具象ランナーへ移譲する。

- YAML 構造体には `deny_unknown_fields` を適用し、未知キー検出で即エラー。
- CIDR / IP 正規化は `ipnetwork` 等のライブラリに委譲し、将来的な依存バージョン更新時は互換性検証を行う。

---

## CLI Args 定義（clap 草案）

```rust
#[derive(clap::Parser, Debug)]
pub struct Args {
    /// 設定ファイルパスを明示指定。未指定なら既定探索を行う。
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// すべての制限を解除する開発用フラグ。
    #[arg(long)]
    pub allow_all: bool,

    /// 汎用ファイルアクセス許可。読取り/書込み共通で扱う。
    #[arg(long = "allow-file", value_delimiter = ',')]
    pub allow_file: Vec<PathBuf>,

    /// ファイル読取りのみ許可するパス。
    #[arg(long = "allow-file-read", value_delimiter = ',')]
    pub allow_file_read: Vec<PathBuf>,

    /// ファイル書込みのみ許可するパス。
    #[arg(long = "allow-file-write", value_delimiter = ',')]
    pub allow_file_write: Vec<PathBuf>,

    /// ファイルアクセスを全面許可するショートカット。
    #[arg(long = "allow-file-all")]
    pub allow_file_all: bool,

    /// 読取り全面許可。
    #[arg(long = "allow-file-read-all")]
    pub allow_file_read_all: bool,

    /// 書込み全面許可。
    #[arg(long = "allow-file-write-all")]
    pub allow_file_write_all: bool,

    /// アウトバウンド通信許可。host[:port] / CIDR / IP を受け付ける。
    #[arg(long = "allow-network", value_delimiter = ',')]
    pub allow_network: Vec<String>,

    /// アウトバウンド通信のみ許可。
    #[arg(long = "allow-network-outbound", value_delimiter = ',')]
    pub allow_network_outbound: Vec<String>,

    /// インバウンド通信のみ許可。
    #[arg(long = "allow-network-inbound", value_delimiter = ',')]
    pub allow_network_inbound: Vec<String>,

    /// ネットワーク全面許可のショートカット。
    #[arg(long = "allow-network-all")]
    pub allow_network_all: bool,

    /// 実行許可パス。
    #[arg(long = "allow-process-exec", value_delimiter = ',')]
    pub allow_process_exec: Vec<PathBuf>,

    /// 実行全面許可のショートカット。
    #[arg(long = "allow-process-exec-all")]
    pub allow_process_exec_all: bool,

    /// CLI フラグの後ろに渡されたコマンドと引数。
    #[arg(trailing_var_arg = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}
```

- 各フラグは `Vec` で受け取り、カンマ区切り指定に対応する。
- `command` は `--` 区切り以降をそのまま格納し、後段で `Policy` に紐づいた実行対象として扱う。
- deny 系フラグは宣言しない（clap レベルで `ArgMatches` に現れない）。

---

## YAML 設定スキーマ（serde）

```yaml
allow_all: bool
file:
  allow_all: bool
  allow_read_all: bool
  allow_write_all: bool
  allow: [Path]            # 読み書き共通
  allow_read: [Path]
  allow_write: [Path]
network:
  allow_all: bool
  allow_outbound:          # host / host:port / CIDR / IP
    - { host: string, port: optional<int>, protocol: "tcp" }
  allow_inbound:
    - { host: string, port: optional<int>, protocol: "tcp" }
process:
  allow_all: bool
  allow_exec: [Path]

# 追加のトップレベルキーが存在した場合はエラー。
```

- `serde_yaml` で `ConfigDraft` にマッピングし、オプション値は `Option<T>` / `Vec<T>` で受け取る。
- `host` は FQDN / IP / CIDR を許容する文字列。`port` は未指定で任意ポートを表す。
- `protocol` は現状 `tcp` のみ。省略時は `tcp` とみなす。
- 既定探索（`./mori.config.yaml` → `$XDG_CONFIG_HOME/mori/config.yaml`）で見つからなければ空の設定として扱う。

---

## Policy のデフォルトとマージ方針

```rust
impl Policy {
    pub fn default() -> Self {
        Self {
            allow_all: false,
            file: FilePolicy::default(),
            network: NetworkPolicy::default(),
            process: ProcessPolicy::default(),
        }
    }
}

impl FilePolicy {
    fn default() -> Self { /* allow_all=false, vecは空 */ }
    fn merge(self, other: FilePolicy) -> FilePolicy { /* allow_all は OR, Vec は結合→正規化 */ }
}
```

- `PolicyDraft`（CLI と設定ファイルの素の値）を `policy::validate()` で各ドメインに渡し、`FilePolicy::from_draft(&draft.file)` のように構築する。
- デフォルト値は「すべて拒否」「許可リスト空」で統一。`allow_*_all` が真の場合は対応する `Vec` を無視する。
- マージは「設定ファイル → CLI フラグ」の順に上書き。CLI で `Some` が渡された項目は設定値を置き換える。
- `Vec` 系は結合後に正規化（重複除去、パス正規化、ホスト表現の正規化）を行い、結果を `Policy` に格納する。
- エラー検出は各 `*_policy::validate()` 内で行い、失敗時は `thiserror` で定義したドメインエラーを返す。外部クレートからのエラーは `anyhow::Context` で包んで呼び出し側に伝播させる。
