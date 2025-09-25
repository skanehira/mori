# mori CLI エントリポイント設計メモ

## 全体像
```
mori
├── cli
│   ├── args.rs        // clap ベースのフラグ定義・パース
│   ├── config.rs      // 設定ファイル読み込み (YAML/TOML)
│   ├── loader.rs      // フラグと設定ファイルを統合し CliPolicy を生成
│   └── mod.rs
├── policy
│   ├── model.rs       // CliPolicy / FilePolicy / NetworkPolicy 構造体
│   ├── validate.rs    // 値検証・正規化 (FQDN, CIDR, パス)
│   └── mod.rs
├── runtime
│   ├── linux.rs       // eBPF + Landlock 実装
│   ├── macos.rs       // sandbox-exec ラッパー
│   ├── common.rs      // 共有ユーティリティ (プロセス起動, ログ)
│   └── mod.rs
└── main.rs
```

- `cli::args` で clap によるフラグ定義 (`--allow-network`, `--config` など)。
- `cli::config` でファイル形式（YAML/TOML）を判別しパース。`serde` + `serde_yaml` / `toml` を想定。
- `cli::loader` で CLI と設定ファイルをマージし、中間表現 `CliPolicy` を生成。
- `policy::validate` で FQDN / CIDR / パスの正規化とエラー判定を行い、`CliPolicy` を確定。
- `runtime` モジュールで OS 判定後に適切な実装を呼び出し、`CliPolicy` を変換。

## エントリポイントのフロー
1. `cli::args::parse()` で clap による引数解析。
2. `cli::config::load()` で `--config` 指定 or 既定の検索パスから設定ファイルを読み込む（任意）。
3. `cli::loader::merge()` で CLI フラグを優先しつつ設定ファイルをマージし `CliPolicyDraft` を生成。
4. `policy::validate::finalize()` でバリデーション・標準化。エラーがあれば即終了。
5. `runtime::dispatch()` で OS 判定し、`runtime::linux::run(policy, command)` などを呼び出す。
6. コマンド実行後の終了コードをそのまま返す。

## 設定ファイル検索順
1. `--config <path>` が指定されていれば最優先。
2. `./mori.config.(yaml|yml|toml)` を検索。
3. `${XDG_CONFIG_HOME:-$HOME/.config}/mori/config.(yaml|toml)`。
4. 見つからない場合は設定なしとして扱う。

## CLI/設定のマージルール
- `--allow-all` 指定がある場合は設定ファイルの allow 指定より優先。
- 同じカテゴリに複数ソースから値がある場合は `Vec` に結合し、重複は正規化時に除去。
- 未対応フラグ・設定キーはパース段階でエラーにする。

## ログとエラー
- `env_logger` or `tracing` を用いてログ出力。`--verbose` フラグでレベル切り替え。
- CLI/設定パースエラー・バリデーションエラーは `anyhow` でラップし、ユーザー向けメッセージを整形。
- 実行時エラーは exit code を 1 (一般エラー) か eBPF 限定コードなどにマッピング。

## 今後のタスク
- clap 定義の草案 (`Args` struct) 作成。
- 設定ファイルの serde スキーマ（YAML/TOML 共通 struct）設計。
- `CliPolicy` の `Default` 実装とマージロジックを具体化。

