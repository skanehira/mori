# cage / rust-landlock 再利用方針メモ

## cage の実装パターン整理
- Go 製 CLI。Linux では go-landlock、macOS では sandbox-exec を利用しつつ、単一コマンドで書き込み制御を提供。
- 主目的は「書き込み禁止デフォルト + `-allow` で例外追加」。ネットワークやプロセス制御は対象外。
- 主なフラグ: `-allow`, `-allow-all`, `-preset`, `-config` など。書き込み許可対象を列挙し、`syscall.Exec` でプロセスを置換。
- macOS 側は sandbox-exec プロファイル（S式）を生成して実行。dylib や共通システムパスは暗黙許可。
- Linux 側は Landlock ルールセットを生成し、`RestrictSelf` 後にコマンドを `exec`。

## mori への取り込み方針
- mori も単一バイナリで macOS / Linux を切り替える構成とし、`Policy` を各 OS 実装へ渡す設計とする。
- ファイル書き込み制御は cage と同じ allow リスト方式を Landlock / sandbox-exec にマッピングする。
- cage の `-allow`, `-preset` などは直接は採用せず、mori 独自の allow 系フラグ（sbx 参照）＋設定ファイルで管理する。
- プロセス実行は cage と同様 `exec` 相当で置き換える流れを維持し、エージェント用途で環境変数を付与する（例: `IN_MORI=1`）。
- 暗黙許可パス（dylib, `/System` など）は cage の挙動を参考にしつつ mori 側でリストアップして Landlock / sandbox-exec に登録する。

## rust-landlock の利用パターン整理
- `Ruleset::default().handle_access(...)` で許可対象の操作種別を指定し、`add_rules` で `PathBeneath` などを追加する構造。
- `PathEnv` のようなヘルパーで環境変数からパス群を読み取り、`AccessFs::from_read`, `from_all` などで権限を付与。
- `restrict_self()` 後に `exec()` して子プロセスを実行するのが基本フロー。
- 追加機能として `AccessNet` を扱う例もあり、将来的な TCP 制御の参考になる。

## mori での適用
- CLI / 設定から収集した `allow_paths_*` を `PathBeneath` へ変換し、読み取り・書き込み権限を個別に付与する。
- Landlock 非対応カーネルの場合はエラーを返し、MVP の前提条件として明記する。
- `restrict_self()` 前に DNS 解決など必要なセットアップを完了させる（Landlock 適用後は新規ファイルアクセスが制限されるため）。
