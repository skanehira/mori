# mori 開発ロードマップ (MVP)

## MVPのゴール
- [ ] Linux: cgroup + eBPF による FQDN ベースのネットワーク制御と Landlock によるファイルIO制御を CLI / 設定ファイルから提供する
- [ ] macOS: sandbox-exec をラップし、mori の allow 系フラグと設定ファイルでネットワーク／ファイルIOを制御できるようにする
- [ ] 共通 CLI: mori 仕様の allow 系フラグと設定フォーマットを通じて、単一プロファイルで両OSに同等の制約を適用できるようにする

## フェーズ0: 基盤準備と既存資産の取り込み
### TODO
- [x] `sbx` README のフラグ仕様を参考資料として整理する
- [x] cage と rust-landlock の API / 実装パターンを調査し再利用方針を決める
- [x] クロスプラットフォーム共通 CLI エントリポイントと設定ロード処理の骨格を設計する
- [x] clap 定義の草案 (`Args` struct) を文書化する
- [x] 設定ファイルの serde スキーマ（YAML struct）を設計する
- [x] `Policy` の `Default` 実装とマージロジックを文書化する
- [x] テスト環境（macOS / Linux）でのスモークテストを実施し結果を記録する
- [ ] CI ランナー / 自動化手段の確立（self-hosted runner 検討、手順化）
### このフェーズで決めること
- [x] mori 独自 CLI フラグの正式仕様と優先度（allow 系のみ、FQDN / CIDR 対応）
- [x] 内部モジュール構成（OS ごとの実装切り替え、共通のポリシー中間表現）
- [x] 設定ファイルフォーマット（YAML 固定）の検索優先順位とバリデーション方針
- [x] 既存ライブラリのバージョン固定と更新ポリシー
- [x] CLI エントリポイント骨格の詳細化（Args/Policy 連携の仕様固め）
- [x] 設定フォーマットの設計確定（YAML スキーマのバリデーション手順定義）

### 開発環境メモ（Ubuntu VM 想定）
- ベース: Ubuntu（cgroup v2 / eBPF 対応カーネル）をゲスト OS として用意する。
- 主要パッケージ:
  ```bash
  sudo apt update
  sudo apt install -y build-essential pkg-config cmake
  sudo apt install -y clang llvm lld bpftool libbpf-dev
  sudo apt install -y linux-libc-dev libclang-dev
  sudo apt install -y curl git
  cargo install bpf-linker
  curl https://sh.rustup.rs -sSf | sh
  source $HOME/.cargo/env
  ```
- 注意点:
  - Landlock を使うために Linux 5.13 以降のカーネル、cgroup v2 が有効なホストを選ぶ。
  - eBPF ビルドには `clang/llvm` と `bpftool`、必要に応じて `bpf-linker` 等を追加導入する。
  - Rust ツールチェーンは `rustup` で管理し、プロジェクトに合わせて nightly / stable を切り替える。
  - OrbStack 提供カーネルなど独自ビルドの場合、`linux-headers-$(uname -r)` が配布されていないケースがある点に留意する。
  - カーネルヘッダーが取得できない場合は、ホスト側の `/usr/src/linux-headers-*` をマウントする、もしくはカーネルソースから必要分のみ取得するといった代替策を検討する。
  - eBPF のビルドには nightly toolchain + `rust-src` コンポーネント、および `cargo install bpf-linker` で導入できる `bpf-linker` を使用する。

### スモークテスト記録
- macOS (2025-09-25): `cargo test` / `sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` 成功。
- Ubuntu VM (orb dev, kernel 6.15.11-orbstack-00539, 2025-09-25): Rust (1.90.0) と必要パッケージ導入後に `cargo test` 成功。

### 開発環境メモ（macOS ホスト想定）
- ベース: macOS 13 以降（`sandbox-exec` は macOS 14 時点で非推奨だが利用可能）。
- 主要セットアップ:
  ```bash
  xcode-select --install              # Xcode Command Line Tools を導入
  /usr/sbin/softwareupdate --install-rosetta --agree-to-license  # Apple Silicon で必要なら
  /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
  brew install rustup-init llvm bpftrace
  rustup-init
  source $HOME/.cargo/env
  ```
- 注意点:
  - `sandbox-exec` は将来的に削除される可能性があるため、挙動と代替策（Apple の App Sandbox など）を継続的に監視する。
  - Homebrew の `llvm` を PATH に入れることで macOS 側でも eBPF ソースの静的検査や解析を行える。
  - macOS 固有テストでは codesign / notarization の要件も調査する（今後の公開に備えて）。
- スモークテスト実績:
  - `cargo test`（2025-09-25）を macOS ホストで実行し成功。
  - `sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` を実行し、sandbox プロファイルが適用されることを確認。

### 自動化 / 実行確認メモ
- Linux: GitHub Actions のホストランナーでは `CAP_BPF` 等が不足し eBPF attach が制限されるため、Ubuntu VM を self-hosted runner として登録するか、Vagrant/Multipass などで同等環境を確保する。
- macOS: Apple Silicon / Intel いずれも物理マシン or Apple Virtualization Framework を使った self-hosted runner を想定。Hosted macOS ランナーは管理者権限が制限されているため、`sandbox-exec` の挙動確認は限定的。
- いずれの環境も、`cargo test` に加えて smoke テスト（簡易な `sandbox-exec` プロファイル適用、eBPF attach）を追加し自動化手順をドキュメント化する。

## フェーズ1: Linux 向けネットワーク制御
### TODO
- [x] connect4 / connect6 にフックする eBPF プログラムを作成し cgroup にアタッチする
- [ ] Hickory DNS による FQDN→IP 解決と eBPF マップ更新ループ（TTL 尊重）を実装する
- [ ] mori CLI / 設定ポリシーから Linux ネットワーク許可ルール（FQDN / IP / CIDR）への変換レイヤーを実装する
- [ ] 拒否イベントのログ出力と最低限の観測手段（構造化ログ等）を整備する
- [ ] Landlock へのマッピングコード（Rust）を CLI 層と分離したモジュールとして設計する
### このフェーズで決めること
- [ ] 許可ルールの内部表現（ポート省略時の扱い、任意ポート表現）
- [ ] DNS 再解決ポリシー（TTL 尊重、有効期限切れ時の挙動、リトライ戦略）
- [ ] 拒否 / エラー時のユーザー通知手段（stderr、ログフォーマット）
- [ ] OS 別変換ロジックの実装方針（Policy -> Linux/macOS 変換）の詳細

## フェーズ2: macOS 向けネットワーク制御
### TODO
- [ ] mori のポリシー表現から sandbox-exec S式を生成するテンプレート・変換ロジックの雛形を設計し実装する
- [ ] Linux と同じ allow 系フラグ / 設定で macOS のネットワーク制限を適用できるラッパーを整備する
- [ ] macOS 固有制約（DNS 解決、コード署名、暗黙許可対象等）を洗い出し対策をまとめる
- [ ] sandbox-exec 適用時に必要な暗黙許可ディレクトリの草案をまとめる
### このフェーズで決めること
- [ ] sandbox-exec プロファイルにおける FQDN / CIDR 指定方法と制約
- [ ] システムライブラリの暗黙許可セットと管理方法
- [ ] sandbox-exec 実行まわりの UX（エラーメッセージ、デバッグログ）

## フェーズ3: 共通 CLI / 設定と UX 統合
### TODO
- [ ] OS 自動判定と単一 CLI から Linux / macOS 実装を切り替える仕組みを整える
- [ ] CLI フラグ・設定ファイル→中間表現→OS 別実装への変換モジュールを共通化する
- [ ] プロファイル読込・バリデーション・エラーハンドリングを統一し、ログフォーマットを揃える
- [ ] 設定ファイルの検索経路（`--config` 明示、既定ディレクトリ探索）を実装する
### このフェーズで決めること
- [ ] プロファイル配布形式（内蔵テンプレート、外部ファイル、バンドル方法）
- [ ] ユーザー向けメッセージ仕様（成功 / 失敗 / 警告）
- [ ] CLI フラグと設定ファイルの優先順位、重複指定時の扱い
- [ ] 最低限のドキュメント構成（README、クイックスタート、FAQ）

## フェーズ4: MVP 検証とドキュメント整備
### TODO
- [ ] 代表的ユースケースに対する E2E テストと CI 自動検証を作成する
- [ ] CLI 使用例・設定ファイル例・制限事項を整理しドキュメント化する
- [ ] MVP 完了条件レビューと残課題の洗い出しを行う
### このフェーズで決めること
- [ ] テストカバレッジの最小ライン（OS / 操作ケースごと）
- [ ] 公開時に明記する既知の制限と今後の拡張候補
- [ ] MVP 完了の正式判断プロセス
