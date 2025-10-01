# eBPF LSMを使用したファイルアクセス制御の設計

このドキュメントでは、eBPF LSM (Linux Security Module) を使用してmoriにファイルアクセス制御を実装する設計について説明します。

## 目次

- [概要](#概要)
- [アーキテクチャ](#アーキテクチャ)
- [設定ファイル形式](#設定ファイル形式)
- [eBPFプログラム設計](#ebpfプログラム設計)
- [ユーザースペース実装](#ユーザースペース実装)
- [ネットワーク制御との統合](#ネットワーク制御との統合)
- [設計上の考慮事項](#設計上の考慮事項)
- [テスト戦略](#テスト戦略)
- [実装ロードマップ](#実装ロードマップ)

## 概要

### 背景

当初、ファイルアクセス制御にLandlockの使用を検討しましたが、Landlockは**ホワイトリスト**モード（デフォルト拒否、特定パスのみ許可）のみをサポートしています。より良いユーザー体験のためには、**ブラックリスト**モード（デフォルト許可、特定パスのみ拒否）が必要です。

bubblewrapを調査したところ、マウント名前空間を使用したホワイトリストアプローチを採用していることがわかりました。そのため、柔軟なブラックリストベースのファイルアクセス制御を可能にする**eBPF LSM**を選択しました。

### なぜeBPF LSMなのか？

1. **既存のネットワーク制御と一貫性がある** - すでに`aya`とeBPFを使用している
2. **カーネルレベルの強制** - 回避不可能
3. **柔軟なブラックリストモード** - デフォルト許可、特定パスのみ拒否
4. **良好なパフォーマンス** - 最小限のオーバーヘッド
5. **拡張性** - 将来的に他のセキュリティポリシーを追加可能

### システム要件

現在のシステムで確認済み：
- ✅ カーネルバージョン: 6.15.11 (>= 5.7が必要)
- ✅ `CONFIG_BPF_LSM=y` が有効
- ✅ `lsm=bpf` がアクティブ（`/sys/kernel/security/lsm`内）

追加のカーネル設定やGRUBの変更は不要です。

## アーキテクチャ

### アーキテクチャ図

```
User Space                         Kernel Space
─────────────────────────────────────────────────────────
mori CLI
  ├─ FilePolicy                    eBPF LSM
  │   ├─ blocked_paths       ───►  BLOCK_PATHS (BPF Map)
  │   └─ blocked_patterns          ├─ file_open hook
  │                                 ├─ inode_permission hook
  ├─ FileEbpf                       └─ path_truncate hook
  │   ├─ load()
  │   ├─ attach()              Child Process
  │   └─ block_path()               │
  │                                 ├─ open("/home/user/.ssh/id_rsa")
  └─ execute_with_file_control      │
      ├─ load eBPF                  └─ LSM hook ───► EPERM
      ├─ block paths
      └─ exec command
```

### ネットワーク制御との比較

| 項目               | ネットワーク制御             | ファイル制御                              |
|--------------------|------------------------------|-------------------------------------------|
| **スコープ**       | cgroup単位                   | **システムワイド** または PIDフィルタ     |
| **フック**         | `cgroup_sock_addr::connect4` | `lsm::file_open`, `lsm::inode_permission` |
| **アタッチ先**     | cgroup fd                    | システム全体 (LSM)                        |
| **ポリシータイプ** | ホワイトリスト（許可IP）     | **ブラックリスト（拒否パス）**            |
| **Map構造**        | `HashMap<u32, u8>` (IP→許可) | `HashMap<[u8; 256], u8>` (パス→拒否)      |

## 設定ファイル形式

### TOML設定ファイル

```toml
[network]
allow = [
    "192.0.2.1",
    "example.com"
]

[file]
# ブラックリスト: 指定したパスへのアクセスを拒否
deny = [
    "/home/user/.ssh",              # ディレクトリ全体
    "/home/user/.aws/credentials",  # 特定ファイル
    "/etc/shadow",
]

# パターンマッチング（将来の拡張）
# deny_patterns = [
#     "/home/*/.ssh/*",
#     "*.pem",
# ]
```

### CLIオプション

```bash
# 設定ファイル経由
mori --config config.toml -- curl https://example.com

# CLIオプション経由
mori --deny-file /home/user/.ssh --deny-file /etc/shadow -- bash

# 組み合わせ（設定ファイル + CLI）
mori --config config.toml --deny-file /tmp/secret.txt -- python script.py
```

### CLI引数構造

**src/cli/args.rs**（現在の実装 + ファイル制御の拡張予定）:

```rust
#[derive(Parser, Debug)]
#[command(author, version, about = "eBPFを使用したLinux向けネットワーク・ファイルサンドボックス")]
pub struct Args {
    /// 設定ファイルのパス（TOML）
    #[arg(long = "config", value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// 指定したホスト[:ポート]への外部接続を許可（FQDN/IP）
    #[cfg(not(target_os = "macos"))]
    #[arg(long = "allow-network", value_delimiter = ',')]
    pub allow_network: Vec<String>,

    /// すべての外部ネットワーク接続を許可
    #[arg(long = "allow-network-all")]
    pub allow_network_all: bool,

    /// 指定したファイルまたはディレクトリパスへのアクセスを拒否（将来実装予定）
    #[cfg(target_os = "linux")]
    #[arg(long = "deny-file", value_delimiter = ',')]
    pub deny_file: Vec<PathBuf>,

    /// 実行するコマンド
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}
```

**注意点**:
- `allow_network`は`cfg(not(target_os = "macos"))`でLinuxのみ有効
- `allow_network_all`はすべてのネットワーク接続を許可する簡易オプション
- `deny_file`は将来実装予定で、`cfg(target_os = "linux")`でLinuxのみ有効とする想定

## eBPFプログラム設計

### 使用するLSMフック

| フック名           | 用途                                | トリガー                          |
|--------------------|-------------------------------------|-----------------------------------|
| `file_open`        | ファイルオープン操作を監視          | `open()`, `openat()`              |
| `inode_permission` | ファイル/ディレクトリの権限チェック | `read()`, `write()`, `stat()`など |
| `path_truncate`    | ファイルの切り詰め                  | `truncate()`                      |

**推奨**: まず`file_open`のみを実装し、検証後に他のフックを追加

### BPF Maps

```rust
// ブロックするパスのリスト（パスあたり最大256バイト）
#[map]
static BLOCK_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(1024, 0);

// プロセスフィルタ（特定のPIDのみ制御する場合）
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(128, 0);
```

### BPFプログラム構造

**mori-bpf/src/main.rs**（追加分）:

```rust
use aya_ebpf::{
    macros::{lsm, map},
    maps::HashMap,
    programs::LsmContext,
    helpers::bpf_probe_read_kernel,
};

// ブロックするパスのリスト（パスあたり最大256バイト）
#[map]
static BLOCK_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(1024, 0);

// プロセスフィルタ（特定のPIDのみ制御する場合）
#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(128, 0);

#[lsm(hook = "file_open")]
pub fn mori_file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // エラー時は許可（安全側に倒す）
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // PIDフィルタリング（オプション）
    let pid = bpf_get_current_pid_tgid() >> 32;
    if unsafe { TARGET_PIDS.get(&(pid as u32)).is_none() } {
        return Ok(0); // 対象プロセスでない場合は許可
    }

    // コンテキストからfileポインタを取得
    let file: *const File = unsafe { ctx.arg(0) };

    // file構造体からパスを抽出
    let mut path_buf = [0u8; 256];
    unsafe {
        bpf_d_path(
            &bpf_probe_read_kernel(&(*file).f_path)?,
            &mut path_buf,
            path_buf.len() as u32
        )?;
    }

    // ブロックリストをチェック
    if unsafe { BLOCK_PATHS.get(&path_buf).is_some() } {
        // ブロック対象
        return Ok(-1); // -EPERM
    }

    // プレフィックスマッチング（ディレクトリツリー全体をブロック）
    // 例: /home/user/.ssh がブロックされている場合、/home/user/.ssh/id_rsa もブロック
    if is_prefix_blocked(&path_buf)? {
        return Ok(-1);
    }

    Ok(0) // 許可
}

// ヘルパー関数: パスがブロックされたディレクトリ配下にあるかチェック
fn is_prefix_blocked(path: &[u8; 256]) -> Result<bool, i32> {
    // BPF Mapの全エントリをイテレートするのは非効率なので、
    // 別途PREFIX_BLOCKSマップを用意するか、
    // ユーザースペースで展開したパスリストを使用
    Ok(false) // 簡易実装: まずは完全一致のみ
}
```

## ユーザースペース実装

### FilePolicy構造体

**src/policy/file.rs**:

```rust
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FilePolicy {
    /// ブロックするパスのリスト
    pub denied_paths: Vec<PathBuf>,
}

impl FilePolicy {
    pub fn new(denied_paths: Vec<PathBuf>) -> Self {
        Self { denied_paths }
    }

    /// パスを正規化（絶対パスに変換）
    pub fn normalize(&mut self) -> Result<(), std::io::Error> {
        self.denied_paths = self.denied_paths
            .iter()
            .map(|p| p.canonicalize())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}
```

### FileEbpf構造体

**src/runtime/linux/file_ebpf.rs**（新規ファイル）:

```rust
use aya::{Ebpf, maps::HashMap, programs::Lsm};
use std::path::Path;
use crate::error::MoriError;

pub struct FileEbpf {
    bpf: Ebpf,
}

impl FileEbpf {
    /// eBPFプログラムをロード・アタッチ
    pub fn load_and_attach() -> Result<Self, MoriError> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(env!("MORI_BPF_ELF")))?;

        let program: &mut Lsm = bpf
            .program_mut("mori_file_open")
            .ok_or_else(|| MoriError::ProgramNotFound {
                name: "mori_file_open".to_string(),
            })?
            .try_into()
            .map_err(|source| MoriError::ProgramPrepare {
                name: "mori_file_open".to_string(),
                source,
            })?;

        program.load().map_err(|source| MoriError::ProgramPrepare {
            name: "mori_file_open".to_string(),
            source,
        })?;

        program.attach().map_err(|source| MoriError::ProgramAttach {
            name: "mori_file_open".to_string(),
            source,
        })?;

        Ok(Self { bpf })
    }

    /// ブロックリストにパスを追加
    pub fn block_path(&mut self, path: &Path) -> Result<(), MoriError> {
        let mut map: HashMap<_, [u8; 256], u8> =
            HashMap::try_from(self.bpf.map_mut("BLOCK_PATHS").unwrap())?;

        let path_str = path.to_str()
            .ok_or_else(|| MoriError::InvalidPath(path.to_path_buf()))?;

        if path_str.len() >= 256 {
            return Err(MoriError::PathTooLong(path.to_path_buf()));
        }

        let mut key = [0u8; 256];
        key[..path_str.len()].copy_from_slice(path_str.as_bytes());

        map.insert(key, 1, 0)?;

        Ok(())
    }

    /// 対象プロセスを追加（PIDフィルタリング用）
    pub fn add_target_pid(&mut self, pid: u32) -> Result<(), MoriError> {
        let mut map: HashMap<_, u32, u8> =
            HashMap::try_from(self.bpf.map_mut("TARGET_PIDS").unwrap())?;

        map.insert(pid, 1, 0)?;
        Ok(())
    }
}
```

### 実行関数

**src/runtime/linux/mod.rs**（追加分）:

```rust
mod file_ebpf;
use file_ebpf::FileEbpf;
use crate::policy::file::FilePolicy;

pub async fn execute_with_file_control(
    command: &str,
    args: &[&str],
    file_policy: &FilePolicy,
) -> Result<i32, MoriError> {
    // eBPFプログラムをロード・アタッチ
    let mut file_ebpf = FileEbpf::load_and_attach()?;

    // ブロックパスを登録
    for path in &file_policy.denied_paths {
        file_ebpf.block_path(path)?;
        println!("Blocked path: {}", path.display());
    }

    // コマンドを実行
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // PIDをターゲットリストに追加
    file_ebpf.add_target_pid(child.id())?;

    let status = child.wait()?;

    // FileEbpfがDropされると自動的にデタッチされる
    Ok(status.code().unwrap_or(-1))
}
```

## ネットワーク制御との統合

### 統合制御関数

**src/runtime/linux/mod.rs**:

```rust
pub async fn execute_with_controls(
    command: &str,
    args: &[&str],
    network_policy: Option<&NetworkPolicy>,
    file_policy: Option<&FilePolicy>,
) -> Result<i32, MoriError> {
    // ファイル制御をロード
    let mut file_ebpf = if let Some(policy) = file_policy {
        let mut ebpf = FileEbpf::load_and_attach()?;
        for path in &policy.denied_paths {
            ebpf.block_path(path)?;
        }
        Some(ebpf)
    } else {
        None
    };

    // ネットワーク制御をロード
    let cgroup = if network_policy.is_some() {
        Some(CgroupManager::create()?)
    } else {
        None
    };

    let network_ebpf = if let (Some(policy), Some(ref cgroup)) = (network_policy, &cgroup) {
        let ebpf = setup_network_ebpf(cgroup.fd(), policy)?;
        Some(ebpf)
    } else {
        None
    };

    // コマンドを実行
    let mut child = Command::new(command)
        .args(args)
        .spawn()?;

    // PIDベースの制御を適用
    if let Some(ref cgroup) = cgroup {
        cgroup.add_process(child.id())?;
    }
    if let Some(ref mut febpf) = file_ebpf {
        febpf.add_target_pid(child.id())?;
    }

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}
```

### 設定ファイルの更新

**src/cli/config.rs**:

```rust
use crate::policy::{NetworkPolicy, file::FilePolicy};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub network: NetworkConfig,

    #[serde(default)]
    pub file: FileConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct FileConfig {
    /// アクセスを拒否するパス
    #[serde(default)]
    pub deny: Vec<PathBuf>,
}

impl ConfigFile {
    pub fn to_file_policy(&self) -> FilePolicy {
        FilePolicy::new(self.file.deny.clone())
    }
}
```

## 設計上の考慮事項

### PIDフィルタリングの必要性と仕組み

**LSMはシステムワイド**で動作するため、PIDフィルタリングが重要です。

#### 動作の仕組み

LSMフックはシステム全体のすべてのファイルオープンで呼び出されますが、BPFプログラム内で以下の順序でチェックします：

```rust
fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // ステップ1: まずPIDをチェック（高速パス）
    let pid = bpf_get_current_pid_tgid() >> 32;
    if unsafe { TARGET_PIDS.get(&(pid as u32)).is_none() } {
        return Ok(0); // 対象プロセスでない → すぐに許可して終了
    }

    // ステップ2: 対象プロセスの場合のみ、パスをチェック（制御パス）
    let file: *const File = unsafe { ctx.arg(0) };
    // ... パスを取得してBLOCK_PATHSをチェック
}
```

**重要なポイント**:
1. システム全体でLSMフックは呼ばれるが、PIDチェックで早期リターン
2. `TARGET_PIDS`に含まれないプロセスは、パス取得などの重い処理をスキップ
3. moriで管理しているプロセスのみ、ファイルパスのブロックチェックを実行

#### アプローチの比較

| アプローチ | メリット | デメリット | パフォーマンス影響 |
|----------|---------|----------|------------------|
| **PIDフィルタあり** | 他のプロセスに影響なし | PID管理が必要、子プロセス追跡が複雑 | ほぼなし（PIDチェックのみ） |
| **PIDフィルタなし** | シンプル | システム全体に影響、危険 | すべてのプロセスでパスチェック |

**推奨**: PIDフィルタありで実装（セキュリティとパフォーマンスの両立）

### パスマッチング戦略

```rust
// 戦略1: 完全一致のみ（シンプル）
"/home/user/.ssh" をブロック → "/home/user/.ssh" のみブロック

// 戦略2: プレフィックスマッチング（推奨）
"/home/user/.ssh" をブロック → "/home/user/.ssh/*" もブロック

// 戦略3: globパターン（複雑）
"/home/*/.ssh/*" のようなパターンマッチ
```

**推奨**: 戦略2（プレフィックスマッチング）をユーザースペースで展開

### プレフィックスマッチングの実装

**採用方針: アプローチA（ユーザースペースでのパス展開）**

ディレクトリ指定時に、そのディレクトリとディレクトリ配下のプレフィックスパターンをBPF Mapに登録します。

#### 実装方式

```rust
// ユーザーが指定: /home/user/.ssh
// ユーザースペースで以下のようにBPF mapに登録:
impl FileEbpf {
    pub fn block_path(&mut self, path: &Path) -> Result<(), MoriError> {
        let path_str = path.to_str()
            .ok_or_else(|| MoriError::InvalidPath(path.to_path_buf()))?;

        // 1. パス自体をブロックリストに追加
        self.add_to_block_map(path_str)?;

        // 2. ディレクトリの場合、末尾に "/" を追加したプレフィックスも登録
        if path.is_dir() {
            let prefix = format!("{}/", path_str);
            self.add_to_block_map(&prefix)?;
        }

        Ok(())
    }

    fn add_to_block_map(&mut self, path_str: &str) -> Result<(), MoriError> {
        if path_str.len() >= 256 {
            return Err(MoriError::PathTooLong(PathBuf::from(path_str)));
        }

        let mut key = [0u8; 256];
        key[..path_str.len()].copy_from_slice(path_str.as_bytes());

        let mut map: HashMap<_, [u8; 256], u8> =
            HashMap::try_from(self.bpf.map_mut("BLOCK_PATHS").unwrap())?;
        map.insert(key, 1, 0)?;

        Ok(())
    }
}
```

#### BPF側のマッチングロジック

```rust
fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // ... PIDチェック省略 ...

    let mut path_buf = [0u8; 256];
    // パスを取得

    // 1. 完全一致チェック
    if unsafe { BLOCK_PATHS.get(&path_buf).is_some() } {
        return Ok(-1); // ブロック
    }

    // 2. プレフィックスマッチング
    // 例: path_buf が "/home/user/.ssh/id_rsa" の場合
    // "/home/user/.ssh/" がBLOCK_PATHSに登録されていればマッチ
    if is_prefix_blocked(&path_buf)? {
        return Ok(-1); // ブロック
    }

    Ok(0) // 許可
}

// プレフィックスマッチングのヘルパー関数
fn is_prefix_blocked(path: &[u8; 256]) -> Result<bool, i32> {
    // パスを "/" で区切りながら、各階層でチェック
    // 例: "/home/user/.ssh/id_rsa" に対して
    // "/home/" → チェック
    // "/home/user/" → チェック
    // "/home/user/.ssh/" → ブロックリストにあればマッチ

    let mut i = 0;
    while i < 256 && path[i] != 0 {
        if path[i] == b'/' && i > 0 {
            // この位置までのパス + "/" をチェック
            let mut prefix = [0u8; 256];
            prefix[..=i].copy_from_slice(&path[..=i]);

            if unsafe { BLOCK_PATHS.get(&prefix).is_some() } {
                return Ok(true); // ブロック
            }
        }
        i += 1;
    }

    Ok(false)
}
```

#### この方式のメリット

1. **シンプル**: ユーザースペースでディレクトリ判定してプレフィックスを登録するだけ
2. **効率的**: 既存のファイルを再帰的に走査する必要がない
3. **動的対応**: 後から作成されたファイルも自動的にブロック対象になる
4. **Map容量**: ユーザー指定のパス数 × 2程度（ディレクトリの場合）のエントリで済む

#### デメリットと対策

- **BPF側の処理が少し複雑**: プレフィックスマッチングのループが必要
  - 対策: パスの深さは通常10階層程度なので、パフォーマンス影響は小さい
- **パスの最大長が256バイト**: 非常に長いパスは扱えない
  - 対策: エラーで明示的に通知、必要に応じて上位ディレクトリを指定してもらう

**Phase 1では、まず完全一致のみ実装し、Phase 2でプレフィックスマッチングを追加する方針とします。**

### セキュリティ考慮事項

#### シンボリックリンクの処理

```rust
impl FilePolicy {
    /// シンボリックリンクを処理するためにパスを正規化
    pub fn normalize(&mut self) -> Result<(), std::io::Error> {
        self.denied_paths = self.denied_paths
            .iter()
            .map(|p| p.canonicalize()) // シンボリックリンクを解決
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }
}
```

#### パストラバーサル

- `..`と`.`を解決するために`canonicalize()`を使用
- ブロックリストに追加する前にパスを検証
- 競合状態（TOCTOU）を考慮

#### 必要な権限

- **LSMアタッチにroot/CAP_BPF権限が必要**
- この要件をユーザー向けに明確に文書化
- 起動時に権限チェックを検討

### 子プロセスの追跡

PIDフィルタリングのために、子プロセスを追跡する必要があります：

```rust
// オプション1: すべての子PIDを手動で追加（モニタリングが必要）
// オプション2: プロセスグループ化にcgroupを使用（ハイブリッドアプローチ）
// オプション3: BPFプログラムが親PIDチェーンをチェック（複雑）
```

**推奨**: 手動PID追加（オプション1）から始め、堅牢性のためcgroupハイブリッド（オプション2）を検討

## テスト戦略

### 単体テスト

```rust
// tests/file_policy_test.rs

#[test]
fn test_block_single_file() {
    let policy = FilePolicy::new(vec![PathBuf::from("/tmp/secret.txt")]);
    // eBPFプログラムをロード、パスを登録
    // open("/tmp/secret.txt") がEPERMになることを確認
}

#[test]
fn test_block_directory() {
    let policy = FilePolicy::new(vec![PathBuf::from("/home/user/.ssh")]);
    // /home/user/.ssh/* へのアクセスがすべてブロックされることを確認
}

#[test]
fn test_allowed_paths() {
    let policy = FilePolicy::new(vec![PathBuf::from("/tmp/blocked.txt")]);
    // /tmp/other.txt がまだアクセス可能であることを確認
}

#[test]
fn test_path_normalization() {
    let mut policy = FilePolicy::new(vec![
        PathBuf::from("/tmp/../etc/shadow"),
    ]);
    policy.normalize().unwrap();
    // /etc/shadow に正規化されることを確認
}
```

### 統合テスト

```bash
#!/bin/bash
# tests/integration/file_access_test.sh

# テスト1: 特定ファイルをブロック
echo "secret" > /tmp/blocked.txt
mori --deny-file /tmp/blocked.txt -- cat /tmp/blocked.txt
# 期待: Permission denied

# テスト2: ブロックされていないファイルは許可
echo "public" > /tmp/allowed.txt
mori --deny-file /tmp/blocked.txt -- cat /tmp/allowed.txt
# 期待: "public"を出力

# テスト3: ディレクトリをブロック
mkdir -p /tmp/blocked_dir
echo "secret" > /tmp/blocked_dir/file.txt
mori --deny-file /tmp/blocked_dir -- cat /tmp/blocked_dir/file.txt
# 期待: Permission denied

# テスト4: ネストしたディレクトリのブロック
mkdir -p /tmp/blocked_dir/subdir
mori --deny-file /tmp/blocked_dir -- ls /tmp/blocked_dir/subdir
# 期待: Permission denied

# テスト5: ネットワーク制御とファイル制御の組み合わせ
mori --deny-file /etc/shadow --allow-network example.com -- bash -c "cat /etc/shadow && curl http://example.com"
# 期待: catは失敗、curlは成功
```

### パフォーマンステスト

```rust
// benches/file_access_bench.rs

#[bench]
fn bench_file_open_with_ebpf(b: &mut Bencher) {
    // ファイル操作に対するeBPF LSMのオーバーヘッドを測定
    b.iter(|| {
        File::open("/tmp/test.txt").unwrap();
    });
}

#[bench]
fn bench_file_open_without_ebpf(b: &mut Bencher) {
    // eBPFなしのベースライン測定
    b.iter(|| {
        File::open("/tmp/test.txt").unwrap();
    });
}
```

### テストデータシナリオ

| シナリオ | ブロックパス | 操作 | 期待結果 |
|----------|-------------|------|---------|
| SSH鍵 | `/home/user/.ssh` | `cat ~/.ssh/id_rsa` | EPERM |
| AWS認証情報 | `/home/user/.aws/credentials` | 認証情報を読み取り | EPERM |
| Shadowファイル | `/etc/shadow` | `cat /etc/shadow` | EPERM |
| Passwdファイル | なし | `cat /etc/passwd` | 成功 |
| ネストしたディレクトリ | `/var/secrets` | `ls /var/secrets/nested/file` | EPERM |

## 実装ロードマップ

### Phase 1: 基本実装（MVP）

**目標**: 最小限の機能でコンセプトを証明

#### 実装項目

- [ ] BPFプログラム実装
  - [ ] `file_open`フックのみ
  - [ ] PIDフィルタリング（`TARGET_PIDS` Map）
  - [ ] 完全一致のパスマッチング（`BLOCK_PATHS` Map）
  - [ ] `bpf_d_path`を使用したパス取得
- [ ] ユーザースペース実装
  - [ ] `FilePolicy`構造体（`src/policy/file.rs`）
  - [ ] `FileEbpf`構造体（`src/runtime/linux/file_ebpf.rs`）
  - [ ] `execute_with_file_control`関数
- [ ] CLI統合
  - [ ] `--deny-file`オプション追加（`src/cli/args.rs`）
  - [ ] エラーハンドリング（`MoriError`に新しいバリアント追加）
- [ ] テスト
  - [ ] 単体テスト（パス正規化など）
  - [ ] 統合テスト（実際のファイルブロック動作確認）

#### 成果物
- 動作するeBPF LSMプログラム
- 特定ファイル（完全一致）へのアクセスをブロック可能
- シンプルなテストで検証可能

#### Phase 1で実装しないこと
- プレフィックスマッチング（Phase 2で実装）
- `inode_permission`や`path_truncate`フック
- Globパターンマッチング
- 設定ファイルの`[file]`セクション（Phase 2で実装）

### Phase 2: プレフィックスマッチングと設定ファイル対応

**目標**: ディレクトリツリーのブロックと設定ファイル対応

#### 実装項目

- [ ] プレフィックスマッチング（アプローチA）
  - [ ] ユーザースペースでディレクトリ判定
  - [ ] ディレクトリの場合、`path/`形式でBPF Mapに追加
  - [ ] BPF側で`is_prefix_blocked`実装
  - [ ] プレフィックスマッチングのテスト追加
- [ ] 設定ファイルサポート
  - [ ] `ConfigFile`に`FileConfig`追加
  - [ ] `[file]` セクションのパース
  - [ ] `to_file_policy()`メソッド実装
- [ ] パスの正規化とシンボリックリンク解決
  - [ ] `FilePolicy::normalize()`の実装強化
  - [ ] シンボリックリンクのテスト
- [ ] エラーメッセージの改善
  - [ ] どのパスがブロックされたか表示
  - [ ] パス正規化失敗時の詳細メッセージ

#### 成果物
- ディレクトリレベルのブロック（`/home/user/.ssh`配下全体）
- 設定ファイル対応（TOML形式）
- より詳細なエラーメッセージ
- プレフィックスマッチングのテストカバレッジ

### Phase 3: 高度な機能

**目標**: 洗練された制御を追加

- [ ] globパターンマッチング（`/home/*/.ssh/*`）
- [ ] 読み取り/書き込みの個別権限
- [ ] `path_truncate`フック
- [ ] 監査ロギング（拒否されたアクセスを記録）
- [ ] パフォーマンス最適化
- [ ] ドキュメントと例

**成果物**:
- フル機能のファイルアクセス制御
- パフォーマンスベンチマーク
- ユーザードキュメント

### Phase 4: プロダクション向けハードニング

**目標**: 堅牢でセキュアにする

- [ ] 子プロセス追跡の改善
- [ ] 競合状態の処理
- [ ] 権限チェック
- [ ] Seccomp統合
- [ ] ファジングテスト
- [ ] セキュリティ監査

**成果物**:
- プロダクション対応リリース
- セキュリティドキュメント
- パフォーマンスレポート

## エラー処理

### 新しいエラータイプ

**src/error.rs**（追加分）:

```rust
#[derive(Error, Debug)]
pub enum MoriError {
    // ... 既存のバリアント ...

    #[error("無効なファイルパス: {0}")]
    InvalidPath(PathBuf),

    #[error("パスが長すぎます（最大256バイト）: {0}")]
    PathTooLong(PathBuf),

    #[error("パスの正規化に失敗しました: {0}")]
    PathNormalization(#[from] std::io::Error),

    #[error("LSMプログラムが見つかりません: {name}")]
    LsmProgramNotFound { name: String },
}
```

## 参考資料

### ドキュメント

- [eBPF LSM ドキュメント](https://docs.kernel.org/bpf/prog_lsm.html)
- [Aya ドキュメント](https://aya-rs.dev/)
- [BPF LSM チュートリアル](https://eunomia.dev/tutorials/19-lsm-connect/)

### 関連プロジェクト

- [ebpfguard](https://github.com/deepfence/ebpfguard) - eBPF LSM用のRustライブラリ
- [bpflock](https://github.com/linux-lock/bpflock) - eBPFベースのセキュリティポリシー
- [bubblewrap](https://github.com/containers/bubblewrap) - マウント名前空間サンドボックス

### 事前調査

- bubblewrapアーキテクチャの調査
- FUSE、eBPF LSM、ptrace、マウント名前空間アプローチの比較
- 現在のシステムでのカーネルLSMサポートの検証

## 将来的な検討事項

### 潜在的な拡張

1. **MAC（強制アクセス制御）**
   - SELinuxライクなポリシー定義
   - ロールベースアクセス制御

2. **ファイル完全性監視**
   - 不正な変更の検出
   - 暗号化ハッシュ検証

3. **ネットワーク-ファイルポリシーの相関**
   - ネットワークアクティビティに基づくファイルアクセスのブロック
   - データ流出の防止

4. **コンテナ統合**
   - OCIランタイムフック
   - Kubernetesアドミッションコントローラー

### パフォーマンス最適化

1. **パスキャッシング**
   - BPF mapに解決済みパスをキャッシュ
   - `bpf_d_path`のオーバーヘッドを削減

2. **バッチ操作**
   - BLOCK_PATHS mapの一括更新
   - システムコールのオーバーヘッドを削減

3. **選択的フックアタッチ**
   - ファイルポリシーがアクティブな場合のみフックをアタッチ
   - ネットワークのみのシナリオでのオーバーヘッドを削減

## 結論

この設計は、eBPF LSMを使用してmoriにファイルアクセス制御を実装するための包括的な青写真を提供します。このアプローチは：

- **一貫性がある** - 既存のネットワーク制御アーキテクチャと統一
- **柔軟** - より良いUXのためのブラックリストモード
- **セキュア** - カーネルレベルでの強制、回避不可能
- **高性能** - 最小限のオーバーヘッド
- **拡張可能** - 将来の拡張機能に対応

段階的な実装ロードマップにより、堅牢でプロダクション対応のソリューションに向けて構築しながら、段階的に価値を提供できます。
