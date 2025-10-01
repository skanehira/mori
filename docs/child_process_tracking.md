# 子プロセス追跡の実装方式の比較

eBPF LSMを使用したファイルアクセス制御では、PIDフィルタリングにより対象プロセスのみを制御します。しかし、対象プロセスが`fork()`や`clone()`で子プロセスを作成した場合、その子プロセスも追跡する必要があります。

このドキュメントでは、子プロセス追跡の3つの実装方式を比較します。

## 前提：なぜ子プロセス追跡が必要か

LSMフックはシステムワイドで動作しますが、PIDフィルタリングで対象プロセスのみを制御します：

```rust
fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // ステップ1: PIDチェック
    let pid = bpf_get_current_pid_tgid() >> 32;
    if unsafe { TARGET_PIDS.get(&(pid as u32)).is_none() } {
        return Ok(0); // 対象プロセスでない → 許可
    }

    // ステップ2: 対象プロセスの場合のみパスチェック
    // ...
}
```

**問題**: 初期プロセス（moriで起動したプロセス）のPIDしか`TARGET_PIDS`に登録していない場合、そのプロセスが`fork()`で作成した子プロセスは`TARGET_PIDS`に含まれず、ファイルアクセス制御が適用されない。

**例**:
```bash
# moriで起動
mori --deny-file /etc/shadow -- bash

# bash (PID=1234) は制御対象
bash$ cat /etc/shadow  # → EPERM (ブロックされる)

# bashが子プロセスを起動
bash$ python3 script.py  # python3 (PID=1235) は制御対象外！

# python3からはアクセス可能になってしまう
import subprocess
subprocess.run(['cat', '/etc/shadow'])  # → 成功してしまう！
```

この問題を解決するため、子プロセスも自動的に`TARGET_PIDS`に追加する必要があります。

## オプション1: 手動PID追加（最もシンプル）

### 概要

初期プロセスのPIDのみを`TARGET_PIDS`に追加し、子プロセスは追跡しない。

### 実装

```rust
// src/runtime/linux/mod.rs

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
    }

    // コマンドを実行
    let mut child = Command::new(command)
        .args(args)
        .spawn()?;

    // 初期プロセスのPIDのみ追加
    file_ebpf.add_target_pid(child.id())?;

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}
```

### メリット

1. **実装が最もシンプル** - 追加のコードが不要
2. **オーバーヘッドなし** - 余計な処理が一切ない
3. **理解しやすい** - 動作が明確

### デメリット

1. **子プロセスが制御対象外** - セキュリティホールになる
2. **回避が容易** - `bash -c 'cat /etc/shadow'` のような回避が可能
3. **実用性が低い** - プロダクション環境では使えない

### 適用シーン

- MVP（概念実証）での動作確認
- 単一プロセスのみを制御する場合
- 開発・テスト環境

## オプション2: cgroupハイブリッドアプローチ

### 概要

cgroupを使用してプロセスグループを管理し、`cgroup.procs`をポーリングして新しいプロセスを検出し、`TARGET_PIDS`に追加する。

### 実装

#### プロセストラッカー

```rust
// src/runtime/linux/process_tracker.rs

use std::collections::HashSet;
use std::time::Duration;
use tokio::time;

/// cgroupを監視して、新しいプロセスをファイル制御のターゲットに追加
pub async fn track_child_processes(
    cgroup: CgroupManager,
    file_ebpf: Arc<Mutex<FileEbpf>>,
) -> Result<(), MoriError> {
    let mut known_pids = HashSet::new();

    loop {
        // cgroup.procsから現在のPID一覧を取得
        let current_pids = cgroup.get_process_list()?;

        // 新しく追加されたPIDを検出
        for pid in &current_pids {
            if !known_pids.contains(pid) {
                // 新しいプロセスをファイル制御のターゲットに追加
                let mut ebpf = file_ebpf.lock().unwrap();
                ebpf.add_target_pid(*pid)?;
                println!("Added child process {} to file control", pid);
                known_pids.insert(*pid);
            }
        }

        // 終了したプロセスをセットから削除
        known_pids.retain(|pid| current_pids.contains(pid));

        // cgroupが空になったら終了
        if current_pids.is_empty() {
            break;
        }

        // 100msごとにチェック
        time::sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}
```

#### CgroupManagerの拡張

```rust
// src/runtime/linux/cgroup.rs

impl CgroupManager {
    /// cgroup内のプロセス一覧を取得
    pub fn get_process_list(&self) -> Result<Vec<u32>, MoriError> {
        let procs_path = self.path.join("cgroup.procs");
        let content = std::fs::read_to_string(&procs_path)?;

        let pids: Vec<u32> = content
            .lines()
            .filter_map(|line| line.trim().parse().ok())
            .collect();

        Ok(pids)
    }
}
```

#### 統合

```rust
// src/runtime/linux/mod.rs

pub async fn execute_with_controls(
    command: &str,
    args: &[&str],
    network_policy: Option<&NetworkPolicy>,
    file_policy: Option<&FilePolicy>,
) -> Result<i32, MoriError> {
    // cgroupを作成（子プロセス追跡のため）
    let cgroup = if network_policy.is_some() || file_policy.is_some() {
        Some(CgroupManager::create()?)
    } else {
        None
    };

    // ネットワーク制御のeBPF（cgroupにアタッチ）
    let network_ebpf = if let (Some(policy), Some(ref cgroup)) = (network_policy, &cgroup) {
        let ebpf = setup_network_ebpf(cgroup.fd(), policy)?;
        Some(ebpf)
    } else {
        None
    };

    // ファイル制御のeBPF（システムワイドにアタッチ）
    let file_ebpf = if let Some(policy) = file_policy {
        let mut ebpf = FileEbpf::load_and_attach()?;
        for path in &policy.denied_paths {
            ebpf.block_path(path)?;
        }
        Some(Arc::new(Mutex::new(ebpf)))
    } else {
        None
    };

    // コマンドを実行
    let mut child = Command::new(command).args(args).spawn()?;

    // cgroupにプロセスを追加
    if let Some(ref cgroup) = cgroup {
        cgroup.add_process(child.id())?;
    }

    // 初期プロセスのPIDを追加
    if let Some(ref febpf) = file_ebpf {
        febpf.lock().unwrap().add_target_pid(child.id())?;
    }

    // 子プロセス追跡タスクを起動
    let tracker_handle = if let (Some(febpf), Some(cg)) = (&file_ebpf, &cgroup) {
        let febpf_clone = Arc::clone(febpf);
        let cg_clone = cg.clone();
        Some(tokio::spawn(async move {
            track_child_processes(cg_clone, febpf_clone).await
        }))
    } else {
        None
    };

    let status = child.wait()?;

    // トラッカータスクの終了を待つ
    if let Some(handle) = tracker_handle {
        handle.await??;
    }

    Ok(status.code().unwrap_or(-1))
}
```

### メリット

1. **自動的な子プロセス追跡** - `fork()`/`clone()`で作成された子プロセスを自動検出
2. **確実性** - cgroupの仕組みでプロセスグループが管理される
3. **ネットワーク制御との統合** - 既存のcgroupを活用

### デメリット

1. **ポーリングが必要** - `cgroup.procs`を定期的に読む必要がある
2. **遅延が発生** - 100ms程度の検出遅延がある
3. **ファイル制御のみでもcgroupが必要** - オーバーヘッドが増加
4. **非同期タスクの管理** - 実装が複雑化

### 代替実装: inotifyを使った通知ベース

ポーリングの代わりに、`cgroup.procs`ファイルの変更を`inotify`で監視する方法：

```rust
use tokio::fs::File;
use tokio::io::{AsyncReadExt};
use inotify::{Inotify, WatchMask};

async fn watch_cgroup_procs(
    cgroup: CgroupManager,
    file_ebpf: Arc<Mutex<FileEbpf>>,
) -> Result<(), MoriError> {
    let procs_path = cgroup.path.join("cgroup.procs");

    let mut inotify = Inotify::init()?;
    inotify.add_watch(&procs_path, WatchMask::MODIFY)?;

    let mut buffer = [0u8; 4096];
    loop {
        let events = inotify.read_events_blocking(&mut buffer)?;

        for event in events {
            if event.mask.contains(inotify::EventMask::MODIFY) {
                // cgroup.procsが変更された → PID一覧を再読み込み
                sync_pids_to_file_control(&cgroup, &file_ebpf)?;
            }
        }
    }

    Ok(())
}
```

**inotifyの問題点**:
- `cgroup.procs`は特殊ファイルで、`inotify`が正しく動作しない可能性がある
- カーネルバージョンやcgroup v1/v2で挙動が異なる

### 適用シーン

- プロダクション環境でネットワーク制御も使う場合
- 確実性を重視する場合
- 100ms程度の遅延が許容できる場合

## オプション3: eBPFトレースポイント（★推奨）

### 概要

`sched_process_fork`トレースポイントをeBPFで監視し、親プロセスが対象の場合、子プロセスを自動的に`TARGET_PIDS`に追加する。

### 実装

#### BPFプログラム

```rust
// mori-bpf/src/main.rs

use aya_ebpf::{
    macros::{lsm, tracepoint, map},
    maps::HashMap,
    programs::{LsmContext, TracePointContext},
    helpers::bpf_get_current_pid_tgid,
};

// 既存のMaps
#[map]
static BLOCK_PATHS: HashMap<[u8; 256], u8> = HashMap::with_max_entries(1024, 0);

#[map]
static TARGET_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(128, 0);

// ★子プロセス追跡用のトレースポイント
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_track_fork(ctx) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

fn try_track_fork(ctx: TracePointContext) -> Result<(), i64> {
    // トレースポイントの構造体定義（BTFを使用）
    #[repr(C)]
    struct SchedProcessFork {
        common_type: u16,
        common_flags: u8,
        common_preempt_count: u8,
        common_pid: i32,
        parent_comm: [u8; 16],
        parent_pid: i32,
        child_comm: [u8; 16],
        child_pid: i32,
    }

    // イベントデータを読み取り
    let event: SchedProcessFork = unsafe { ctx.read_at(0)? };
    let parent_pid = event.parent_pid as u32;
    let child_pid = event.child_pid as u32;

    // 親プロセスが対象（TARGET_PIDSに含まれる）かチェック
    if unsafe { TARGET_PIDS.get(&parent_pid).is_none() } {
        return Ok(()); // 対象外の親 → 何もしない
    }

    // 子プロセスをTARGET_PIDSに追加
    unsafe {
        TARGET_PIDS.insert(&child_pid, &1, 0)?;
    }

    Ok(())
}

// 既存のfile_openフック（変更なし）
#[lsm(hook = "file_open")]
pub fn mori_file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    // PIDチェック
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { TARGET_PIDS.get(&pid).is_none() } {
        return Ok(0); // 対象プロセスでない → 許可
    }

    // パスチェック
    // ... （既存の実装）

    Ok(0)
}
```

#### ユーザースペース

```rust
// src/runtime/linux/file_ebpf.rs

use aya::{Ebpf, maps::HashMap, programs::{Lsm, TracePoint}};
use std::path::Path;
use crate::error::MoriError;

pub struct FileEbpf {
    bpf: Ebpf,
}

impl FileEbpf {
    /// eBPFプログラムをロード・アタッチ
    pub fn load_and_attach() -> Result<Self, MoriError> {
        let mut bpf = Ebpf::load(include_bytes_aligned!(env!("MORI_BPF_ELF")))?;

        // LSMフック（file_open）をアタッチ
        let lsm_program: &mut Lsm = bpf
            .program_mut("mori_file_open")
            .ok_or_else(|| MoriError::ProgramNotFound {
                name: "mori_file_open".to_string(),
            })?
            .try_into()
            .map_err(|source| MoriError::ProgramPrepare {
                name: "mori_file_open".to_string(),
                source,
            })?;

        lsm_program.load().map_err(|source| MoriError::ProgramPrepare {
            name: "mori_file_open".to_string(),
            source,
        })?;

        lsm_program.attach().map_err(|source| MoriError::ProgramAttach {
            name: "mori_file_open".to_string(),
            source,
        })?;

        // ★トレースポイント（sched_process_fork）をアタッチ
        let tp_program: &mut TracePoint = bpf
            .program_mut("sched_process_fork")
            .ok_or_else(|| MoriError::ProgramNotFound {
                name: "sched_process_fork".to_string(),
            })?
            .try_into()
            .map_err(|source| MoriError::ProgramPrepare {
                name: "sched_process_fork".to_string(),
                source,
            })?;

        tp_program.load().map_err(|source| MoriError::ProgramPrepare {
            name: "sched_process_fork".to_string(),
            source,
        })?;

        tp_program.attach("sched", "sched_process_fork")
            .map_err(|source| MoriError::ProgramAttach {
                name: "sched_process_fork".to_string(),
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

#### 実行フロー

```rust
// src/runtime/linux/mod.rs

pub async fn execute_with_file_control(
    command: &str,
    args: &[&str],
    file_policy: &FilePolicy,
) -> Result<i32, MoriError> {
    // 1. eBPFプログラムをロード・アタッチ
    //    → file_openフックとsched_process_forkトレースポイントの両方
    let mut file_ebpf = FileEbpf::load_and_attach()?;

    // 2. ブロックパスを登録
    for path in &file_policy.denied_paths {
        file_ebpf.block_path(path)?;
        println!("Blocked path: {}", path.display());
    }

    // 3. コマンドを実行
    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    // 4. 初期プロセスのPIDを追加
    file_ebpf.add_target_pid(child.id())?;

    // ★これだけ！子プロセスは自動的に追跡される

    let status = child.wait()?;

    // FileEbpfがDropされると自動的にデタッチされる
    Ok(status.code().unwrap_or(-1))
}
```

### 動作フロー

```
初期状態:
  TARGET_PIDS = { 1234 }  // 初期プロセス

プロセス1234がfork()を実行:
  ↓
  カーネルが sched_process_fork トレースポイントを発火
  ↓
  BPFプログラム (sched_process_fork):
    - イベントから parent_pid = 1234 を取得
    - TARGET_PIDSに1234が含まれる？ → Yes
    - イベントから child_pid = 1235 を取得
    - TARGET_PIDS.insert(1235, 1)
  ↓
  TARGET_PIDS = { 1234, 1235 }  // 自動的に追加！

プロセス1235がfork()を実行:
  ↓
  同様に1236も自動追加
  ↓
  TARGET_PIDS = { 1234, 1235, 1236 }

プロセス1235がファイルをオープン:
  ↓
  LSMフック (file_open):
    - pid = 1235
    - TARGET_PIDSに1235が含まれる？ → Yes
    - パスチェック → ブロック判定
```

### メリット

1. **完全自動**: ユーザースペースでのポーリングや非同期タスクが不要
2. **リアルタイム**: `fork()`/`clone()`直後に子プロセスが追跡対象になる
3. **軽量**: カーネル内で完結、オーバーヘッド最小
4. **cgroupが不要**: ファイル制御だけの場合、cgroupを作らなくて良い
5. **確実性**: すべての子プロセス（孫、曽孫...）を自動追跡
6. **シンプルなユーザースペース**: 実装がオプション1とほぼ同じ

### デメリット

1. **トレースポイントの構造体依存**: カーネルバージョンでフィールドのオフセットが変わる可能性
   - 対策: BTF（BPF Type Format）を使って型安全にアクセス
   - Ayaは自動的にBTFをサポート
2. **BPFプログラムの複雑性**: トレースポイントの処理が追加される
   - ただし、ユーザースペースはシンプルなまま
3. **デバッグの難しさ**: カーネル内の動作をデバッグするのは難しい
   - 対策: `bpf_printk`でログ出力

### BTFによる型安全性

最新のカーネル（5.2以降）とAyaでは、BTF（BPF Type Format）により、トレースポイントの構造体に型安全にアクセスできます：

```rust
// Ayaが自動的にBTF情報を使用
#[repr(C)]
struct SchedProcessFork {
    // BTFにより、カーネルバージョンに応じたオフセットが自動的に解決される
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    parent_comm: [u8; 16],
    parent_pid: i32,
    child_comm: [u8; 16],
    child_pid: i32,
}

let event: SchedProcessFork = unsafe { ctx.read_at(0)? };
// BTFがあれば、カーネルバージョンが違っても正しいオフセットでアクセスできる
```

### 適用シーン

- **Phase 2-3での実装を推奨**
- プロダクション環境
- 確実な子プロセス追跡が必要な場合
- ファイル制御のみを使用する場合（cgroupが不要）

## 比較表

| 項目 | オプション1<br/>（手動PID追加） | オプション2<br/>（cgroup） | オプション3<br/>（eBPF）★推奨 |
|------|-------------------------------|------------------------|---------------------------|
| **実装の複雑さ** | 最もシンプル | やや複雑（非同期タスク） | BPF側が少し複雑、ユーザースペースはシンプル |
| **子プロセス追跡** | 手動、見逃す | 自動、ポーリング | **自動、リアルタイム** |
| **追跡の確実性** | 低い（初期プロセスのみ） | 高い（全プロセス） | **最も高い（全プロセス）** |
| **検出遅延** | なし（追跡しない） | 100ms程度 | **ほぼゼロ** |
| **オーバーヘッド** | 最小 | ポーリング/inotifyのオーバーヘッド | **最小（カーネル内で完結）** |
| **cgroupの要否** | 不要 | 必要 | **不要** |
| **ユーザースペースの複雑さ** | 最もシンプル | 非同期タスク管理が必要 | **シンプル** |
| **カーネル依存性** | なし | cgroup v2必須 | BTF対応カーネル推奨（5.2+） |
| **セキュリティホール** | あり（子プロセスで回避可能） | なし | **なし** |
| **実装時期** | Phase 1 | Phase 4（非推奨） | **Phase 2-3** |

## 推奨実装戦略

### Phase 1: MVPでの動作確認

**オプション1（手動PID追加）を採用**

- 最もシンプルで理解しやすい
- 基本的なeBPF LSMの動作を確認
- 単一プロセスでの動作テスト

```rust
// Phase 1: 簡易実装
pub async fn execute_with_file_control(
    command: &str,
    args: &[&str],
    file_policy: &FilePolicy,
) -> Result<i32, MoriError> {
    let mut file_ebpf = FileEbpf::load_and_attach()?;

    for path in &file_policy.denied_paths {
        file_ebpf.block_path(path)?;
    }

    let mut child = Command::new(command).args(args).spawn()?;

    // 初期プロセスのみ追跡
    file_ebpf.add_target_pid(child.id())?;

    let status = child.wait()?;
    Ok(status.code().unwrap_or(-1))
}
```

### Phase 2-3: プロダクション対応

**オプション3（eBPFトレースポイント）を採用**

- 子プロセスの自動追跡
- cgroupが不要
- リアルタイムで確実

```rust
// Phase 2-3: トレースポイントによる自動追跡
// ユーザースペースのコードは Phase 1 とほぼ同じ！
// BPF側にトレースポイントを追加するだけ
```

### Phase 4以降: オプション2は不要

オプション3の方が優れているため、オプション2（cgroupハイブリッド）の実装は不要です。

## 実装上の注意点

### オプション3（eBPF）実装時の注意

1. **トレースポイントの構造体定義**
   - カーネルバージョンで変わる可能性があるため、BTFを活用
   - Ayaは自動的にBTFをサポートするため、通常は問題ない

2. **エラーハンドリング**
   - トレースポイントでエラーが発生しても、プロセス実行は継続される
   - ログ出力で問題を検出できるようにする

3. **パフォーマンス**
   - `sched_process_fork`はシステムワイドで頻繁に発火する
   - 親PIDチェックで早期リターンすることでオーバーヘッドを最小化

4. **デバッグ**
   - `bpf_printk`を使ってカーネルログに出力
   - `/sys/kernel/debug/tracing/trace_pipe`で確認

### テスト戦略

```bash
# Phase 1: 単一プロセステスト
mori --deny-file /etc/shadow -- cat /etc/shadow
# 期待: EPERM

# Phase 2-3: 子プロセステスト
mori --deny-file /etc/shadow -- bash -c "cat /etc/shadow"
# 期待: EPERM（bashの子プロセスも制御される）

# 孫プロセステスト
mori --deny-file /etc/shadow -- bash -c "python3 -c 'import subprocess; subprocess.run([\"cat\", \"/etc/shadow\"])'"
# 期待: EPERM（bash → python3 → cat の3世代すべて制御される）
```

## 結論

**オプション3（eBPFトレースポイント）が最も優れたアプローチです。**

理由:
1. 完全自動で確実な子プロセス追跡
2. リアルタイム、オーバーヘッド最小
3. cgroupが不要（ファイル制御のみの場合）
4. ユーザースペースの実装がシンプル
5. プロダクション環境で使用可能

実装順序:
1. **Phase 1**: オプション1でMVP実装、動作確認
2. **Phase 2-3**: オプション3に移行、プロダクション対応
3. オプション2は実装不要
