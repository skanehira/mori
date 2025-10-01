# ポリシー設計

## 概要

moriのネットワーク制御を統一的なポリシー構造体で管理し、CLI引数と設定ファイルの両方から同じポリシーに変換する設計。単一の`NetworkPolicy`に集約することで、プラットフォームごとの実装は同一インターフェースを受け取ればよくなり、テストや拡張が容易になる。

## ポリシー構造体

### NetworkPolicy

```rust
// src/policy.rs

use std::net::Ipv4Addr;

use crate::{error::MoriError, net::parse_allow_network};

/// ネットワークアクセスポリシーの統一的な表現
#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetworkPolicy {
    /// 許可するIPv4アドレス（直接指定）
    pub allowed_ipv4: Vec<Ipv4Addr>,
    /// 許可するドメイン名
    pub allowed_domains: Vec<String>,
}

impl NetworkPolicy {
    /// 空のポリシーを作成
    pub fn new() -> Self {
        Self::default()
    }

    /// 許可エントリからポリシーを構築
    pub fn from_entries(entries: &[String]) -> Result<Self, MoriError> {
        let network_rules = parse_allow_network(entries)?;
        Ok(Self {
            allowed_ipv4: network_rules.direct_v4,
            allowed_domains: network_rules.domains,
        })
    }

    /// IPv4アドレスを追加（重複は自動で排除）
    pub fn add_ipv4(&mut self, addr: Ipv4Addr) {
        if !self.allowed_ipv4.contains(&addr) {
            self.allowed_ipv4.push(addr);
        }
    }

    /// ドメインを追加（重複は自動で排除）
    pub fn add_domain(&mut self, domain: String) {
        if !self.allowed_domains.contains(&domain) {
            self.allowed_domains.push(domain);
        }
    }

    /// 他のポリシーをマージ
    pub fn merge(&mut self, other: Self) {
        for ip in other.allowed_ipv4 {
            self.add_ipv4(ip);
        }
        for domain in other.allowed_domains {
            self.add_domain(domain);
        }
    }

    /// 許可対象が存在しないかを判定
    pub fn is_empty(&self) -> bool {
        self.allowed_ipv4.is_empty() && self.allowed_domains.is_empty()
    }
}
```

## CLI引数からの変換

既存の`Args`構造体に`--config`オプションを追加し、CLIと設定ファイルからの値を同じ`NetworkPolicy`にマージする。

```rust
// src/main.rs

use std::path::PathBuf;

use clap::Parser;
use mori::{
    config::ConfigFile,
    policy::NetworkPolicy,
    runtime::execute_with_network_control,
};

#[derive(Parser, Debug)]
#[command(author, version, about = "Network sandbox for Linux using eBPF")]
struct Args {
    /// Path to configuration file (TOML)
    #[arg(long = "config", value_name = "PATH")]
    config: Option<PathBuf>,

    /// Allow outbound connections to the specified host[:port] (FQDN/IP)
    #[arg(long = "allow-network", value_delimiter = ',')]
    allow_network: Vec<String>,

    /// Command to execute
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Args::parse();
    let command = &args.command[0];
    let command_args: Vec<&str> = args.command[1..].iter().map(String::as_str).collect();

    let mut policy = NetworkPolicy::new();

    if let Some(config_path) = args.config.as_ref() {
        let config = ConfigFile::load(config_path)?;
        let config_policy = config.to_policy()?;
        policy.merge(config_policy);
    }

    let cli_policy = NetworkPolicy::from_entries(&args.allow_network)?;
    policy.merge(cli_policy);

    let exit_code = execute_with_network_control(command, &command_args, &policy)?;
    std::process::exit(exit_code);
}
```

### 変換＆マージフロー

1. `--config`オプションで指定されたTOMLを読み込む（任意）
2. 設定ファイルの`network.allow`を`NetworkPolicy`へ変換
3. `--allow-network`で与えられた値を同じポリシーに変換
4. 設定ファイル由来のポリシーにCLI由来のポリシーをマージ（CLI優先で追加）

## 設定ファイル対応

TOMLフォーマットの設定ファイルから`NetworkPolicy`への変換を実装。

### 設定ファイル構造

```toml
[network]
allow = [
    "192.168.1.1",
    "example.com",
    "10.0.0.5",
    "api.github.com",
]
```

### ConfigFile実装

```rust
// src/config.rs

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::{
    error::MoriError,
    policy::NetworkPolicy,
};

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct ConfigFile {
    #[serde(default)]
    pub network: NetworkConfig,
}

#[derive(Debug, Deserialize, Serialize, Default)]
pub struct NetworkConfig {
    /// 許可するネットワーク先（IP、ドメイン）
    #[serde(default)]
    pub allow: Vec<String>,
}

impl ConfigFile {
    /// 設定ファイルを読み込む
    pub fn load(path: &Path) -> Result<Self, MoriError> {
        let content = fs::read_to_string(path)?;
        toml::from_str(&content).map_err(|source| MoriError::ConfigParse {
            path: PathBuf::from(path),
            source,
        })
    }

    /// 設定ファイルからネットワークポリシーを構築
    pub fn to_policy(&self) -> Result<NetworkPolicy, MoriError> {
        NetworkPolicy::from_entries(&self.network.allow)
    }
}
```

## CLIと設定ファイルの優先順位

- 設定ファイルの`network.allow`が先に適用される
- `--allow-network`で指定したエントリは追加でマージされる
- 同じエントリが重複した場合は自動的に除外される
- 設定ファイルは任意。指定がない場合はCLIだけでポリシーを構築する

## プラットフォーム固有の適用

### Linux実装への統合

`execute_with_network_control`は`NetworkPolicy`を受け取り、事前に構築済みのポリシーをそのまま利用する。

```rust
// src/runtime/linux/mod.rs

pub fn execute_with_network_control(
    command: &str,
    args: &[&str],
    policy: &NetworkPolicy,
) -> Result<i32, MoriError> {
    let domain_names = policy.allowed_domains.clone();
    let resolver = SystemDnsResolver;
    let resolved = resolver.resolve_domains(&domain_names)?;

    let cgroup = CgroupManager::create()?;
    let ebpf = Arc::new(Mutex::new(NetworkEbpf::load_and_attach(cgroup.fd())?));

    let dns_cache = Arc::new(Mutex::new(DnsCache::default()));
    let allowed_dns_ips = Arc::new(Mutex::new(HashSet::new()));
    let now = Instant::now();

    {
        let mut ebpf_guard = ebpf.lock().unwrap();
        for &ip in &policy.allowed_ipv4 {
            ebpf_guard.allow_ipv4(ip)?;
            println!("Added {} to allow list", ip);
        }
    }

    apply_domain_records(&dns_cache, &ebpf, now, resolved.domains)?;
    apply_dns_servers(&ebpf, &allowed_dns_ips, resolved.dns_v4)?;

    let mut child = Command::new(command)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    cgroup.add_process(child.id())?;
    println!("Process {} added to cgroup", child.id());

    if domain_names.is_empty() {
        let status = child.wait()?;
        return Ok(status.code().unwrap_or(-1));
    }

    let shutdown_signal = ShutdownSignal::new();
    let resolver = Arc::new(SystemDnsResolver);
    let refresh_handle = spawn_refresh_thread(
        domain_names.clone(),
        Arc::clone(&dns_cache),
        Arc::clone(&ebpf),
        Arc::clone(&allowed_dns_ips),
        Arc::clone(&shutdown_signal),
        resolver,
    );

    let status = child.wait()?;
    shutdown_signal.shutdown();
    if let Some(handle) = refresh_handle {
        handle
            .join()
            .map_err(|_| std::io::Error::other("refresh thread panicked"))
            .map_err(MoriError::Io)??;
    }

    Ok(status.code().unwrap_or(-1))
}
```

### macOS実装

将来的に実装する際も同じ`NetworkPolicy`インターフェースを使用する。

```rust
// src/runtime/macos.rs

pub fn execute_with_network_control(
    _command: &str,
    _args: &[&str],
    _policy: &NetworkPolicy,
) -> Result<i32, crate::error::MoriError> {
    Err(crate::error::MoriError::Unsupported)
}
```

## 設計の利点

1. **統一されたポリシー表現**: CLI引数と設定ファイルの両方から同じ`NetworkPolicy`構造体に変換
2. **既存コードの再利用**: `parse_allow_network`関数をそのまま利用可能
3. **プラットフォーム非依存**: ポリシー自体はLinux/macOS固有の詳細を含まない
4. **拡張性**: 将来的に新しいフィールド（ポート制限、帯域制限など）を追加しやすい
5. **テスト容易性**: ポリシー変換ロジックを独立してテスト可能

## DNSリフレッシュについて

DNSリフレッシュ間隔はポリシーに含めない。理由:

- 現在の実装では、DNSキャッシュの中で最もTTLが短いエントリの有効期限に基づいてsleep時間を決定している
- `DnsCache::next_refresh_in()`が自動的に最適なリフレッシュタイミングを計算
- ユーザーが指定する必要がなく、自動的に効率的な動作を実現

## 実装の変更範囲

### 新規ファイル
- `src/policy.rs`: `NetworkPolicy`構造体の定義とユーティリティ
- `src/config.rs`: 設定ファイル読み込みとポリシー変換ロジック

### 変更ファイル
- `src/lib.rs`: `config`・`policy`モジュールを公開
- `src/main.rs`: `Args::parse()`後に`NetworkPolicy`を構築し、CLIと設定ファイルをマージ
- `src/runtime/mod.rs`: 公開インターフェースの変更（`NetworkPolicy`受け渡し）
- `src/runtime/linux/mod.rs`: `execute_with_network_control`のシグネチャ変更
- `src/runtime/macos.rs`: `execute_with_network_control`のシグネチャ変更
- `src/error.rs`: `MoriError::ConfigParse`バリアントの追加
- `Cargo.toml`: `toml` / `serde` 依存関係、テスト用の`tempfile`を追加

### 既存コードへの影響
- `parse_allow_network`関数はそのまま利用
- `NetworkRules`構造体も維持（内部的に使用）
- eBPF、DNS解決、キャッシュ機構は変更不要
- `--config`と`--allow-network`の組み合わせで重複が自動的に除去される
