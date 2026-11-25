use serde::{Deserialize, Serialize};

use crate::net::Route;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckItem {
    pub name: String,
    /// pass | warn | fail | info
    pub status: String,
    pub detail: String,
}

impl CheckItem {
    fn new(name: &str, status: &str, detail: impl Into<String>) -> Self {
        Self { name: name.into(), status: status.into(), detail: detail.into() }
    }
}

#[derive(Debug, Clone, Default)]
pub struct EnvReport {
    pub checks: Vec<CheckItem>,
    pub tun_active: bool,
    pub system_proxy: Option<Route>,
    pub env_proxy: Option<Route>,
}

const PROXY_APPS: &[&str] = &[
    "clash-verge", "verge-mihomo", "verge-mihomo-alpha", "mihomo", "clash", "clash-meta", "clashx", "clashx meta",
    "clashx pro", "flclash", "flclashcore", "mihomo-party", "sing-box", "surge", "stash", "v2rayn", "xray",
    "nekoray", "hiddify", "loon", "quantumult x", "shadowrocket", "clash for windows",
];

pub fn is_tunnel_iface(name: &str) -> bool {
    let n = name.to_lowercase();
    ["meta", "mihomo", "clash", "wintun", "sing", "utun", "tun", "wireguard", "tailscale"]
        .iter()
        .any(|k| n.contains(k))
}

fn proxy_processes() -> Vec<String> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing());
    let mut found: Vec<String> = sys
        .processes()
        .values()
        .filter_map(|p| {
            let name = p.name().to_string_lossy().to_string();
            let base = name.to_lowercase().trim_end_matches(".exe").to_string();
            PROXY_APPS.contains(&base.as_str()).then_some(name)
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

fn env_proxy() -> Option<(String, Route)> {
    for k in ["HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(v) = std::env::var(k) {
            if let Some(r) = Route::parse_proxy(&v) {
                return Some((format!("{k}={v}"), r));
            }
        }
    }
    None
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    pub fn powershell(script: &str) -> Option<String> {
        let full = format!("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='SilentlyContinue';{script}");
        let out = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &full])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct NetInfo {
        alias: Option<String>,
        desc: Option<String>,
        v6routes: Vec<String>,
        v6addrs: Vec<String>,
    }

    pub struct Net {
        pub default_iface: Option<String>,
        pub default_desc: Option<String>,
        pub ipv6_bypass: Vec<String>,
    }

    pub fn net() -> Net {
        let script = r#"
$r = Find-NetRoute -RemoteIPAddress 8.8.8.8 | Where-Object { $_.InterfaceAlias } | Select-Object -First 1
$alias = $r.InterfaceAlias
$desc = if ($alias) { (Get-NetAdapter -Name $alias).InterfaceDescription } else { $null }
$v6 = @(Get-NetRoute -AddressFamily IPv6 -DestinationPrefix '::/0' | ForEach-Object { $_.InterfaceAlias })
$v6a = @(Get-NetIPAddress -AddressFamily IPv6 | Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1' -and $_.PrefixOrigin -ne 'WellKnown' } | ForEach-Object { $_.InterfaceAlias })
[pscustomobject]@{ alias = $alias; desc = $desc; v6routes = $v6; v6addrs = $v6a } | ConvertTo-Json -Compress
"#;
        let info: NetInfo = powershell(script).and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
        let ipv6_bypass = info
            .v6routes
            .iter()
            .filter(|a| !is_tunnel_iface(a) && info.v6addrs.contains(a))
            .cloned()
            .collect();
        Net { default_iface: info.alias, default_desc: info.desc, ipv6_bypass }
    }

    pub fn system_proxy() -> Option<(String, Option<Route>)> {
        use winreg::enums::HKEY_CURRENT_USER;
        use winreg::RegKey;
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            .ok()?;
        let pac: String = key.get_value("AutoConfigURL").unwrap_or_default();
        let enabled: u32 = key.get_value("ProxyEnable").unwrap_or(0);
        if enabled == 1 {
            let server: String = key.get_value("ProxyServer").unwrap_or_default();
            let pick = if server.contains('=') {
                server
                    .split(';')
                    .find_map(|p| p.strip_prefix("https=").or_else(|| p.strip_prefix("http=")))
                    .unwrap_or("")
                    .to_string()
            } else {
                server.clone()
            };
            return Some((server, Route::parse_proxy(&pick)));
        }
        if !pac.is_empty() {
            return Some((format!("PAC {pac}"), None));
        }
        None
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    fn run(cmd: &str, args: &[&str]) -> String {
        std::process::Command::new(cmd)
            .args(args)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }

    pub struct Net {
        pub default_iface: Option<String>,
        pub default_desc: Option<String>,
        pub ipv6_bypass: Vec<String>,
    }

    pub fn net() -> Net {
        let default_iface = run("route", &["-n", "get", "8.8.8.8"])
            .lines()
            .find_map(|l| l.trim().strip_prefix("interface:").map(|s| s.trim().to_string()));
        let mut ipv6_bypass = Vec::new();
        for line in run("netstat", &["-rn", "-f", "inet6"]).lines() {
            let cols: Vec<&str> = line.split_whitespace().collect();
            if cols.first() == Some(&"default") {
                if let Some(iface) = cols.last() {
                    let iface = iface.to_string();
                    if is_tunnel_iface(&iface) || iface.starts_with("lo") || ipv6_bypass.contains(&iface) {
                        continue;
                    }
                    let cfg = run("ifconfig", &[&iface]);
                    let global = cfg.lines().any(|l| {
                        let l = l.trim();
                        l.starts_with("inet6 ") && !l.starts_with("inet6 fe80")
                    });
                    if global {
                        ipv6_bypass.push(iface);
                    }
                }
            }
        }
        Net { default_iface, default_desc: None, ipv6_bypass }
    }

    pub fn system_proxy() -> Option<(String, Option<Route>)> {
        let out = run("scutil", &["--proxy"]);
        let get = |k: &str| {
            out.lines().find_map(|l| {
                let (a, b) = l.split_once(':')?;
                (a.trim() == k).then(|| b.trim().to_string())
            })
        };
        for (en, host, port) in [("HTTPSEnable", "HTTPSProxy", "HTTPSPort"), ("HTTPEnable", "HTTPProxy", "HTTPPort")] {
            if get(en).as_deref() == Some("1") {
                let h = get(host)?;
                let p: u16 = get(port)?.parse().ok()?;
                return Some((format!("{h}:{p}"), Some(Route::Http { host: h, port: p })));
            }
        }
        if get("SOCKSEnable").as_deref() == Some("1") {
            let h = get("SOCKSProxy")?;
            let p: u16 = get("SOCKSPort")?.parse().ok()?;
            return Some((format!("socks5://{h}:{p}"), Some(Route::Socks5 { host: h, port: p })));
        }
        if get("ProxyAutoConfigEnable").as_deref() == Some("1") {
            return Some((format!("PAC {}", get("ProxyAutoConfigURLString").unwrap_or_default()), None));
        }
        None
    }
}

#[cfg(not(any(windows, target_os = "macos")))]
mod platform {
    use super::*;
    pub struct Net {
        pub default_iface: Option<String>,
        pub default_desc: Option<String>,
        pub ipv6_bypass: Vec<String>,
    }
    pub fn net() -> Net {
        Net { default_iface: None, default_desc: None, ipv6_bypass: Vec::new() }
    }
    pub fn system_proxy() -> Option<(String, Option<Route>)> {
        None
    }
}

#[cfg(windows)]
pub fn platform_powershell(script: &str) -> Option<String> {
    platform::powershell(script)
}

/// Runs all environment checks. Blocking; call from `spawn_blocking`.
pub fn run() -> EnvReport {
    let mut r = EnvReport::default();

    let procs = proxy_processes();
    r.checks.push(if procs.is_empty() {
        CheckItem::new("代理软件", "warn", "没有发现本机运行中的代理软件（如果代理在路由器上，可以忽略）")
    } else {
        CheckItem::new("代理软件", "pass", procs.join("、"))
    });

    let net = platform::net();
    let iface_text = match (&net.default_iface, &net.default_desc) {
        (Some(a), Some(d)) if !d.is_empty() => format!("{a}（{d}）"),
        (Some(a), _) => a.clone(),
        _ => "未知".into(),
    };
    r.tun_active = net.default_iface.as_deref().map(is_tunnel_iface).unwrap_or(false)
        || net.default_desc.as_deref().map(is_tunnel_iface).unwrap_or(false);
    r.checks.push(CheckItem::new(
        "TUN 模式",
        if r.tun_active { "pass" } else { "info" },
        if r.tun_active {
            format!("外网流量的出口网卡是 {iface_text}，由代理软件接管")
        } else {
            format!("外网流量直接走 {iface_text}，未发现 TUN 接管")
        },
    ));

    match platform::system_proxy() {
        Some((text, route)) => {
            r.checks.push(CheckItem::new("系统代理", "info", format!("已开启：{text}")));
            r.system_proxy = route;
        }
        None => r.checks.push(CheckItem::new("系统代理", "info", "未开启")),
    }

    match env_proxy() {
        Some((text, route)) => {
            r.checks.push(CheckItem::new("代理环境变量", "info", text));
            r.env_proxy = Some(route);
        }
        None => r.checks.push(CheckItem::new("代理环境变量", "info", "未设置（NetDect 进程内）")),
    }

    r.checks.push(if net.ipv6_bypass.is_empty() {
        CheckItem::new("IPv6 旁路", "pass", "没有绕过 TUN 的 IPv6 默认路由")
    } else {
        CheckItem::new(
            "IPv6 旁路",
            "warn",
            format!("{} 上有 IPv6 默认路由和公网 IPv6 地址，IPv6 流量可能不经代理", net.ipv6_bypass.join("、")),
        )
    });

    if !r.tun_active && r.system_proxy.is_none() && r.env_proxy.is_none() {
        r.checks.push(CheckItem::new("接管方式", "fail", "TUN、系统代理、代理环境变量都没有，流量会直连"));
    }
    r
}
