use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const KEYRING_SERVICE: &str = "NetDect";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExitCfg {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Expected egress IP set by hand, used when the proxy cannot be reached from this machine.
    pub pinned_ip: Option<String>,
    pub last_ip: Option<String>,
    pub last_country: Option<String>,
    pub last_org: Option<String>,
    pub last_checked: Option<u64>,
    pub last_error: Option<String>,
}

impl ExitCfg {
    pub fn expected_ip(&self) -> Option<(String, &'static str)> {
        if let Some(ip) = self.pinned_ip.as_ref().filter(|s| !s.trim().is_empty()) {
            return Some((ip.trim().to_string(), "pinned"));
        }
        self.last_ip.clone().map(|ip| (ip, "resolved"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EngineCfg {
    /// auto | http | pipe | unix | none
    pub kind: String,
    pub address: String,
    pub secret: String,
}

impl Default for EngineCfg {
    fn default() -> Self {
        Self { kind: "auto".into(), address: String::new(), secret: String::new() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProbeCfg {
    /// auto | tun | system | env
    pub mode: String,
    pub concurrency: usize,
    pub timeout_secs: u64,
}

impl Default for ProbeCfg {
    fn default() -> Self {
        Self { mode: "auto".into(), concurrency: 8, timeout_secs: 10 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GuardCfg {
    /// Start guarding as soon as NetDect launches.
    pub start_on_launch: bool,
    /// Launch NetDect hidden at login (implies guarding).
    pub autostart: bool,
    pub poll_ms: u64,
    pub verify_minutes: u64,
    pub notify: bool,
    /// Re-verify the exit right after a watched app starts.
    pub verify_on_app_start: bool,
    pub close_to_tray: bool,
}

impl Default for GuardCfg {
    fn default() -> Self {
        Self {
            start_on_launch: false,
            autostart: false,
            poll_ms: 1000,
            verify_minutes: 5,
            notify: true,
            verify_on_app_start: true,
            close_to_tray: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub exits: Vec<ExitCfg>,
    pub target_exit: Option<String>,
    pub selected_apps: Vec<String>,
    pub engine: EngineCfg,
    pub probe: ProbeCfg,
    pub guard: GuardCfg,
    /// Extra install locations per provider id, merged with the built-in table.
    pub extra_process_paths: HashMap<String, Vec<String>>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            exits: Vec::new(),
            target_exit: None,
            selected_apps: vec!["anthropic".into()],
            engine: EngineCfg::default(),
            probe: ProbeCfg::default(),
            guard: GuardCfg::default(),
            extra_process_paths: HashMap::new(),
        }
    }
}

impl AppConfig {
    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(self).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, path).map_err(|e| e.to_string())
    }

    pub fn exit(&self, id: &str) -> Option<&ExitCfg> {
        self.exits.iter().find(|e| e.id == id)
    }

    pub fn exit_mut(&mut self, id: &str) -> Option<&mut ExitCfg> {
        self.exits.iter_mut().find(|e| e.id == id)
    }

    pub fn unique_id(&self, name: &str) -> String {
        let base: String = name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string();
        let base = if base.is_empty() { "exit".to_string() } else { base };
        let mut id = base.clone();
        let mut n = 2;
        while self.exit(&id).is_some() {
            id = format!("{base}-{n}");
            n += 1;
        }
        id
    }
}

pub fn config_file(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

pub fn set_password(id: &str, password: &str) -> Result<(), String> {
    keyring::Entry::new(KEYRING_SERVICE, id)
        .and_then(|e| e.set_password(password))
        .map_err(|e| format!("写入系统钥匙串失败: {e}"))
}

pub fn get_password(id: &str) -> Option<String> {
    keyring::Entry::new(KEYRING_SERVICE, id).ok()?.get_password().ok()
}

pub fn delete_password(id: &str) {
    if let Ok(e) = keyring::Entry::new(KEYRING_SERVICE, id) {
        let _ = e.delete_credential();
    }
}

/// Parses `host:port:user:pass`; only the first three colons separate fields.
pub fn parse_exit_string(s: &str) -> Result<(String, u16, String, String), String> {
    let mut parts = s.trim().splitn(4, ':');
    let host = parts.next().unwrap_or("").trim().to_string();
    let port = parts.next().unwrap_or("").trim();
    let user = parts.next().unwrap_or("").to_string();
    let pass = parts.next().unwrap_or("").to_string();
    if host.is_empty() {
        return Err("缺少主机".into());
    }
    let port: u16 = port.parse().map_err(|_| "端口无效".to_string())?;
    Ok((host, port, user, pass))
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_exit() {
        let (h, p, u, pw) = parse_exit_string("isp.decodo.com:10001:spaglxqbsu:xYz:s8~").unwrap();
        assert_eq!(h, "isp.decodo.com");
        assert_eq!(p, 10001);
        assert_eq!(u, "spaglxqbsu");
        assert_eq!(pw, "xYz:s8~");
        assert!(parse_exit_string("host:abc").is_err());
    }

    #[test]
    fn ids() {
        let mut c = AppConfig::default();
        assert_eq!(c.unique_id("Japan 01"), "japan-01");
        c.exits.push(ExitCfg { id: "japan-01".into(), ..Default::default() });
        assert_eq!(c.unique_id("Japan 01"), "japan-01-2");
    }
}
