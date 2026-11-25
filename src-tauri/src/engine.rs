use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::EngineCfg;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "address", rename_all = "lowercase")]
pub enum Transport {
    Http(String),
    Pipe(String),
    Unix(String),
}

impl Transport {
    pub fn describe(&self) -> String {
        match self {
            Transport::Http(a) => format!("HTTP {a}"),
            Transport::Pipe(a) => format!("命名管道 {a}"),
            Transport::Unix(a) => format!("Unix socket {a}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Engine {
    pub transport: Transport,
    pub secret: String,
    pub version: String,
}

/// One active connection as reported by mihomo / Clash-compatible `/connections`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Conn {
    pub id: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
    pub host: String,
    pub sniff_host: String,
    pub dst_ip: String,
    /// Address the engine dialed: the real target for DIRECT, the proxy server otherwise.
    pub remote: String,
    pub dst_port: u16,
    pub network: String,
    pub inbound_type: String,
    pub process: String,
    pub process_path: String,
    pub source_port: u16,
    pub start: String,
}

impl Conn {
    /// The node that actually carries the traffic (first element of `chains`).
    pub fn node(&self) -> String {
        self.chains.first().cloned().unwrap_or_default()
    }

    /// Domain the connection was for: sniffed SNI first, then the DNS-mapped host.
    pub fn domain(&self) -> &str {
        if self.sniff_host.is_empty() {
            &self.host
        } else {
            &self.sniff_host
        }
    }

    pub fn rule_text(&self) -> String {
        if self.rule_payload.is_empty() {
            self.rule.clone()
        } else {
            format!("{} {}", self.rule, self.rule_payload)
        }
    }
}

#[derive(Deserialize)]
struct RawConns {
    #[serde(default)]
    connections: Option<Vec<RawConn>>,
}

#[derive(Deserialize)]
struct RawConn {
    #[serde(default)]
    id: String,
    #[serde(default)]
    start: String,
    #[serde(default)]
    chains: Vec<String>,
    #[serde(default)]
    rule: String,
    #[serde(default, rename = "rulePayload")]
    rule_payload: String,
    #[serde(default)]
    metadata: serde_json::Value,
}

fn json_port(v: &serde_json::Value) -> u16 {
    match v {
        serde_json::Value::String(s) => s.parse().unwrap_or(0),
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0) as u16,
        _ => 0,
    }
}

impl Engine {
    pub async fn get(&self, path: &str) -> Result<String, String> {
        request(&self.transport, &self.secret, path).await
    }

    pub async fn connections(&self) -> Result<Vec<Conn>, String> {
        let body = self.get("/connections").await?;
        let raw: RawConns = serde_json::from_str(&body).map_err(|e| format!("解析 /connections 失败: {e}"))?;
        Ok(raw
            .connections
            .unwrap_or_default()
            .into_iter()
            .map(|c| {
                let m = &c.metadata;
                let s = |k: &str| m.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
                let process_path = s("processPath");
                let mut process = s("process");
                if process.is_empty() && !process_path.is_empty() {
                    process = process_path.rsplit(['\\', '/']).next().unwrap_or("").to_string();
                }
                let direct = c.chains.first().is_some_and(|n| n.eq_ignore_ascii_case("DIRECT"));
                let remote = s("remoteDestination");
                let mut dst_ip = s("destinationIP");
                if dst_ip.is_empty() && direct {
                    dst_ip = remote.clone();
                }
                Conn {
                    id: c.id,
                    chains: c.chains,
                    rule: c.rule,
                    rule_payload: c.rule_payload,
                    host: s("host"),
                    sniff_host: s("sniffHost"),
                    dst_ip,
                    remote,
                    dst_port: m.get("destinationPort").map(json_port).unwrap_or(0),
                    network: s("network"),
                    inbound_type: s("type"),
                    process,
                    process_path,
                    source_port: m.get("sourcePort").map(json_port).unwrap_or(0),
                    start: c.start,
                }
            })
            .collect())
    }

    /// Polls `/connections` until a connection with `port` as its source port shows up.
    pub async fn find_by_port(&self, port: u16, wait: Duration) -> Option<Conn> {
        let deadline = Instant::now() + wait;
        loop {
            if let Ok(list) = self.connections().await {
                if let Some(c) = list.into_iter().find(|c| c.source_port == port) {
                    return Some(c);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(120)).await;
        }
    }
}

async fn request(t: &Transport, secret: &str, path: &str) -> Result<String, String> {
    let fut = async {
        match t {
            Transport::Http(base) => {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(Duration::from_secs(4))
                    .build()
                    .map_err(|e| e.to_string())?;
                let mut req = client.get(format!("{}{}", base.trim_end_matches('/'), path));
                if !secret.is_empty() {
                    req = req.bearer_auth(secret);
                }
                let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
                let status = resp.status();
                let text = resp.text().await.map_err(|e| e.to_string())?;
                if !status.is_success() {
                    return Err(format!("HTTP {status}: {}", text.chars().take(120).collect::<String>()));
                }
                Ok(text)
            }
            Transport::Pipe(name) => pipe_request(name, secret, path).await,
            Transport::Unix(p) => unix_request(p, secret, path).await,
        }
    };
    tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .map_err(|_| "代理软件 API 超时".to_string())?
}

/// HTTP/1.0 over an arbitrary stream; HTTP/1.0 keeps Go's server from chunking.
async fn raw_http<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S, secret: &str, path: &str) -> Result<String, String> {
    let mut req = format!("GET {path} HTTP/1.0\r\nHost: localhost\r\n");
    if !secret.is_empty() {
        req.push_str(&format!("Authorization: Bearer {secret}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await.map_err(|e| format!("写入失败: {e}"))?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw).await.map_err(|e| format!("读取失败: {e}"))?;
    let resp = crate::net::parse_response(&raw)?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("HTTP {}: {}", resp.status, resp.body.chars().take(120).collect::<String>()));
    }
    Ok(resp.body)
}

#[cfg(windows)]
async fn pipe_request(name: &str, secret: &str, path: &str) -> Result<String, String> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    let full = if name.starts_with(r"\\") { name.to_string() } else { format!(r"\\.\pipe\{name}") };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut client = loop {
        match ClientOptions::new().open(&full) {
            Ok(c) => break c,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(40)).await;
            }
            Err(e) => return Err(format!("打开命名管道失败: {e}")),
        }
    };
    raw_http(&mut client, secret, path).await
}

#[cfg(not(windows))]
async fn pipe_request(_: &str, _: &str, _: &str) -> Result<String, String> {
    Err("命名管道仅支持 Windows".into())
}

#[cfg(unix)]
async fn unix_request(p: &str, secret: &str, path: &str) -> Result<String, String> {
    let mut s = tokio::net::UnixStream::connect(p).await.map_err(|e| format!("连接 Unix socket 失败: {e}"))?;
    raw_http(&mut s, secret, path).await
}

#[cfg(not(unix))]
async fn unix_request(_: &str, _: &str, _: &str) -> Result<String, String> {
    Err("Unix socket 仅支持 macOS / Linux".into())
}

fn normalize_http(addr: &str) -> Option<String> {
    let a = addr.trim().trim_matches('\'').trim_matches('"');
    if a.is_empty() {
        return None;
    }
    let a = a.trim_start_matches("http://").trim_start_matches("https://");
    let a = if a.starts_with(':') { format!("127.0.0.1{a}") } else { a.to_string() };
    let a = a.replace("0.0.0.0:", "127.0.0.1:").replace("[::]:", "127.0.0.1:");
    Some(format!("http://{a}"))
}

fn clash_verge_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    const ID: &str = "io.github.clash-verge-rev.clash-verge-rev";
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        v.push(PathBuf::from(appdata).join(ID));
    }
    #[cfg(target_os = "macos")]
    if let Ok(home) = std::env::var("HOME") {
        v.push(PathBuf::from(home).join("Library/Application Support").join(ID));
    }
    #[cfg(target_os = "linux")]
    if let Ok(home) = std::env::var("HOME") {
        v.push(PathBuf::from(home).join(".local/share").join(ID));
    }
    v
}

/// Candidate transports read from Clash Verge Rev's generated runtime config.
/// Controller sockets that exist right now. Clash Verge's yaml can name a stale
/// pipe (e.g. sidecar vs. service mode), so live ones are tried first.
fn live_sockets() -> Vec<Transport> {
    let mut out = Vec::new();
    #[cfg(windows)]
    if let Ok(rd) = std::fs::read_dir(r"\\.\pipe\") {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let l = name.to_lowercase();
            if (l.contains("mihomo") || l.contains("clash")) && !l.contains("service") {
                out.push(Transport::Pipe(name));
            }
        }
    }
    #[cfg(unix)]
    for dir in ["/tmp/verge", "/tmp", "/var/tmp"] {
        let Ok(rd) = std::fs::read_dir(dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if (name.contains("mihomo") || name.contains("clash")) && name.ends_with(".sock") && !name.contains("service") {
                out.push(Transport::Unix(e.path().to_string_lossy().to_string()));
            }
        }
    }
    out
}

fn discover_candidates(user_secret: &str) -> Vec<(Transport, String)> {
    let mut out = Vec::new();
    let mut yaml_secret = String::new();
    let mut configured = Vec::new();
    for dir in clash_verge_dirs() {
        let Ok(text) = std::fs::read_to_string(dir.join("clash-verge.yaml")) else { continue };
        let Ok(y) = serde_yaml::from_str::<serde_yaml::Value>(&text) else { continue };
        let s = |k: &str| y.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let secret = s("secret");
        if yaml_secret.is_empty() {
            yaml_secret = secret.clone();
        }
        if let Some(h) = normalize_http(&s("external-controller")) {
            configured.push((Transport::Http(h), secret.clone()));
        }
        let pipe = s("external-controller-pipe");
        if !pipe.is_empty() {
            configured.push((Transport::Pipe(pipe), secret.clone()));
        }
        let unix = s("external-controller-unix");
        if !unix.is_empty() {
            configured.push((Transport::Unix(unix), secret.clone()));
        }
    }
    let secret = if user_secret.is_empty() { yaml_secret } else { user_secret.to_string() };
    for t in live_sockets() {
        out.push((t, secret.clone()));
    }
    for (t, s) in configured {
        if !out.iter().any(|(x, _)| x.describe() == t.describe()) {
            out.push((t, s));
        }
    }
    out
}

/// Resolves and probes the engine API. Returns the engine or a human-readable reason.
pub async fn connect(cfg: &EngineCfg) -> Result<Engine, String> {
    let mut candidates: Vec<(Transport, String)> = Vec::new();
    match cfg.kind.as_str() {
        "none" => return Err("已在设置中关闭代理软件 API".into()),
        "http" => {
            let a = normalize_http(&cfg.address).ok_or("未填写 HTTP 地址")?;
            candidates.push((Transport::Http(a), cfg.secret.clone()));
        }
        "pipe" => candidates.push((Transport::Pipe(cfg.address.clone()), cfg.secret.clone())),
        "unix" => candidates.push((Transport::Unix(cfg.address.clone()), cfg.secret.clone())),
        _ => {
            candidates.extend(discover_candidates(&cfg.secret));
            for port in [9090u16, 9097] {
                candidates.push((Transport::Http(format!("http://127.0.0.1:{port}")), cfg.secret.clone()));
            }
        }
    }
    let mut errors = Vec::new();
    for (t, secret) in candidates {
        match request(&t, &secret, "/version").await {
            Ok(body) => {
                let version = serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("version").and_then(|x| x.as_str()).map(String::from))
                    .unwrap_or_else(|| body.chars().take(40).collect());
                return Ok(Engine { transport: t, secret, version });
            }
            Err(e) => errors.push(format!("{}：{e}", t.describe())),
        }
    }
    if errors.is_empty() {
        Err("没有找到代理软件 API".into())
    } else {
        Err(errors.join("；"))
    }
}
