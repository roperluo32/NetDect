use std::sync::{Arc, OnceLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

/// How a probe connection reaches the internet, mirroring how the real app would.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Route {
    /// Plain socket; with a TUN proxy this is intercepted by the proxy engine.
    Direct,
    Http { host: String, port: u16 },
    Socks5 { host: String, port: u16 },
}

impl Route {
    pub fn describe(&self) -> String {
        match self {
            Route::Direct => "直接连接（由 TUN 接管）".into(),
            Route::Http { host, port } => format!("HTTP 代理 {host}:{port}"),
            Route::Socks5 { host, port } => format!("SOCKS5 代理 {host}:{port}"),
        }
    }

    /// Parses `http://h:p`, `socks5://h:p`, `socks5h://h:p` or bare `h:p` (treated as HTTP).
    pub fn parse_proxy(s: &str) -> Option<Route> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (scheme, rest) = match s.split_once("://") {
            Some((a, b)) => (a.to_ascii_lowercase(), b),
            None => ("http".to_string(), s),
        };
        let rest = rest.trim_end_matches('/');
        let rest = rest.rsplit_once('@').map(|(_, h)| h).unwrap_or(rest);
        let (host, port) = rest.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
        match scheme.as_str() {
            "http" | "https" => Some(Route::Http { host, port }),
            "socks5" | "socks5h" | "socks" => Some(Route::Socks5 { host, port }),
            _ => None,
        }
    }
}

pub struct Opened {
    pub stream: TcpStream,
    pub local_port: u16,
}

fn err<E: std::fmt::Display>(prefix: &str) -> impl FnOnce(E) -> String + '_ {
    move |e| format!("{prefix}: {e}")
}

/// Opens a TCP connection to `host:port` through `route`. For `Direct`, name
/// resolution goes through the system resolver so fake-ip DNS keeps working.
pub async fn open(route: &Route, host: &str, port: u16, limit: Duration) -> Result<Opened, String> {
    let fut = async {
        match route {
            Route::Direct => {
                let stream = TcpStream::connect((host, port)).await.map_err(err("连接失败"))?;
                let local_port = stream.local_addr().map_err(err("本地地址"))?.port();
                Ok(Opened { stream, local_port })
            }
            Route::Http { host: ph, port: pp } => {
                let mut stream = TcpStream::connect((ph.as_str(), *pp)).await.map_err(err("连接 HTTP 代理失败"))?;
                let local_port = stream.local_addr().map_err(err("本地地址"))?.port();
                let target = host_port(host, port);
                let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n");
                stream.write_all(req.as_bytes()).await.map_err(err("CONNECT 写入失败"))?;
                let head = read_head(&mut stream).await?;
                let status = head.lines().next().unwrap_or("");
                if !status.contains(" 200") {
                    return Err(format!("HTTP 代理拒绝 CONNECT：{status}"));
                }
                Ok(Opened { stream, local_port })
            }
            Route::Socks5 { host: ph, port: pp } => {
                let mut stream = TcpStream::connect((ph.as_str(), *pp)).await.map_err(err("连接 SOCKS5 代理失败"))?;
                let local_port = stream.local_addr().map_err(err("本地地址"))?.port();
                socks5_connect(&mut stream, host, port, None).await?;
                Ok(Opened { stream, local_port })
            }
        }
    };
    timeout(limit, fut).await.map_err(|_| "连接超时".to_string())?
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<String, String> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        let n = s.read(&mut byte).await.map_err(err("读取代理响应失败"))?;
        if n == 0 {
            return Err("代理提前关闭连接".into());
        }
        buf.push(byte[0]);
        if buf.len() > 16 * 1024 {
            return Err("代理响应头过长".into());
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// SOCKS5 CONNECT with optional username/password auth (RFC 1928 / 1929).
pub async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    port: u16,
    auth: Option<(&str, &str)>,
) -> Result<(), String> {
    let methods: &[u8] = if auth.is_some() { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] };
    s.write_all(methods).await.map_err(err("SOCKS5 握手失败"))?;
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await.map_err(err("SOCKS5 握手失败"))?;
    match rep[1] {
        0x00 => {}
        0x02 => {
            let (u, p) = auth.ok_or("SOCKS5 要求认证")?;
            let mut msg = vec![0x01, u.len() as u8];
            msg.extend_from_slice(u.as_bytes());
            msg.push(p.len() as u8);
            msg.extend_from_slice(p.as_bytes());
            s.write_all(&msg).await.map_err(err("SOCKS5 认证失败"))?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await.map_err(err("SOCKS5 认证失败"))?;
            if ar[1] != 0 {
                return Err("SOCKS5 用户名或密码错误".into());
            }
        }
        _ => return Err("SOCKS5 不支持的认证方式".into()),
    }
    let mut req = vec![0x05, 0x01, 0x00];
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else {
        req.push(0x03);
        req.push(host.len() as u8);
        req.extend_from_slice(host.as_bytes());
    }
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.map_err(err("SOCKS5 请求失败"))?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await.map_err(err("SOCKS5 响应失败"))?;
    if head[1] != 0 {
        return Err(format!("SOCKS5 连接被拒绝（code={}）", head[1]));
    }
    let skip = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.map_err(err("SOCKS5 响应失败"))?;
            l[0] as usize
        }
        _ => return Err("SOCKS5 响应地址类型未知".into()),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await.map_err(err("SOCKS5 响应失败"))?;
    Ok(())
}

fn tls_connector() -> TlsConnector {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    let cfg = CFG.get_or_init(|| {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    });
    TlsConnector::from(cfg.clone())
}

pub async fn tls_handshake(stream: TcpStream, host: &str, limit: Duration) -> Result<TlsStream<TcpStream>, String> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(err("无效的主机名"))?;
    timeout(limit, tls_connector().connect(name, stream))
        .await
        .map_err(|_| "TLS 握手超时".to_string())?
        .map_err(err("TLS 握手失败"))
}

pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// Sends a GET and reads the whole response (connection: close), de-chunking if needed.
pub async fn http_get<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    path: &str,
    limit: Duration,
) -> Result<HttpResponse, String> {
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetDect/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let fut = async {
        s.write_all(req.as_bytes()).await.map_err(err("请求写入失败"))?;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match s.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => {
                    raw.extend_from_slice(&chunk[..n]);
                    if raw.len() > 256 * 1024 {
                        break;
                    }
                }
                // Servers often drop TLS without close_notify after Connection: close.
                Err(_) if !raw.is_empty() => break,
                Err(e) => return Err(format!("读取响应失败: {e}")),
            }
        }
        parse_response(&raw)
    };
    timeout(limit, fut).await.map_err(|_| "读取响应超时".to_string())?
}

pub fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or("响应不完整")?;
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut body = raw[split + 4..].to_vec();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or("响应状态行无效")?;
    let chunked = head
        .lines()
        .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding:") && l.to_ascii_lowercase().contains("chunked"));
    if chunked {
        body = dechunk(&body);
    }
    Ok(HttpResponse { status, body: String::from_utf8_lossy(&body).into_owned() })
}

fn dechunk(mut data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let Some(pos) = data.windows(2).position(|w| w == b"\r\n") else { break };
        let size_line = String::from_utf8_lossy(&data[..pos]);
        let size = usize::from_str_radix(size_line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        data = &data[pos + 2..];
        if size == 0 || data.len() < size {
            out.extend_from_slice(&data[..data.len().min(size)]);
            break;
        }
        out.extend_from_slice(&data[..size]);
        data = &data[(size + 2).min(data.len())..];
    }
    out
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Trace {
    pub ip: String,
    pub loc: String,
    pub colo: String,
    /// Host header Cloudflare saw. Differs from the requested host when another
    /// server (e.g. Vercel in front of a Cloudflare zone) relays the request.
    pub h: String,
}

impl Trace {
    pub fn is_for(&self, host: &str) -> bool {
        self.h.is_empty() || self.h.eq_ignore_ascii_case(host)
    }
}

/// Parses a Cloudflare `/cdn-cgi/trace` body.
pub fn parse_trace(body: &str) -> Option<Trace> {
    let mut t = Trace::default();
    let mut has_fl = false;
    for line in body.lines() {
        if let Some((k, v)) = line.trim().split_once('=') {
            match k {
                "ip" => t.ip = v.to_string(),
                "loc" => t.loc = v.to_string(),
                "colo" => t.colo = v.to_string(),
                "h" => {
                    t.h = v.to_string();
                    has_fl = true;
                }
                "fl" | "visit_scheme" => has_fl = true,
                _ => {}
            }
        }
    }
    (has_fl && !t.ip.is_empty()).then_some(t)
}

/// Extracts the first IPv4 (or failing that IPv6) address that appears in `body`.
pub fn extract_ip(body: &str) -> Option<String> {
    let is_tok = |c: char| c.is_ascii_hexdigit() || c == '.' || c == ':';
    let tokens: Vec<&str> = body.split(|c: char| !is_tok(c)).filter(|t| !t.is_empty()).collect();
    tokens
        .iter()
        .find(|t| t.parse::<std::net::Ipv4Addr>().is_ok())
        .or_else(|| tokens.iter().find(|t| t.contains(':') && t.parse::<std::net::Ipv6Addr>().is_ok()))
        .map(|t| t.to_string())
}

/// Splits `https://host[:port]/path` into parts.
pub fn split_https_url(u: &str) -> Option<(String, u16, String)> {
    let parsed = url::Url::parse(u).ok()?;
    let host = parsed.host_str()?.to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);
    let mut path = parsed.path().to_string();
    if let Some(q) = parsed.query() {
        path.push('?');
        path.push_str(q);
    }
    Some((host, port, path))
}

/// One HTTPS GET through `route`, returning the local source port and the response.
pub async fn https_get(route: &Route, url: &str, limit: Duration) -> (Option<u16>, Result<HttpResponse, String>) {
    let Some((host, port, path)) = split_https_url(url) else {
        return (None, Err(format!("无效地址 {url}")));
    };
    let opened = match open(route, &host, port, limit).await {
        Ok(o) => o,
        Err(e) => return (None, Err(e)),
    };
    let lp = opened.local_port;
    let mut tls = match tls_handshake(opened.stream, &host, limit).await {
        Ok(t) => t,
        Err(e) => return (Some(lp), Err(e)),
    };
    (Some(lp), http_get(&mut tls, &host, &path, limit).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_parse() {
        let b = "fl=1\nh=claude.ai\nip=203.0.113.10\nts=1\nvisit_scheme=https\ncolo=NRT\nloc=JP\n";
        let t = parse_trace(b).unwrap();
        assert_eq!(t.ip, "203.0.113.10");
        assert_eq!(t.loc, "JP");
        assert!(t.is_for("claude.ai"));
        assert!(!t.is_for("modelcontextprotocol.io"));
        assert!(parse_trace("<html>404</html>").is_none());
    }

    #[test]
    fn ip_extract() {
        assert_eq!(extract_ip("当前 IP：1.2.3.4  来自于：日本").as_deref(), Some("1.2.3.4"));
        assert_eq!(extract_ip("{\"ip\":\"203.0.113.10\"}").as_deref(), Some("203.0.113.10"));
        assert_eq!(extract_ip("no ip here"), None);
    }

    #[test]
    fn proxy_parse() {
        assert_eq!(Route::parse_proxy("127.0.0.1:7897"), Some(Route::Http { host: "127.0.0.1".into(), port: 7897 }));
        assert_eq!(
            Route::parse_proxy("socks5://u:p@127.0.0.1:7898"),
            Some(Route::Socks5 { host: "127.0.0.1".into(), port: 7898 })
        );
    }

    #[test]
    fn chunked() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nip=1\r\n3\r\n.2.\r\n0\r\n\r\n";
        let r = parse_response(raw).unwrap();
        assert_eq!(r.body, "ip=1.2.");
    }
}
