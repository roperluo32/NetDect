use std::time::Duration;

use serde::Deserialize;

pub struct ExitInfo {
    pub ip: String,
    pub country: Option<String>,
    pub org: Option<String>,
}

#[derive(Deserialize)]
struct IpInfo {
    ip: Option<String>,
    country: Option<String>,
    org: Option<String>,
}

/// Connects to the configured SOCKS5 egress directly and asks an echo service for its IP.
pub async fn resolve(host: &str, port: u16, user: &str, pass: &str) -> Result<ExitInfo, String> {
    let mut url = url::Url::parse(&format!("socks5h://{host}:{port}")).map_err(|e| format!("出口地址无效: {e}"))?;
    if !user.is_empty() {
        url.set_username(user).map_err(|_| "用户名无效".to_string())?;
        url.set_password(Some(pass)).map_err(|_| "密码无效".to_string())?;
    }
    let proxy = reqwest::Proxy::all(url.as_str()).map_err(|e| e.to_string())?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|e| e.to_string())?;

    let mut errors = Vec::new();
    match client.get("https://ipinfo.io/json").send().await {
        Ok(r) => match r.json::<IpInfo>().await {
            Ok(info) if info.ip.is_some() => {
                return Ok(ExitInfo { ip: info.ip.unwrap_or_default(), country: info.country, org: info.org });
            }
            Ok(_) => errors.push("ipinfo.io 未返回 IP".to_string()),
            Err(e) => errors.push(format!("ipinfo.io: {e}")),
        },
        Err(e) => errors.push(format!("ipinfo.io: {}", describe(&e))),
    }
    match client.get("https://www.cloudflare.com/cdn-cgi/trace").send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            if let Some(t) = crate::net::parse_trace(&body) {
                return Ok(ExitInfo { ip: t.ip, country: Some(t.loc), org: None });
            }
            errors.push("cloudflare trace 无结果".into());
        }
        Err(e) => errors.push(format!("cloudflare: {}", describe(&e))),
    }
    Err(format!("无法经该出口访问回显服务（{}）。如果本机连不上该代理，可以手动固定期望 IP", errors.join("；")))
}

fn describe(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(inner) = src {
        s.push_str(": ");
        s.push_str(&inner.to_string());
        src = inner.source();
    }
    s
}
