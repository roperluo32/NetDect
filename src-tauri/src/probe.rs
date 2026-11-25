use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::engine::{Conn, Engine};
use crate::net::{self, Route};

pub const PROBE_FLAG: &str = "--netdect-probe";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildSpec {
    pub route: Route,
    pub url: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "lowercase")]
enum ChildMsg {
    Port { port: u16 },
    Done { ip: Option<String>, error: Option<String> },
}

fn emit(msg: &ChildMsg) {
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{}", serde_json::to_string(msg).unwrap_or_default());
    let _ = out.flush();
}

/// Entry point when NetDect runs as a renamed probe copy. Returns the exit code.
pub fn run_probe_child(spec_json: &str) -> i32 {
    let Ok(spec) = serde_json::from_str::<ChildSpec>(spec_json) else {
        emit(&ChildMsg::Done { ip: None, error: Some("探针参数无效".into()) });
        return 2;
    };
    let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return 3 };
    rt.block_on(async {
        let limit = Duration::from_millis(spec.timeout_ms);
        let Some((host, port, path)) = net::split_https_url(&spec.url) else {
            emit(&ChildMsg::Done { ip: None, error: Some("回显地址无效".into()) });
            return;
        };
        let opened = match net::open(&spec.route, &host, port, limit).await {
            Ok(o) => o,
            Err(e) => return emit(&ChildMsg::Done { ip: None, error: Some(e) }),
        };
        emit(&ChildMsg::Port { port: opened.local_port });
        let result = async {
            let mut tls = net::tls_handshake(opened.stream, &host, limit).await?;
            let resp = net::http_get(&mut tls, &host, &path, limit).await?;
            net::extract_ip(&resp.body).ok_or_else(|| format!("回显服务没有返回 IP（HTTP {}）", resp.status))
        }
        .await;
        match result {
            Ok(ip) => emit(&ChildMsg::Done { ip: Some(ip), error: None }),
            Err(e) => emit(&ChildMsg::Done { ip: None, error: Some(e) }),
        }
    });
    0
}

#[derive(Debug, Default)]
pub struct ProcProbeResult {
    pub ip: Option<String>,
    pub error: Option<String>,
    pub conn: Option<Conn>,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn probe_dir() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    std::env::temp_dir()
        .join("netdect-probe")
        .join(format!("{}-{nanos}-{n}", std::process::id()))
}

async fn remove_dir_retry(dir: PathBuf) {
    for _ in 0..20 {
        if tokio::fs::remove_dir_all(&dir).await.is_ok() || !dir.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

/// Runs a copy of this executable named `process_name` and reports the egress IP it observed.
pub async fn probe_process(process_name: &str, spec: &ChildSpec, engine: Option<&Engine>, limit: Duration) -> ProcProbeResult {
    let mut res = ProcProbeResult::default();
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            res.error = Some(format!("找不到自身可执行文件: {e}"));
            return res;
        }
    };
    let dir = probe_dir();
    let dest = dir.join(process_name);
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        res.error = Some(format!("创建临时目录失败: {e}"));
        return res;
    }
    if let Err(e) = tokio::fs::copy(&exe, &dest).await {
        res.error = Some(format!("复制探针失败: {e}"));
        remove_dir_retry(dir).await;
        return res;
    }

    let mut cmd = tokio::process::Command::new(&dest);
    cmd.arg(PROBE_FLAG)
        .arg(serde_json::to_string(spec).unwrap_or_default())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        cmd.creation_flags(0x0800_0000);
    }
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            res.error = Some(format!("启动探针失败: {e}"));
            remove_dir_retry(dir).await;
            return res;
        }
    };

    let stdout = child.stdout.take();
    let run = async {
        let mut attrib: Option<tokio::task::JoinHandle<Option<Conn>>> = None;
        let Some(stdout) = stdout else { return (None, Some("探针无输出".to_string()), attrib) };
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            match serde_json::from_str::<ChildMsg>(&line) {
                Ok(ChildMsg::Port { port }) => {
                    if let Some(e) = engine {
                        let e = e.clone();
                        attrib = Some(tokio::spawn(async move { e.find_by_port(port, Duration::from_millis(2500)).await }));
                    }
                }
                Ok(ChildMsg::Done { ip, error }) => return (ip, error, attrib),
                Err(_) => {}
            }
        }
        (None, Some("探针提前退出".to_string()), attrib)
    };
    match tokio::time::timeout(limit + Duration::from_secs(3), run).await {
        Ok((ip, error, attrib)) => {
            res.ip = ip;
            res.error = error;
            if let Some(h) = attrib {
                res.conn = h.await.ok().flatten();
            }
        }
        Err(_) => res.error = Some("探针超时".into()),
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
    remove_dir_retry(dir).await;
    res
}
