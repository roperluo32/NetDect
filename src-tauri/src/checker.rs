use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::config::AppConfig;
use crate::engine::{Conn, Engine};
use crate::env_check::{self, CheckItem, EnvReport};
use crate::net::{self, Route, Trace};
use crate::probe::{self, ChildSpec};
use crate::providers::ProviderDb;

const ECHO_URLS: &[&str] = &["https://4.ipw.cn/", "https://myip.ipip.net/json", "https://api.ipify.org/", "https://ipinfo.io/ip"];

#[derive(Debug, Clone, Serialize)]
pub struct ItemResult {
    pub id: usize,
    pub app: String,
    /// domain | suffix | keyword | process | cidr | cidr6 | asn
    pub kind: String,
    pub target: String,
    pub probe: String,
    /// rules | local | both
    pub source: String,
    /// pass | fail | warn | skip
    pub status: String,
    /// measured | attributed | sampled | none
    pub method: String,
    pub observed_ip: Option<String>,
    pub observed_loc: Option<String>,
    pub rule: Option<String>,
    pub chain: Vec<String>,
    pub node: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AppReport {
    pub id: String,
    pub name: String,
    pub status: String,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub skip: usize,
    pub discovered_roots: Vec<String>,
    pub items: Vec<ItemResult>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub started_at: u64,
    pub finished_at: u64,
    pub status: String,
    pub summary: String,
    pub cancelled: bool,
    pub target_id: String,
    pub target_name: String,
    pub expected_ip: String,
    pub expected_source: String,
    pub route: String,
    pub engine: Option<String>,
    pub engine_error: Option<String>,
    pub echo_url: Option<String>,
    pub baseline_ip: Option<String>,
    pub env: Vec<CheckItem>,
    pub apps: Vec<AppReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Progress {
    pub stage: String,
    pub done: usize,
    pub total: usize,
    pub item: Option<ItemResult>,
}

pub type ProgressFn = Arc<dyn Fn(Progress) + Send + Sync>;

#[derive(Clone)]
enum Job {
    Endpoint { host: String },
    Process { name: String },
    Skip,
}

struct Planned {
    item: ItemResult,
    job: Job,
}

fn new_item(id: usize, app: &str, kind: &str, target: &str, probe: &str, source: &str) -> ItemResult {
    ItemResult {
        id,
        app: app.to_string(),
        kind: kind.to_string(),
        target: target.to_string(),
        probe: probe.to_string(),
        source: source.to_string(),
        status: "warn".into(),
        method: "none".into(),
        observed_ip: None,
        observed_loc: None,
        rule: None,
        chain: Vec::new(),
        node: None,
        note: String::new(),
    }
}

fn first_host(cidr: &str) -> Option<String> {
    let net: ipnet::IpNet = cidr.trim().parse().ok()?;
    let host = match net {
        ipnet::IpNet::V4(n) => {
            let base = u32::from(n.network());
            IpAddr::from(std::net::Ipv4Addr::from(if n.prefix_len() >= 31 { base } else { base + 1 }))
        }
        ipnet::IpNet::V6(n) => {
            let base = u128::from(n.network());
            IpAddr::from(std::net::Ipv6Addr::from(base + 1))
        }
    };
    Some(host.to_string())
}

pub(crate) fn platform_process(name: &str) -> bool {
    let exe = name.to_ascii_lowercase().ends_with(".exe");
    if cfg!(windows) {
        exe
    } else {
        !exe
    }
}

pub(crate) fn same_proc(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn plan(cfg: &AppConfig, db: &ProviderDb, roots_out: &mut Vec<(String, Vec<String>)>) -> Vec<Planned> {
    let mut out = Vec::new();
    let mut id = 0usize;
    let push = |out: &mut Vec<Planned>, item: ItemResult, job: Job| {
        out.push(Planned { item, job });
    };
    for app_id in &cfg.selected_apps {
        let Some(p) = db.get(app_id) else { continue };
        let app = p.provider.as_str();
        let mut seen_hosts: HashSet<String> = HashSet::new();
        let mut rule_procs: Vec<String> = Vec::new();
        for g in &p.groups {
            let r = &g.rules;
            for d in &r.domain {
                if seen_hosts.insert(d.to_lowercase()) {
                    id += 1;
                    push(&mut out, new_item(id, app, "domain", d, d, "rules"), Job::Endpoint { host: d.clone() });
                }
            }
            for d in &r.domain_suffix {
                if seen_hosts.insert(d.to_lowercase()) {
                    id += 1;
                    push(&mut out, new_item(id, app, "suffix", d, d, "rules"), Job::Endpoint { host: d.clone() });
                }
            }
            for k in &r.domain_keyword {
                let host = format!("{k}.com");
                id += 1;
                let mut it = new_item(id, app, "keyword", k, &host, "rules");
                it.method = "sampled".into();
                push(&mut out, it, Job::Endpoint { host });
            }
            for c in &r.ip_cidr {
                id += 1;
                match first_host(c) {
                    Some(h) => push(&mut out, new_item(id, app, "cidr", c, &h, "rules"), Job::Endpoint { host: h }),
                    None => {
                        let mut it = new_item(id, app, "cidr", c, "", "rules");
                        it.status = "skip".into();
                        it.note = "IP 段格式无法解析".into();
                        push(&mut out, it, Job::Skip);
                    }
                }
            }
            for c in &r.ip_cidr6 {
                id += 1;
                let mut it = new_item(id, app, "cidr6", c, "", "rules");
                it.status = "skip".into();
                it.note = "IPv6 段不单独探测，是否存在 IPv6 旁路见环境检查".into();
                push(&mut out, it, Job::Skip);
            }
            for a in &r.asn {
                id += 1;
                let text = match a {
                    serde_yaml::Value::Number(n) => n.to_string(),
                    serde_yaml::Value::String(s) => s.clone(),
                    _ => "?".into(),
                };
                let mut it = new_item(id, app, "asn", &format!("AS{text}"), "", "rules");
                it.status = "skip".into();
                it.note = "ASN 规则无法直接探测，以同一服务的 IP 段为代表".into();
                push(&mut out, it, Job::Skip);
            }
            for n in &r.process_name {
                if platform_process(n) && !rule_procs.iter().any(|x| same_proc(x, n)) {
                    rule_procs.push(n.clone());
                }
            }
        }

        let extra = cfg.extra_process_paths.get(app).cloned().unwrap_or_default();
        let found = crate::discovery::discover(app, &extra);
        roots_out.push((app.to_string(), found.roots.clone()));
        let mut procs: Vec<(String, String, String)> = Vec::new();
        for (name, path) in &found.processes {
            let in_rules = rule_procs.iter().any(|r| same_proc(r, name));
            procs.push((name.clone(), if in_rules { "both" } else { "local" }.into(), path.clone()));
        }
        for r in &rule_procs {
            if !procs.iter().any(|(n, _, _)| same_proc(n, r)) {
                procs.push((r.clone(), "rules".into(), String::new()));
            }
        }
        for (name, source, path) in procs {
            id += 1;
            let mut it = new_item(id, app, "process", &name, &name, &source);
            if source == "local" {
                it.note = format!("规则表未收录，本机发现：{path}");
            }
            push(&mut out, it, Job::Process { name });
        }
    }
    out
}

pub(crate) struct EndpointOutcome {
    pub trace: Option<Trace>,
    pub conn: Option<Conn>,
    pub error: Option<String>,
    /// Host in a discarded trace that was relayed by another server.
    pub relayed: Option<String>,
}

pub(crate) async fn probe_endpoint(route: &Route, host: &str, engine: Option<&Engine>, limit: Duration) -> EndpointOutcome {
    let opened = match net::open(route, host, 443, limit).await {
        Ok(o) => o,
        Err(e) => return EndpointOutcome { trace: None, conn: None, error: Some(e), relayed: None },
    };
    // Look the connection up while it is still held open: servers that reject the
    // handshake close it before a concurrent lookup can see it. Engines that rely on
    // SNI sniffing only route after ClientHello, hence the second lookup.
    let port = opened.local_port;
    let early = match engine {
        Some(e) => e.find_by_port(port, Duration::from_millis(800)).await,
        None => None,
    };
    let attrib = match (&early, engine) {
        (None, Some(e)) => {
            let e = e.clone();
            Some(tokio::spawn(async move { e.find_by_port(port, Duration::from_millis(2500)).await }))
        }
        _ => None,
    };
    let tls = net::tls_handshake(opened.stream, host, limit).await;
    let conn = match attrib {
        Some(h) => h.await.ok().flatten(),
        None => early,
    };
    match tls {
        Ok(mut s) => match net::http_get(&mut s, host, "/cdn-cgi/trace", limit).await {
            Ok(resp) => {
                let trace = if resp.status == 200 { net::parse_trace(&resp.body) } else { None };
                match trace {
                    // The IP in a relayed trace belongs to the relaying server, not to us.
                    Some(t) if !t.is_for(host) => EndpointOutcome { trace: None, conn, error: None, relayed: Some(t.h) },
                    trace => EndpointOutcome { trace, conn, error: None, relayed: None },
                }
            }
            Err(e) => EndpointOutcome { trace: None, conn, error: Some(e), relayed: None },
        },
        Err(e) => EndpointOutcome { trace: None, conn, error: Some(e), relayed: None },
    }
}

fn apply_conn(it: &mut ItemResult, conn: &Option<Conn>) {
    if let Some(c) = conn {
        it.rule = Some(c.rule_text());
        it.chain = c.chains.clone();
        it.node = Some(c.node());
    }
}

pub(crate) fn is_direct_or_reject(node: &str) -> bool {
    let n = node.to_ascii_uppercase();
    n == "DIRECT" || n.starts_with("REJECT") || n == "PASS"
}

struct Ctx {
    route: Route,
    engine: Option<Engine>,
    expected: String,
    echo: Option<(String, bool)>,
    limit: Duration,
}

async fn run_job(ctx: &Ctx, mut it: ItemResult, job: Job) -> ItemResult {
    match job {
        Job::Skip => it,
        Job::Endpoint { host } => {
            let mut o = probe_endpoint(&ctx.route, &host, ctx.engine.as_ref(), ctx.limit).await;
            if it.kind == "suffix" && o.trace.is_none() && o.conn.is_none() && o.error.is_some() && !host.starts_with("www.") {
                let www = format!("www.{host}");
                let retry = probe_endpoint(&ctx.route, &www, ctx.engine.as_ref(), ctx.limit).await;
                if retry.trace.is_some() || retry.conn.is_some() {
                    it.probe = www;
                    o = retry;
                }
            }
            apply_conn(&mut it, &o.conn);
            let sampled = it.method == "sampled";
            if let Some(t) = o.trace {
                it.observed_ip = Some(t.ip.clone());
                it.observed_loc = Some(format!("{}{}", t.loc, if t.colo.is_empty() { String::new() } else { format!(" · {}", t.colo) }));
                it.method = if sampled { "sampled".into() } else { "measured".into() };
                if t.ip == ctx.expected {
                    it.status = "pass".into();
                } else {
                    it.status = "fail".into();
                    it.note = format!("出口是 {}，不是目标出口", t.ip);
                }
            } else if o.conn.is_some() {
                if !sampled {
                    it.method = "attributed".into();
                }
                it.status = "pending".into();
                if let Some(h) = &o.relayed {
                    it.note = format!("站点经其他服务器转发（trace 来自 {h}），trace 里的 IP 不是本机出口，改按节点判定");
                }
            } else {
                it.status = "warn".into();
                it.note = match (&o.error, ctx.engine.is_some()) {
                    _ if o.relayed.is_some() => format!(
                        "站点经其他服务器转发（trace 来自 {}），拿不到真实出口，且代理软件记录中没有这条连接",
                        o.relayed.clone().unwrap_or_default()
                    ),
                    (Some(e), _) => format!("{e}；无法确认出口"),
                    (None, true) => "非 Cloudflare 站点，且代理软件连接记录中没有找到这条连接".into(),
                    (None, false) => "非 Cloudflare 站点，且没有代理软件 API，无法确认出口".into(),
                };
            }
            it
        }
        Job::Process { name } => {
            let Some((url, distinct)) = ctx.echo.clone() else {
                it.status = "warn".into();
                it.note = "所有 IP 回显服务都不可用，无法做进程探测".into();
                return it;
            };
            let spec = ChildSpec { route: ctx.route.clone(), url, timeout_ms: ctx.limit.as_millis() as u64 };
            let r = probe::probe_process(&name, &spec, ctx.engine.as_ref(), ctx.limit).await;
            apply_conn(&mut it, &r.conn);
            let proc_rule = r.conn.as_ref().map(|c| c.rule.to_lowercase().contains("process")).unwrap_or(false);
            let prefix = if it.note.is_empty() { String::new() } else { format!("{}；", it.note) };
            match r.ip {
                Some(ip) => {
                    it.observed_ip = Some(ip.clone());
                    it.method = "measured".into();
                    if ip != ctx.expected && it.source == "local" {
                        it.status = "warn".into();
                        it.note = format!(
                            "{prefix}以该进程名发出的流量出口是 {ip}；它若联网会绕过目标出口，建议在代理软件里加 PROCESS-NAME,{name} 规则"
                        );
                    } else if ip != ctx.expected {
                        it.status = "fail".into();
                        it.note = format!("{prefix}以该进程名发出的流量出口是 {ip}");
                    } else if distinct || proc_rule {
                        it.status = "pass".into();
                    } else {
                        it.status = "warn".into();
                        it.note = format!("{prefix}回显服务本身就走目标出口，无法确认进程规则是否生效");
                    }
                }
                None => {
                    if r.conn.is_some() {
                        it.method = "attributed".into();
                        it.status = "pending".into();
                    } else {
                        it.status = "warn".into();
                    }
                    it.note = format!("{prefix}{}", r.error.unwrap_or_else(|| "探针未返回结果".into()));
                }
            }
            it
        }
    }
}

/// Second pass: judge attribution-only items against nodes proven by measurement.
fn finalize(items: &mut [ItemResult]) {
    let mut good: HashSet<String> = HashSet::new();
    let mut bad: HashSet<String> = HashSet::new();
    for it in items.iter() {
        if let Some(node) = &it.node {
            match (it.status.as_str(), it.method.as_str()) {
                ("pass", "measured") | ("pass", "sampled") => {
                    good.insert(node.clone());
                }
                ("fail", "measured") | ("fail", "sampled") => {
                    bad.insert(node.clone());
                }
                _ => {}
            }
        }
    }
    for it in items.iter_mut() {
        if it.status != "pending" {
            continue;
        }
        let node = it.node.clone().unwrap_or_default();
        let prefix = if it.note.is_empty() { String::new() } else { format!("{}；", it.note) };
        if is_direct_or_reject(&node) {
            it.status = "fail".into();
            it.note = format!("{prefix}被分到 {node}，没有走代理");
        } else if bad.contains(&node) && !good.contains(&node) {
            it.status = "fail".into();
            it.note = format!("{prefix}节点 {node} 已实测不是目标出口");
        } else if good.contains(&node) {
            it.status = "pass".into();
            if it.note.is_empty() {
                it.note = format!("与已实测通过的节点 {node} 一致");
            }
        } else {
            it.status = "warn".into();
            it.note = format!("{prefix}节点 {node} 没有被实测过，无法确认出口");
        }
    }
}

fn tally(items: &[ItemResult]) -> (usize, usize, usize, usize) {
    let c = |s: &str| items.iter().filter(|i| i.status == s).count();
    (c("pass"), c("fail"), c("warn"), c("skip"))
}

pub(crate) fn resolve_route(mode: &str, env: &EnvReport) -> Result<Route, String> {
    match mode {
        "tun" => Ok(Route::Direct),
        "system" => env.system_proxy.clone().ok_or_else(|| "设置为「系统代理」，但系统代理未开启或无法解析".into()),
        "env" => env.env_proxy.clone().ok_or_else(|| "设置为「环境变量」，但没有可用的代理环境变量".into()),
        _ => Ok(if env.tun_active {
            Route::Direct
        } else if let Some(r) = &env.system_proxy {
            r.clone()
        } else if let Some(r) = &env.env_proxy {
            r.clone()
        } else {
            Route::Direct
        }),
    }
}

async fn pick_echo(route: &Route, expected: &str) -> (Option<(String, bool)>, Option<String>) {
    let mut fallback: Option<(String, String)> = None;
    for url in ECHO_URLS {
        let (_, resp) = net::https_get(route, url, Duration::from_secs(6)).await;
        let Some(ip) = resp.ok().and_then(|r| net::extract_ip(&r.body)) else { continue };
        if ip != expected {
            return (Some((url.to_string(), true)), Some(ip));
        }
        fallback.get_or_insert((url.to_string(), ip));
    }
    match fallback {
        Some((u, ip)) => (Some((u, false)), Some(ip)),
        None => (None, None),
    }
}

pub async fn run(cfg: AppConfig, db: ProviderDb, cancel: Arc<AtomicBool>, progress: ProgressFn) -> Result<Report, String> {
    let started_at = crate::config::now_secs();
    let target_id = cfg.target_exit.clone().ok_or("还没有选择目标出口")?;
    let target = cfg.exit(&target_id).ok_or("目标出口不存在")?.clone();
    let (expected, expected_source) =
        target.expected_ip().ok_or("目标出口还没有 IP：请先点「刷新 IP」，或在编辑里手动固定期望 IP")?;
    if cfg.selected_apps.is_empty() {
        return Err("请至少勾选一个应用".into());
    }

    progress(Progress { stage: "环境检查".into(), done: 0, total: 0, item: None });
    let env = tokio::task::spawn_blocking(env_check::run).await.map_err(|e| e.to_string())?;
    let route = resolve_route(&cfg.probe.mode, &env)?;

    progress(Progress { stage: "连接代理软件 API".into(), done: 0, total: 0, item: None });
    let (engine, engine_error) = match crate::engine::connect(&cfg.engine).await {
        Ok(e) => (Some(e), None),
        Err(e) => (None, Some(e)),
    };

    progress(Progress { stage: "选择 IP 回显服务".into(), done: 0, total: 0, item: None });
    let (echo, baseline_ip) = pick_echo(&route, &expected).await;

    progress(Progress { stage: "发现本机应用".into(), done: 0, total: 0, item: None });
    let roots: Vec<(String, Vec<String>)>;
    let planned = {
        let cfg = cfg.clone();
        let db = db.clone();
        let (p, r) = tokio::task::spawn_blocking(move || {
            let mut roots = Vec::new();
            let p = plan(&cfg, &db, &mut roots);
            (p, roots)
        })
        .await
        .map_err(|e| e.to_string())?;
        roots = r;
        p
    };

    let total = planned.len();
    let ctx = Arc::new(Ctx {
        route: route.clone(),
        engine: engine.clone(),
        expected: expected.clone(),
        echo: echo.clone(),
        limit: Duration::from_secs(cfg.probe.timeout_secs.clamp(3, 60)),
    });
    let sem = Arc::new(tokio::sync::Semaphore::new(cfg.probe.concurrency.clamp(1, 32)));
    let mut set = tokio::task::JoinSet::new();
    for p in planned {
        let ctx = ctx.clone();
        let sem = sem.clone();
        let cancel = cancel.clone();
        set.spawn(async move {
            let _permit = sem.acquire_owned().await.ok();
            if cancel.load(Ordering::Relaxed) {
                return None;
            }
            Some(run_job(&ctx, p.item, p.job).await)
        });
    }
    let mut items: Vec<ItemResult> = Vec::with_capacity(total);
    let mut done = 0;
    while let Some(r) = set.join_next().await {
        if cancel.load(Ordering::Relaxed) {
            set.abort_all();
        }
        if let Ok(Some(it)) = r {
            done += 1;
            progress(Progress { stage: "检测中".into(), done, total, item: Some(it.clone()) });
            items.push(it);
        }
    }
    let cancelled = cancel.load(Ordering::Relaxed);
    items.sort_by_key(|i| i.id);
    finalize(&mut items);

    let mut apps = Vec::new();
    for app_id in &cfg.selected_apps {
        let Some(p) = db.get(app_id) else { continue };
        let its: Vec<ItemResult> = items.iter().filter(|i| &i.app == app_id).cloned().collect();
        let (pass, fail, warn, skip) = tally(&its);
        let status = if fail > 0 {
            "fail"
        } else if warn > 0 || pass == 0 {
            "warn"
        } else {
            "pass"
        };
        apps.push(AppReport {
            id: app_id.clone(),
            name: p.name.clone(),
            status: status.into(),
            pass,
            fail,
            warn,
            skip,
            discovered_roots: roots.iter().find(|(a, _)| a == app_id).map(|(_, r)| r.clone()).unwrap_or_default(),
            items: its,
        });
    }

    let (pass, fail, warn, _) = tally(&items);
    let env_fail = env.checks.iter().any(|c| c.status == "fail");
    let env_warn = env.checks.iter().any(|c| c.status == "warn");
    let status = if cancelled {
        "warn"
    } else if fail > 0 || env_fail {
        "fail"
    } else if warn > 0 || env_warn || pass == 0 {
        "warn"
    } else {
        "pass"
    };
    let summary = if cancelled {
        format!("检测已取消（完成 {done}/{total} 项）")
    } else {
        match status {
            "pass" => format!("全部 {pass} 项都从 {}（{expected}）出口", target.name),
            "fail" => format!("{fail} 项没有从 {}（{expected}）出口", target.name),
            _ => format!("{pass} 项通过，{warn} 项无法确认"),
        }
    };

    Ok(Report {
        started_at,
        finished_at: crate::config::now_secs(),
        status: status.into(),
        summary,
        cancelled,
        target_id,
        target_name: target.name.clone(),
        expected_ip: expected,
        expected_source: expected_source.into(),
        route: route.describe(),
        engine: engine.map(|e| format!("{} · {}", e.transport.describe(), e.version)),
        engine_error,
        echo_url: echo.map(|(u, distinct)| if distinct { u } else { format!("{u}（与目标出口相同，无法区分）") }),
        baseline_ip,
        env: env.checks,
        apps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_host() {
        assert_eq!(first_host("160.79.104.0/21").as_deref(), Some("160.79.104.1"));
        assert_eq!(first_host("2607:6bc0::/32").as_deref(), Some("2607:6bc0::1"));
    }

    fn item(status: &str, method: &str, node: &str) -> ItemResult {
        let mut i = new_item(0, "a", "domain", "x", "x", "rules");
        i.status = status.into();
        i.method = method.into();
        i.node = Some(node.into());
        i
    }

    #[test]
    fn two_pass() {
        let mut v = vec![
            item("pass", "measured", "japan01"),
            item("pending", "attributed", "japan01"),
            item("pending", "attributed", "DIRECT"),
            item("pending", "attributed", "seoul"),
        ];
        finalize(&mut v);
        assert_eq!(v[1].status, "pass");
        assert_eq!(v[2].status, "fail");
        assert_eq!(v[3].status, "warn");
    }
}
