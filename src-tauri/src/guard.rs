//! Runtime guard: watches the proxy engine's live connections and flags any
//! connection of a selected app that does not leave through the target exit.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use serde::Serialize;
use tokio::sync::Notify;

use crate::checker::{self, Report};
use crate::config::{now_secs, AppConfig};
use crate::engine::{self, Conn, Engine};
use crate::providers::ProviderDb;

const MAX_EVENTS: usize = 1000;
const NOTIFY_SAME_KEY: Duration = Duration::from_secs(120);
const NOTIFY_ANY: Duration = Duration::from_secs(3);
const PROCESS_SCAN: Duration = Duration::from_secs(3);
const RECONNECT: Duration = Duration::from_secs(5);
const ENGINE_FAILS_BEFORE_ALERT: u32 = 3;
const APP_VERIFY_GAP: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Default)]
pub struct GuardEvent {
    pub seq: u64,
    pub time: u64,
    /// ok | leak | unverified | blocked | system
    pub level: String,
    pub app: String,
    pub app_name: String,
    pub process: String,
    pub host: String,
    pub dst: String,
    pub network: String,
    /// process | domain | ip, empty for system events
    pub matched_by: String,
    pub rule: String,
    pub chain: Vec<String>,
    pub node: String,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct NodeInfo {
    pub node: String,
    pub ip: String,
    pub good: bool,
    pub checked_at: u64,
    pub via: String,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct WatchedApp {
    pub id: String,
    pub name: String,
    pub running: Vec<String>,
    pub process_names: usize,
    pub roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct Counts {
    pub ok: u64,
    pub leak: u64,
    pub unverified: u64,
    pub blocked: u64,
}

#[derive(Debug, Clone, Serialize, Default, PartialEq)]
pub struct GuardStatus {
    pub running: bool,
    /// off | starting | ok | warn | alert | error
    pub state: String,
    pub headline: String,
    pub started_at: Option<u64>,
    pub target_name: String,
    pub expected_ip: String,
    pub engine: Option<String>,
    pub engine_error: Option<String>,
    pub last_verify: Option<u64>,
    pub verify_ok: Option<bool>,
    pub verify_note: String,
    pub verifying: bool,
    pub nodes: Vec<NodeInfo>,
    pub apps: Vec<WatchedApp>,
    pub counts: Counts,
    /// Matched connections currently open.
    pub active: usize,
    pub env_problems: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GuardSnapshot {
    pub status: GuardStatus,
    pub events: Vec<GuardEvent>,
}

pub trait GuardHooks: Send + Sync + 'static {
    fn status(&self, status: &GuardStatus);
    fn event(&self, event: &GuardEvent);
    fn notify(&self, title: &str, body: &str);
}

struct AppMatcher {
    id: String,
    name: String,
    names: HashSet<String>,
    roots: Vec<String>,
    domains: HashSet<String>,
    suffixes: Vec<String>,
    keywords: Vec<String>,
    cidrs: Vec<IpNet>,
}

impl AppMatcher {
    fn matches(&self, c: &Conn) -> Option<&'static str> {
        let proc_name = c.process.to_lowercase();
        if !proc_name.is_empty() && self.names.contains(&proc_name) {
            return Some("process");
        }
        let path = c.process_path.to_lowercase();
        if !path.is_empty() && self.roots.iter().any(|r| path.starts_with(r)) {
            return Some("process");
        }
        let host = c.domain().trim_end_matches('.').to_lowercase();
        if !host.is_empty() {
            if self.domains.contains(&host)
                || self.suffixes.iter().any(|s| host == *s || host.ends_with(&format!(".{s}")))
                || self.keywords.iter().any(|k| host.contains(k.as_str()))
            {
                return Some("domain");
            }
        }
        if let Ok(ip) = c.dst_ip.parse::<IpAddr>() {
            if self.cidrs.iter().any(|n| n.contains(&ip)) {
                return Some("ip");
            }
        }
        None
    }
}

fn with_sep(p: &str) -> String {
    let l = p.to_lowercase();
    if l.ends_with('\\') || l.ends_with('/') {
        l
    } else if cfg!(windows) {
        format!("{l}\\")
    } else {
        format!("{l}/")
    }
}

fn build_matchers(cfg: &AppConfig, db: &ProviderDb) -> Vec<AppMatcher> {
    let mut out = Vec::new();
    for id in &cfg.selected_apps {
        let Some(p) = db.get(id) else { continue };
        let mut m = AppMatcher {
            id: p.provider.clone(),
            name: p.name.clone(),
            names: HashSet::new(),
            roots: Vec::new(),
            domains: HashSet::new(),
            suffixes: Vec::new(),
            keywords: Vec::new(),
            cidrs: Vec::new(),
        };
        for g in &p.groups {
            let r = &g.rules;
            m.domains.extend(r.domain.iter().map(|d| d.to_lowercase()));
            m.suffixes.extend(r.domain_suffix.iter().map(|d| d.trim_start_matches('.').to_lowercase()));
            m.keywords.extend(r.domain_keyword.iter().map(|d| d.to_lowercase()));
            m.cidrs.extend(r.ip_cidr.iter().chain(r.ip_cidr6.iter()).filter_map(|c| c.parse::<IpNet>().ok()));
            m.names.extend(r.process_name.iter().filter(|n| checker::platform_process(n)).map(|n| n.to_lowercase()));
        }
        let extra = cfg.extra_process_paths.get(id).cloned().unwrap_or_default();
        let found = crate::discovery::discover(id, &extra);
        m.names.extend(found.processes.iter().map(|(n, _)| n.to_lowercase()));
        m.roots = found.roots.iter().map(|r| with_sep(r)).collect();
        out.push(m);
    }
    out
}

fn is_local(c: &Conn) -> bool {
    let host = c.domain().to_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".lan") {
        return true;
    }
    match c.dst_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v)) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_unspecified()
                || v.is_broadcast()
                || v.is_multicast()
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        Ok(IpAddr::V6(v)) => {
            let s = v.segments()[0];
            v.is_loopback() || v.is_unspecified() || v.is_multicast() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
        Err(_) => host.is_empty(),
    }
}

/// Probes launched by NetDect itself (checker endpoints and renamed process probes).
fn is_own(c: &Conn, own_exe: &str) -> bool {
    let path = c.process_path.to_lowercase();
    path.contains("netdect-probe") || (!own_exe.is_empty() && path == own_exe)
}

fn display_chain(c: &Conn) -> Vec<String> {
    c.chains.iter().rev().cloned().collect()
}

fn judge(node: &str, rule: &str, nodes: &HashMap<String, NodeInfo>, expected: &str) -> (&'static str, String) {
    let upper = node.to_ascii_uppercase();
    if node.is_empty() {
        return ("unverified", "代理软件没有给出这条连接的节点".into());
    }
    if upper.starts_with("REJECT") {
        return ("blocked", format!("被规则拦截（{rule}），没有发出"));
    }
    if upper == "DIRECT" || upper == "PASS" {
        return ("leak", "直连，没有经过代理，出口是本机 IP".into());
    }
    match nodes.get(node) {
        Some(n) if n.ip == expected => ("ok", String::new()),
        Some(n) => ("leak", format!("节点 {node} 实测出口是 {}，不是目标 {expected}", n.ip)),
        None => ("unverified", format!("节点 {node} 还没有实测过出口 IP")),
    }
}

struct Inner {
    status: GuardStatus,
    events: VecDeque<GuardEvent>,
    seq: u64,
    nodes: HashMap<String, NodeInfo>,
    report_hosts: HashMap<String, Vec<String>>,
    matchers: Arc<Vec<AppMatcher>>,
    engine: Option<Engine>,
    last_notify: HashMap<String, Instant>,
    last_any_notify: Option<Instant>,
    pending_nodes: HashSet<String>,
    off_target: Vec<String>,
    emitted: Option<GuardStatus>,
}

struct Shared {
    inner: Mutex<Inner>,
    generation: AtomicU64,
    verifying: AtomicBool,
    wake: Notify,
    hooks: Arc<dyn GuardHooks>,
    config: Arc<Mutex<AppConfig>>,
    providers: Arc<Mutex<ProviderDb>>,
    own_exe: String,
}

#[derive(Clone)]
pub struct Guard {
    sh: Arc<Shared>,
}

enum VerifyReason {
    Start,
    Timer,
    Manual,
    AppStart(String),
}

impl Guard {
    pub fn new(config: Arc<Mutex<AppConfig>>, providers: Arc<Mutex<ProviderDb>>, hooks: Arc<dyn GuardHooks>) -> Self {
        let own_exe = std::env::current_exe().map(|p| p.to_string_lossy().to_lowercase()).unwrap_or_default();
        let mut status = GuardStatus::default();
        refresh_state(&mut status);
        Guard {
            sh: Arc::new(Shared {
                inner: Mutex::new(Inner {
                    status,
                    events: VecDeque::new(),
                    seq: 0,
                    nodes: HashMap::new(),
                    report_hosts: HashMap::new(),
                    matchers: Arc::new(Vec::new()),
                    engine: None,
                    last_notify: HashMap::new(),
                    last_any_notify: None,
                    pending_nodes: HashSet::new(),
                    off_target: Vec::new(),
                    emitted: None,
                }),
                generation: AtomicU64::new(0),
                verifying: AtomicBool::new(false),
                wake: Notify::new(),
                hooks,
                config,
                providers,
                own_exe,
            }),
        }
    }

    pub fn is_running(&self) -> bool {
        self.sh.inner.lock().unwrap().status.running
    }

    pub fn snapshot(&self) -> GuardSnapshot {
        let g = self.sh.inner.lock().unwrap();
        GuardSnapshot { status: g.status.clone(), events: g.events.iter().cloned().collect() }
    }

    pub fn start(&self) -> Result<GuardStatus, String> {
        let cfg = self.sh.config.lock().unwrap().clone();
        let (target_name, expected) = target_of(&cfg)?;
        if cfg.selected_apps.is_empty() {
            return Err("请至少勾选一个应用".into());
        }
        let gen = {
            let mut g = self.sh.inner.lock().unwrap();
            if g.status.running {
                return Ok(g.status.clone());
            }
            let gen = self.sh.generation.fetch_add(1, Ordering::SeqCst) + 1;
            let s = &mut g.status;
            s.running = true;
            s.started_at = Some(now_secs());
            s.target_name = target_name;
            s.expected_ip = expected;
            s.counts = Counts::default();
            s.verify_ok = None;
            s.verify_note.clear();
            s.engine_error = None;
            s.env_problems.clear();
            g.pending_nodes.clear();
            g.off_target.clear();
            gen
        };
        self.sh.push_system("system", "守护已开启".into());
        self.sh.publish();
        let sh = self.sh.clone();
        tauri::async_runtime::spawn(async move { run_loop(sh, gen).await });
        Ok(self.snapshot().status)
    }

    pub fn stop(&self) -> GuardStatus {
        self.sh.generation.fetch_add(1, Ordering::SeqCst);
        {
            let mut g = self.sh.inner.lock().unwrap();
            if !g.status.running {
                return g.status.clone();
            }
            g.status.running = false;
            g.status.active = 0;
            g.status.apps.iter_mut().for_each(|a| a.running.clear());
        }
        self.sh.wake.notify_one();
        self.sh.push_system("system", "守护已暂停".into());
        self.sh.publish();
        self.snapshot().status
    }

    /// Re-verify now; also picks up target / app selection changes.
    pub fn verify_now(&self) {
        if !self.is_running() {
            return;
        }
        let sh = self.sh.clone();
        tauri::async_runtime::spawn(async move { verify(sh, VerifyReason::Manual).await });
    }

    /// Called after settings change: refresh target and matchers without losing history.
    pub fn reconfigure(&self) {
        let cfg = self.sh.config.lock().unwrap().clone();
        if let Ok((name, ip)) = target_of(&cfg) {
            let mut g = self.sh.inner.lock().unwrap();
            g.status.target_name = name;
            g.status.expected_ip = ip;
        }
        self.verify_now();
    }

    pub fn clear(&self) {
        {
            let mut g = self.sh.inner.lock().unwrap();
            g.status.counts = Counts::default();
            g.events.clear();
        }
        self.sh.publish();
    }

    /// Seeds the node → exit IP table and verification hosts from a finished check.
    pub fn learn_from_report(&self, r: &Report) {
        let mut g = self.sh.inner.lock().unwrap();
        for app in &r.apps {
            let mut hosts = Vec::new();
            for it in &app.items {
                let (Some(node), Some(ip)) = (&it.node, &it.observed_ip) else { continue };
                if it.method != "measured" || checker::is_direct_or_reject(node) {
                    continue;
                }
                g.nodes.insert(
                    node.clone(),
                    NodeInfo { node: node.clone(), ip: ip.clone(), good: false, checked_at: r.finished_at, via: format!("检测 {}", it.probe) },
                );
                if it.kind != "process" && it.status == "pass" && hosts.len() < 3 {
                    hosts.push(it.probe.clone());
                }
            }
            if !hosts.is_empty() {
                g.report_hosts.insert(app.id.clone(), hosts);
            }
        }
        drop(g);
        self.sh.publish();
    }
}

fn target_of(cfg: &AppConfig) -> Result<(String, String), String> {
    let id = cfg.target_exit.clone().ok_or("还没有选择目标出口")?;
    let exit = cfg.exit(&id).ok_or("目标出口不存在")?;
    let (ip, _) = exit.expected_ip().ok_or("目标出口还没有 IP：请先「刷新 IP」或固定 IP")?;
    Ok((exit.name.clone(), ip))
}

fn refresh_state(s: &mut GuardStatus) {
    let (state, headline) = if !s.running {
        ("off", "守护未开启".to_string())
    } else if s.engine.is_none() && s.engine_error.is_some() {
        ("error", "代理软件 API 无法访问，看不到实时连接".to_string())
    } else if s.verify_ok == Some(false) {
        ("alert", "出口复核失败：目标出口没有生效".to_string())
    } else if s.counts.leak > 0 {
        ("alert", format!("发现 {} 条连接没走目标出口", s.counts.leak))
    } else if !s.env_problems.is_empty() {
        ("alert", format!("环境异常：{}", s.env_problems.join("；")))
    } else if s.counts.unverified > 0 {
        ("warn", format!("{} 条连接的节点没有实测过", s.counts.unverified))
    } else if s.verify_ok.is_none() && s.last_verify.is_some() {
        ("warn", "出口复核没有结论，只能依据节点判断".to_string())
    } else if s.verify_ok.is_none() {
        ("starting", "正在复核出口…".to_string())
    } else {
        ("ok", "守护中 · 全部经目标出口".to_string())
    };
    s.state = state.into();
    s.headline = headline;
}

impl Shared {
    fn gen_alive(&self, gen: u64) -> bool {
        self.generation.load(Ordering::SeqCst) == gen
    }

    fn publish(&self) {
        let mut g = self.inner.lock().unwrap();
        let expected = g.status.expected_ip.clone();
        let mut nodes: Vec<NodeInfo> = g
            .nodes
            .values()
            .cloned()
            .map(|mut n| {
                n.good = n.ip == expected;
                n
            })
            .collect();
        nodes.sort_by(|a, b| b.good.cmp(&a.good).then(a.node.cmp(&b.node)));
        g.status.nodes = nodes;
        g.status.verifying = self.verifying.load(Ordering::SeqCst);
        refresh_state(&mut g.status);
        if g.emitted.as_ref() == Some(&g.status) {
            return;
        }
        g.emitted = Some(g.status.clone());
        let s = g.status.clone();
        drop(g);
        self.hooks.status(&s);
    }

    fn push(&self, mut e: GuardEvent) -> u64 {
        let mut g = self.inner.lock().unwrap();
        g.seq += 1;
        e.seq = g.seq;
        e.time = now_secs();
        g.events.push_back(e.clone());
        while g.events.len() > MAX_EVENTS {
            g.events.pop_front();
        }
        drop(g);
        self.hooks.event(&e);
        e.seq
    }

    /// Re-judges an event in place; listeners upsert by `seq`.
    fn update_event(&self, seq: u64, level: &str, note: String) {
        let mut g = self.inner.lock().unwrap();
        let Some(e) = g.events.iter_mut().find(|e| e.seq == seq) else { return };
        e.level = level.into();
        e.note = note;
        let e = e.clone();
        drop(g);
        self.hooks.event(&e);
    }

    fn push_system(&self, level: &str, note: String) {
        self.push(GuardEvent { level: level.into(), note, ..Default::default() });
    }

    fn count(&self, level: &str, delta: i64) {
        let mut g = self.inner.lock().unwrap();
        let k = &mut g.status.counts;
        let slot = match level {
            "ok" => &mut k.ok,
            "leak" => &mut k.leak,
            "blocked" => &mut k.blocked,
            _ => &mut k.unverified,
        };
        *slot = (*slot as i64 + delta).max(0) as u64;
    }

    fn notify(&self, key: &str, title: &str, body: &str) {
        if !self.config.lock().unwrap().guard.notify {
            return;
        }
        let now = Instant::now();
        {
            let mut g = self.inner.lock().unwrap();
            if g.last_notify.get(key).is_some_and(|t| now.duration_since(*t) < NOTIFY_SAME_KEY) {
                return;
            }
            if g.last_any_notify.is_some_and(|t| now.duration_since(t) < NOTIFY_ANY) {
                return;
            }
            g.last_notify.insert(key.to_string(), now);
            g.last_any_notify = Some(now);
        }
        self.hooks.notify(title, body);
    }
}

struct Seen {
    seq: u64,
    level: &'static str,
}

struct LoopState {
    seen: HashMap<String, Seen>,
    engine_fails: u32,
    last_reconnect: Option<Instant>,
    sys: Arc<Mutex<sysinfo::System>>,
    prev_running: HashMap<String, Vec<String>>,
    last_app_verify: HashMap<String, Instant>,
    first_scan: bool,
}

async fn run_loop(sh: Arc<Shared>, gen: u64) {
    let mut st = LoopState {
        seen: HashMap::new(),
        engine_fails: 0,
        last_reconnect: None,
        sys: Arc::new(Mutex::new(sysinfo::System::new())),
        prev_running: HashMap::new(),
        last_app_verify: HashMap::new(),
        first_scan: true,
    };
    connect_engine(&sh).await;
    {
        let sh2 = sh.clone();
        tauri::async_runtime::spawn(async move { verify(sh2, VerifyReason::Start).await });
    }
    let mut next_scan = Instant::now();
    let mut next_verify = Instant::now() + verify_interval(&sh);

    loop {
        let poll = Duration::from_millis(sh.config.lock().unwrap().guard.poll_ms.clamp(300, 10_000));
        tokio::select! {
            _ = tokio::time::sleep(poll) => {}
            _ = sh.wake.notified() => {}
        }
        if !sh.gen_alive(gen) {
            break;
        }
        poll_connections(&sh, &mut st).await;
        let now = Instant::now();
        if now >= next_scan {
            next_scan = now + PROCESS_SCAN;
            scan_processes(&sh, &mut st).await;
        }
        if now >= next_verify {
            next_verify = now + verify_interval(&sh);
            let sh2 = sh.clone();
            tauri::async_runtime::spawn(async move { verify(sh2, VerifyReason::Timer).await });
        }
        sh.publish();
    }
}

fn verify_interval(sh: &Shared) -> Duration {
    Duration::from_secs(sh.config.lock().unwrap().guard.verify_minutes.clamp(1, 120) * 60)
}

async fn connect_engine(sh: &Arc<Shared>) -> bool {
    let cfg = sh.config.lock().unwrap().engine.clone();
    match engine::connect(&cfg).await {
        Ok(e) => {
            let mut g = sh.inner.lock().unwrap();
            g.status.engine = Some(format!("{} · {}", e.transport.describe(), e.version));
            g.status.engine_error = None;
            g.engine = Some(e);
            true
        }
        Err(err) => {
            let mut g = sh.inner.lock().unwrap();
            g.status.engine = None;
            g.status.engine_error = Some(err);
            g.engine = None;
            false
        }
    }
}

async fn poll_connections(sh: &Arc<Shared>, st: &mut LoopState) {
    let engine = sh.inner.lock().unwrap().engine.clone();
    let Some(engine) = engine else {
        if st.last_reconnect.is_none_or(|t| t.elapsed() >= RECONNECT) {
            st.last_reconnect = Some(Instant::now());
            if connect_engine(sh).await {
                sh.push_system("system", "已连接代理软件 API，开始监视实时连接".into());
            }
        }
        return;
    };

    let list = match engine.connections().await {
        Ok(l) => l,
        Err(e) => {
            st.engine_fails += 1;
            if st.engine_fails == ENGINE_FAILS_BEFORE_ALERT {
                {
                    let mut g = sh.inner.lock().unwrap();
                    g.engine = None;
                    g.status.engine = None;
                    g.status.engine_error = Some(e.clone());
                }
                sh.push_system("leak", format!("代理软件 API 无响应，守护看不到实时连接：{e}"));
                sh.notify("engine", "NetDect：守护中断", "代理软件 API 无响应，无法确认流量出口。代理软件可能已退出。");
            }
            return;
        }
    };
    st.engine_fails = 0;

    let (matchers, nodes, expected, verified) = {
        let g = sh.inner.lock().unwrap();
        (g.matchers.clone(), g.nodes.clone(), g.status.expected_ip.clone(), g.status.last_verify.is_some())
    };
    let active_ids: HashSet<&str> = list.iter().map(|c| c.id.as_str()).collect();
    st.seen.retain(|id, _| active_ids.contains(id.as_str()));

    let mut active = 0usize;
    for c in &list {
        if c.inbound_type.eq_ignore_ascii_case("inner") || is_own(c, &sh.own_exe) || is_local(c) {
            continue;
        }
        let Some((m, by)) = matchers.iter().find_map(|m| m.matches(c).map(|by| (m, by))) else { continue };
        active += 1;
        let node = c.node();
        let rule = c.rule_text();
        let (level, note) = judge(&node, &rule, &nodes, &expected);
        if let Some(prev) = st.seen.get_mut(&c.id) {
            // Nodes get measured after connections were first seen; settle those now.
            if prev.level == "unverified" && level != "unverified" {
                sh.count(prev.level, -1);
                sh.count(level, 1);
                sh.update_event(prev.seq, level, note.clone());
                prev.level = level;
                if level == "leak" {
                    notify_leak(sh, m, c, &node);
                }
            }
            continue;
        }
        let host = c.domain().to_string();
        let dst = if c.dst_ip.is_empty() { format!(":{}", c.dst_port) } else { format!("{}:{}", c.dst_ip, c.dst_port) };
        sh.count(level, 1);
        let seq = sh.push(GuardEvent {
            level: level.into(),
            app: m.id.clone(),
            app_name: m.name.clone(),
            process: c.process.clone(),
            host: host.clone(),
            dst,
            network: c.network.clone(),
            matched_by: by.into(),
            rule,
            chain: display_chain(c),
            node: node.clone(),
            note,
            ..Default::default()
        });
        st.seen.insert(c.id.clone(), Seen { seq, level });
        if level == "leak" {
            notify_leak(sh, m, c, &node);
        } else if level == "unverified" && !host.is_empty() && verified {
            let first = sh.inner.lock().unwrap().pending_nodes.insert(node.clone());
            if first {
                let sh2 = sh.clone();
                tauri::async_runtime::spawn(async move { check_node(sh2, node, host).await });
            }
        }
    }
    sh.inner.lock().unwrap().status.active = active;
}

fn notify_leak(sh: &Shared, m: &AppMatcher, c: &Conn, node: &str) {
    let who = if c.process.is_empty() { m.name.clone() } else { format!("{}（{}）", m.name, c.process) };
    let target = if c.domain().is_empty() { c.dst_ip.as_str() } else { c.domain() };
    sh.notify(
        &format!("leak|{}|{}|{}", m.id, c.process, node),
        "NetDect：发现流量没走目标出口",
        &format!("{who} → {target}，经 {node}"),
    );
}

/// Learns an unknown node's exit IP by probing the same host the app used.
async fn check_node(sh: Arc<Shared>, node: String, host: String) {
    let (engine, cfg) = (sh.inner.lock().unwrap().engine.clone(), sh.config.lock().unwrap().clone());
    let env = tokio::task::spawn_blocking(crate::env_check::run).await;
    let Ok(env) = env else { return };
    let Ok(route) = checker::resolve_route(&cfg.probe.mode, &env) else { return };
    let o = checker::probe_endpoint(&route, &host, engine.as_ref(), Duration::from_secs(8)).await;
    let probed_node = o.conn.as_ref().map(|c| c.node()).unwrap_or_default();
    match o.trace {
        Some(t) if !probed_node.is_empty() && !checker::is_direct_or_reject(&probed_node) => {
            let expected = sh.inner.lock().unwrap().status.expected_ip.clone();
            sh.inner.lock().unwrap().nodes.insert(
                probed_node.clone(),
                NodeInfo { node: probed_node.clone(), ip: t.ip.clone(), good: false, checked_at: now_secs(), via: format!("按需实测 {host}") },
            );
            let ok = t.ip == expected;
            sh.push_system(
                if ok { "ok" } else { "leak" },
                format!("按需实测：节点 {probed_node} 的出口是 {}（{}），{}", t.ip, t.loc, if ok { "与目标一致" } else { "不是目标出口" }),
            );
            if !ok {
                sh.notify(&format!("node|{probed_node}"), "NetDect：节点出口不对", &format!("节点 {probed_node} 的出口是 {}", t.ip));
            }
        }
        _ => {
            sh.push_system(
                "unverified",
                format!("节点 {node} 无法按需实测（{host} 不返回出口 IP），可以运行一次「检测」来确认"),
            );
        }
    }
    sh.publish();
}

async fn scan_processes(sh: &Arc<Shared>, st: &mut LoopState) {
    let matchers = sh.inner.lock().unwrap().matchers.clone();
    if matchers.is_empty() {
        return;
    }
    let sys = st.sys.clone();
    let own = sh.own_exe.clone();
    let m2 = matchers.clone();
    let running: Vec<Vec<String>> = tokio::task::spawn_blocking(move || {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
        let mut sys = sys.lock().unwrap();
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));
        let mut out: Vec<Vec<String>> = vec![Vec::new(); m2.len()];
        for p in sys.processes().values() {
            let name = p.name().to_string_lossy().to_string();
            let path = p.exe().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            if path.contains("netdect-probe") || path == own {
                continue;
            }
            let lname = name.to_lowercase();
            for (i, m) in m2.iter().enumerate() {
                let hit = m.names.contains(&lname) || (!path.is_empty() && m.roots.iter().any(|r| path.starts_with(r)));
                if hit && !out[i].iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                    out[i].push(name.clone());
                }
            }
        }
        out.iter_mut().for_each(|v| v.sort());
        out
    })
    .await
    .unwrap_or_default();

    let verify_on_start = sh.config.lock().unwrap().guard.verify_on_app_start;
    let mut started = Vec::new();
    {
        let mut g = sh.inner.lock().unwrap();
        for (i, m) in matchers.iter().enumerate() {
            let names = running.get(i).cloned().unwrap_or_default();
            // Per process name: apps may keep a background service running all the time.
            let prev = st.prev_running.insert(m.id.clone(), names.clone()).unwrap_or_default();
            let fresh: Vec<String> = names.iter().filter(|n| !prev.contains(n)).cloned().collect();
            if !fresh.is_empty() && !st.first_scan {
                started.push((m.id.clone(), m.name.clone(), fresh));
            }
            if let Some(a) = g.status.apps.iter_mut().find(|a| a.id == m.id) {
                a.running = names;
            }
        }
    }
    st.first_scan = false;
    for (id, name, procs) in started {
        sh.push_system("system", format!("{name} 启动了 {}", procs.join("、")));
        let due = st.last_app_verify.get(&id).is_none_or(|t| t.elapsed() >= APP_VERIFY_GAP);
        if verify_on_start && due {
            st.last_app_verify.insert(id, Instant::now());
            let sh2 = sh.clone();
            tauri::async_runtime::spawn(async move { verify(sh2, VerifyReason::AppStart(name)).await });
        }
    }
}

fn verify_hosts(cfg: &AppConfig, db: &ProviderDb, from_report: &HashMap<String, Vec<String>>) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for id in &cfg.selected_apps {
        let picks: Vec<String> = match from_report.get(id) {
            Some(h) => h.iter().take(2).cloned().collect(),
            None => db
                .get(id)
                .map(|p| {
                    p.groups
                        .iter()
                        .flat_map(|g| g.rules.domain_suffix.iter().chain(g.rules.domain.iter()))
                        .take(2)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        };
        for h in picks {
            if !hosts.contains(&h) {
                hosts.push(h);
            }
        }
    }
    hosts.truncate(8);
    hosts
}

async fn verify(sh: Arc<Shared>, reason: VerifyReason) {
    if sh.verifying.swap(true, Ordering::SeqCst) {
        return;
    }
    sh.publish();
    let cfg = sh.config.lock().unwrap().clone();
    let db = sh.providers.lock().unwrap().clone();

    let target = target_of(&cfg);
    if let Ok((name, ip)) = &target {
        let mut g = sh.inner.lock().unwrap();
        g.status.target_name = name.clone();
        g.status.expected_ip = ip.clone();
    }

    let (cfg2, db2) = (cfg.clone(), db.clone());
    let matchers = tokio::task::spawn_blocking(move || build_matchers(&cfg2, &db2)).await.unwrap_or_default();
    {
        let mut g = sh.inner.lock().unwrap();
        let prev: HashMap<String, Vec<String>> = g.status.apps.iter().map(|a| (a.id.clone(), a.running.clone())).collect();
        g.status.apps = matchers
            .iter()
            .map(|m| WatchedApp {
                id: m.id.clone(),
                name: m.name.clone(),
                running: prev.get(&m.id).cloned().unwrap_or_default(),
                process_names: m.names.len(),
                roots: m.roots.clone(),
            })
            .collect();
        g.matchers = Arc::new(matchers);
    }

    let env = tokio::task::spawn_blocking(crate::env_check::run).await.ok();
    let problems: Vec<String> = env
        .as_ref()
        .map(|e| e.checks.iter().filter(|c| c.status == "fail").map(|c| format!("{}：{}", c.name, c.detail)).collect())
        .unwrap_or_default();
    let new_problems: Vec<String> = {
        let mut g = sh.inner.lock().unwrap();
        let fresh = problems.iter().filter(|p| !g.status.env_problems.contains(p)).cloned().collect();
        g.status.env_problems = problems.clone();
        fresh
    };
    for p in &new_problems {
        sh.push_system("leak", format!("环境异常：{p}"));
        sh.notify(&format!("env|{p}"), "NetDect：环境异常", p);
    }

    if sh.inner.lock().unwrap().engine.is_none() {
        connect_engine(&sh).await;
    }

    let outcome: Result<(bool, String), String> = async {
        let (_, expected) = target.clone()?;
        let env = env.ok_or("环境检查失败")?;
        let route = checker::resolve_route(&cfg.probe.mode, &env)?;
        let (hosts, prev_nodes) = {
            let g = sh.inner.lock().unwrap();
            (verify_hosts(&cfg, &db, &g.report_hosts), g.nodes.clone())
        };
        let engine = sh.inner.lock().unwrap().engine.clone();
        let mut set = tokio::task::JoinSet::new();
        for h in hosts {
            let (route, engine) = (route.clone(), engine.clone());
            set.spawn(async move {
                let o = checker::probe_endpoint(&route, &h, engine.as_ref(), Duration::from_secs(8)).await;
                (h, o)
            });
        }
        let mut reached = Vec::new();
        let mut off_target = Vec::new();
        let mut drift = Vec::new();
        while let Some(Ok((h, o))) = set.join_next().await {
            let Some(t) = o.trace else { continue };
            let node = o.conn.as_ref().map(|c| c.node()).unwrap_or_default();
            if !node.is_empty() && !checker::is_direct_or_reject(&node) {
                if let Some(prev) = prev_nodes.get(&node) {
                    if prev.ip == expected && t.ip != expected {
                        drift.push(format!("节点 {node} 的出口从 {} 变成了 {}（{}）", prev.ip, t.ip, t.loc));
                    }
                }
                sh.inner.lock().unwrap().nodes.insert(
                    node.clone(),
                    NodeInfo { node: node.clone(), ip: t.ip.clone(), good: false, checked_at: now_secs(), via: format!("复核 {h}") },
                );
            }
            if t.ip == expected {
                reached.push(h);
            } else {
                let via = if node.is_empty() { String::new() } else { format!("经 {node} ") };
                off_target.push(format!("{h} {via}出口 {}（{}）", t.ip, t.loc));
            }
        }
        off_target.sort();
        let changed = {
            let mut g = sh.inner.lock().unwrap();
            let changed = g.off_target != off_target;
            g.off_target = off_target.clone();
            changed
        };
        if changed && !off_target.is_empty() && !reached.is_empty() {
            sh.push_system(
                "unverified",
                format!("规则覆盖提醒：{}。应用访问这些域名时不会走目标出口", off_target.join("；")),
            );
        }
        if !drift.is_empty() {
            return Ok((false, drift.join("；")));
        }
        if reached.is_empty() {
            if off_target.is_empty() {
                return Err("所选应用的域名都拿不到出口 IP，可以先运行一次「检测」，守护会改用检测中实测通过的域名".into());
            }
            return Ok((false, format!("没有一个复核域名从目标出口出去：{}", off_target.join("；"))));
        }
        Ok((true, format!("{} 出口为 {expected}", reached.join("、"))))
    }
    .await;

    let prev_ok = sh.inner.lock().unwrap().status.verify_ok;
    let (ok, note) = match &outcome {
        Ok((ok, note)) => (Some(*ok), note.clone()),
        Err(e) => (None, e.clone()),
    };
    {
        let mut g = sh.inner.lock().unwrap();
        g.status.last_verify = Some(now_secs());
        g.status.verify_ok = ok;
        g.status.verify_note = note.clone();
    }
    match (ok, &reason) {
        (Some(false), _) => {
            sh.push_system("leak", format!("出口复核失败：{note}"));
            sh.notify("verify", "NetDect：出口复核失败", &note);
        }
        (Some(true), VerifyReason::AppStart(app)) => {
            sh.push_system("ok", format!("{app} 启动后复核通过：{note}"));
            sh.notify(&format!("appstart|{app}|{}", now_secs()), &format!("NetDect：{app} 出口正常"), &note);
        }
        (Some(true), _) if prev_ok == Some(false) => {
            sh.push_system("ok", format!("出口已恢复正常：{note}"));
            sh.notify("verify-ok", "NetDect：出口已恢复", &note);
        }
        (Some(true), VerifyReason::Start | VerifyReason::Manual) => sh.push_system("ok", format!("出口复核通过：{note}")),
        (None, _) => sh.push_system("unverified", format!("出口复核没有结论：{note}")),
        _ => {}
    }
    sh.verifying.store(false, Ordering::SeqCst);
    sh.publish();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(process: &str, path: &str, host: &str, ip: &str) -> Conn {
        Conn {
            id: "1".into(),
            process: process.into(),
            process_path: path.into(),
            host: host.into(),
            dst_ip: ip.into(),
            ..Default::default()
        }
    }

    fn native(p: &str) -> String {
        p.replace('/', std::path::MAIN_SEPARATOR_STR)
    }

    fn matcher() -> AppMatcher {
        AppMatcher {
            id: "anthropic".into(),
            name: "Anthropic".into(),
            names: ["claude.exe".to_string()].into_iter().collect(),
            roots: vec![with_sep(&native("/Apps/Claude_1"))],
            domains: ["cdn.growthbook.io".to_string()].into_iter().collect(),
            suffixes: vec!["claude.ai".into()],
            keywords: vec!["anthropic".into()],
            cidrs: vec!["160.79.104.0/21".parse().unwrap()],
        }
    }

    #[test]
    fn matching() {
        let m = matcher();
        assert_eq!(m.matches(&conn("Claude.exe", "", "", "")), Some("process"));
        assert_eq!(m.matches(&conn("x.exe", &native("/Apps/Claude_1/app/x.exe"), "", "")), Some("process"));
        assert_eq!(m.matches(&conn("x.exe", &native("/Apps/Claude_10/x.exe"), "", "")), None);
        assert_eq!(m.matches(&conn("chrome.exe", "", "api.claude.ai", "")), Some("domain"));
        assert_eq!(m.matches(&conn("chrome.exe", "", "notclaude.ai", "")), None);
        assert_eq!(m.matches(&conn("chrome.exe", "", "x.anthropic.dev", "")), Some("domain"));
        assert_eq!(m.matches(&conn("chrome.exe", "", "", "160.79.105.1")), Some("ip"));
    }

    #[test]
    fn local_and_judge() {
        assert!(is_local(&conn("", "", "", "192.168.1.2")));
        assert!(is_local(&conn("", "", "", "198.18.0.5")));
        assert!(!is_local(&conn("", "", "claude.ai", "")));
        let mut nodes = HashMap::new();
        nodes.insert("jp".to_string(), NodeInfo { node: "jp".into(), ip: "1.1.1.1".into(), ..Default::default() });
        nodes.insert("hk".to_string(), NodeInfo { node: "hk".into(), ip: "2.2.2.2".into(), ..Default::default() });
        assert_eq!(judge("jp", "", &nodes, "1.1.1.1").0, "ok");
        assert_eq!(judge("hk", "", &nodes, "1.1.1.1").0, "leak");
        assert_eq!(judge("DIRECT", "", &nodes, "1.1.1.1").0, "leak");
        assert_eq!(judge("REJECT-DROP", "", &nodes, "1.1.1.1").0, "blocked");
        assert_eq!(judge("sg", "", &nodes, "1.1.1.1").0, "unverified");
    }
}
