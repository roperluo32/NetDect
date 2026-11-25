//! Headless guard run: `cargo run --example guard -- <expected-ip> <seconds> [provider ...]`
use std::sync::{Arc, Mutex};
use std::time::Duration;

use netdect_lib::guard::{Guard, GuardEvent, GuardHooks, GuardStatus};
use netdect_lib::{config, probe, providers};

struct Print;

impl GuardHooks for Print {
    fn status(&self, s: &GuardStatus) {
        let nodes: Vec<String> = s.nodes.iter().map(|n| format!("{}={}{}", n.node, n.ip, if n.good { "✓" } else { "✗" })).collect();
        eprintln!("[status] {} · {} · 活动 {} · 节点 [{}]", s.state, s.headline, s.active, nodes.join(", "));
    }
    fn event(&self, e: &GuardEvent) {
        let chain = e.chain.join(" → ");
        println!(
            "[{}] {} {} {} {} | {} → {} | {}",
            e.level, e.app_name, e.process, e.host, e.dst, e.rule, chain, e.note
        );
    }
    fn notify(&self, title: &str, body: &str) {
        println!("[notify] {title} — {body}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == probe::PROBE_FLAG {
        std::process::exit(probe::run_probe_child(&args[2]));
    }
    let expected = args.get(1).cloned().expect("usage: guard <expected-ip> <seconds> [provider ...]");
    let secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(30);
    let apps: Vec<String> = if args.len() > 3 { args[3..].to_vec() } else { vec!["anthropic".into()] };

    let mut cfg = config::AppConfig::default();
    cfg.exits.push(config::ExitCfg {
        id: "target".into(),
        name: "target".into(),
        host: "unused".into(),
        port: 1,
        pinned_ip: Some(expected),
        ..Default::default()
    });
    cfg.target_exit = Some("target".into());
    cfg.selected_apps = apps;

    let db = providers::load(std::path::Path::new("__no_cache__"));
    let guard = Guard::new(Arc::new(Mutex::new(cfg)), Arc::new(Mutex::new(db)), Arc::new(Print));
    if let Err(e) = guard.start() {
        eprintln!("start failed: {e}");
        return;
    }
    std::thread::sleep(Duration::from_secs(secs));
    let s = guard.stop();
    println!("final counts: {:?}", s.counts);
}
