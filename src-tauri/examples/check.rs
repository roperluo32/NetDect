//! Headless run of the checker: `cargo run --example check -- <expected-ip> [provider ...]`
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use netdect_lib::{checker, config, probe, providers, report};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == probe::PROBE_FLAG {
        std::process::exit(probe::run_probe_child(&args[2]));
    }
    let expected = args.get(1).cloned().expect("usage: check <expected-ip> [provider ...]");
    let apps: Vec<String> = if args.len() > 2 { args[2..].to_vec() } else { vec!["anthropic".into()] };

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
    let rt = tokio::runtime::Runtime::new().unwrap();
    let progress: checker::ProgressFn = Arc::new(|p| {
        if p.item.is_none() {
            eprintln!("[{}/{}] {}", p.done, p.total, p.stage);
        }
    });
    match rt.block_on(checker::run(cfg, db, Arc::new(AtomicBool::new(false)), progress)) {
        Ok(r) => println!("{}", report::to_markdown(&r)),
        Err(e) => eprintln!("error: {e}"),
    }
}
