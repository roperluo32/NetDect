pub mod checker;
pub mod config;
pub mod discovery;
pub mod engine;
pub mod env_check;
pub mod exits;
pub mod guard;
pub mod net;
pub mod probe;
pub mod providers;
pub mod report;
mod tray;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_autostart::{MacosLauncher, ManagerExt};
use tauri_plugin_notification::NotificationExt;

use config::{AppConfig, EngineCfg, ExitCfg, GuardCfg, ProbeCfg};
use guard::{Guard, GuardEvent, GuardHooks, GuardSnapshot, GuardStatus};
use providers::ProviderDb;

const AUTOSTART_FLAG: &str = "--autostart";

struct AppState {
    config_path: PathBuf,
    providers_cache: PathBuf,
    config: Arc<Mutex<AppConfig>>,
    providers: Arc<Mutex<ProviderDb>>,
    cancel: Arc<AtomicBool>,
    running: AtomicBool,
    last_report: Mutex<Option<checker::Report>>,
}

impl AppState {
    fn save(&self, cfg: &AppConfig) -> Result<(), String> {
        cfg.save(&self.config_path)
    }
}

#[derive(Serialize)]
struct ExitView {
    #[serde(flatten)]
    exit: ExitCfg,
    has_password: bool,
}

#[derive(Serialize)]
struct ProviderView {
    id: String,
    name: String,
    description: String,
    scope: String,
    categories: Vec<String>,
    aliases: Vec<String>,
    rule_count: usize,
}

#[derive(Serialize)]
struct StateView {
    exits: Vec<ExitView>,
    target_exit: Option<String>,
    selected_apps: Vec<String>,
    engine: EngineCfg,
    probe: ProbeCfg,
    guard: GuardCfg,
    providers: Vec<ProviderView>,
    providers_source: String,
    providers_updated_at: u64,
    platform: String,
    config_path: String,
}

fn view(state: &AppState) -> StateView {
    let cfg = state.config.lock().unwrap().clone();
    let db = state.providers.lock().unwrap();
    StateView {
        exits: cfg
            .exits
            .iter()
            .map(|e| ExitView { exit: e.clone(), has_password: config::get_password(&e.id).is_some() })
            .collect(),
        target_exit: cfg.target_exit.clone(),
        selected_apps: cfg.selected_apps.clone(),
        engine: cfg.engine.clone(),
        probe: cfg.probe.clone(),
        guard: cfg.guard.clone(),
        providers: db
            .providers
            .iter()
            .map(|p| ProviderView {
                id: p.provider.clone(),
                name: p.name.clone(),
                description: p.description.clone(),
                scope: if p.scope.is_empty() { "global".into() } else { p.scope.clone() },
                categories: p.categories.clone(),
                aliases: p.aliases.clone(),
                rule_count: p.rule_count(),
            })
            .collect(),
        providers_source: db.source.clone(),
        providers_updated_at: db.updated_at,
        platform: std::env::consts::OS.into(),
        config_path: state.config_path.to_string_lossy().into(),
    }
}

#[tauri::command]
fn get_state(state: State<'_, AppState>) -> StateView {
    view(&state)
}

#[derive(Deserialize)]
struct ExitInput {
    id: Option<String>,
    name: String,
    host: String,
    port: u16,
    username: String,
    /// Empty when editing means "keep the stored password".
    password: Option<String>,
    pinned_ip: Option<String>,
}

#[tauri::command]
fn save_exit(state: State<'_, AppState>, guard: State<'_, Guard>, input: ExitInput) -> Result<StateView, String> {
    let name = input.name.trim();
    if name.is_empty() {
        return Err("请填写名称".into());
    }
    if input.host.trim().is_empty() || input.port == 0 {
        return Err("请填写主机和端口".into());
    }
    let pinned = input.pinned_ip.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    if let Some(ip) = &pinned {
        ip.parse::<std::net::IpAddr>().map_err(|_| format!("固定 IP 格式不正确：{ip}"))?;
    }
    {
        let mut cfg = state.config.lock().unwrap();
        let id = match input.id.as_ref().filter(|s| !s.is_empty()) {
            Some(id) => {
                let e = cfg.exit_mut(id).ok_or("出口不存在")?;
                let endpoint_changed = e.host != input.host.trim() || e.port != input.port || e.username != input.username;
                e.name = name.into();
                e.host = input.host.trim().into();
                e.port = input.port;
                e.username = input.username.clone();
                e.pinned_ip = pinned;
                if endpoint_changed {
                    e.last_ip = None;
                    e.last_country = None;
                    e.last_org = None;
                }
                id.clone()
            }
            None => {
                let id = cfg.unique_id(name);
                cfg.exits.push(ExitCfg {
                    id: id.clone(),
                    name: name.into(),
                    host: input.host.trim().into(),
                    port: input.port,
                    username: input.username.clone(),
                    pinned_ip: pinned,
                    ..Default::default()
                });
                if cfg.target_exit.is_none() {
                    cfg.target_exit = Some(id.clone());
                }
                id
            }
        };
        if let Some(pw) = input.password.filter(|p| !p.is_empty()) {
            config::set_password(&id, &pw)?;
        }
        state.save(&cfg)?;
    }
    guard.reconfigure();
    Ok(view(&state))
}

#[tauri::command]
fn delete_exit(state: State<'_, AppState>, id: String) -> Result<StateView, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.exits.retain(|e| e.id != id);
        if cfg.target_exit.as_deref() == Some(id.as_str()) {
            cfg.target_exit = cfg.exits.first().map(|e| e.id.clone());
        }
        state.save(&cfg)?;
    }
    config::delete_password(&id);
    Ok(view(&state))
}

#[tauri::command]
fn parse_exit_string(s: String) -> Result<(String, u16, String, String), String> {
    config::parse_exit_string(&s)
}

#[tauri::command]
async fn refresh_exit_ip(state: State<'_, AppState>, guard: State<'_, Guard>, id: String) -> Result<StateView, String> {
    let exit = state.config.lock().unwrap().exit(&id).cloned().ok_or("出口不存在")?;
    let password = config::get_password(&id).unwrap_or_default();
    let result = exits::resolve(&exit.host, exit.port, &exit.username, &password).await;
    {
        let mut cfg = state.config.lock().unwrap();
        if let Some(e) = cfg.exit_mut(&id) {
            e.last_checked = Some(config::now_secs());
            match &result {
                Ok(info) => {
                    e.last_ip = Some(info.ip.clone());
                    e.last_country = info.country.clone();
                    e.last_org = info.org.clone();
                    e.last_error = None;
                }
                Err(err) => e.last_error = Some(err.clone()),
            }
        }
        state.save(&cfg)?;
    }
    guard.reconfigure();
    result.map(|_| view(&state))
}

#[tauri::command]
fn set_target_exit(state: State<'_, AppState>, guard: State<'_, Guard>, id: String) -> Result<StateView, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        if cfg.exit(&id).is_none() {
            return Err("出口不存在".into());
        }
        cfg.target_exit = Some(id);
        state.save(&cfg)?;
    }
    guard.reconfigure();
    Ok(view(&state))
}

#[tauri::command]
fn set_selected_apps(state: State<'_, AppState>, guard: State<'_, Guard>, ids: Vec<String>) -> Result<StateView, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.selected_apps = ids;
        state.save(&cfg)?;
    }
    guard.reconfigure();
    Ok(view(&state))
}

#[tauri::command]
fn save_settings(state: State<'_, AppState>, guard: State<'_, Guard>, engine: EngineCfg, probe: ProbeCfg) -> Result<StateView, String> {
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.engine = engine;
        cfg.probe = probe;
        state.save(&cfg)?;
    }
    guard.reconfigure();
    Ok(view(&state))
}

#[tauri::command]
async fn test_engine(engine: EngineCfg) -> Result<String, String> {
    let e = engine::connect(&engine).await?;
    let n = e.connections().await.map(|c| c.len()).unwrap_or(0);
    Ok(format!("{} · 版本 {} · 当前 {n} 条连接", e.transport.describe(), e.version))
}

#[tauri::command]
async fn update_providers(state: State<'_, AppState>) -> Result<StateView, String> {
    let db = providers::fetch_latest().await?;
    if let Some(dir) = state.providers_cache.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&state.providers_cache, serde_json::to_string(&db).map_err(|e| e.to_string())?)
        .map_err(|e| format!("写入缓存失败: {e}"))?;
    *state.providers.lock().unwrap() = db;
    Ok(view(&state))
}

#[tauri::command]
async fn run_check(app: tauri::AppHandle, state: State<'_, AppState>, guard: State<'_, Guard>) -> Result<checker::Report, String> {
    if state.running.swap(true, Ordering::SeqCst) {
        return Err("检测正在进行".into());
    }
    state.cancel.store(false, Ordering::SeqCst);
    let cfg = state.config.lock().unwrap().clone();
    let db = state.providers.lock().unwrap().clone();
    let emitter = app.clone();
    let progress: checker::ProgressFn = Arc::new(move |p| {
        let _ = emitter.emit("check-progress", p);
    });
    let result = checker::run(cfg, db, state.cancel.clone(), progress).await;
    state.running.store(false, Ordering::SeqCst);
    if let Ok(r) = &result {
        *state.last_report.lock().unwrap() = Some(r.clone());
        guard.learn_from_report(r);
    }
    result
}

#[tauri::command]
fn cancel_check(state: State<'_, AppState>) {
    state.cancel.store(true, Ordering::SeqCst);
}

#[tauri::command]
fn export_report(state: State<'_, AppState>, path: String) -> Result<(), String> {
    let report = state.last_report.lock().unwrap().clone().ok_or("还没有检测报告")?;
    let content = if path.to_lowercase().ends_with(".json") {
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    } else {
        report::to_markdown(&report)
    };
    std::fs::write(&path, content).map_err(|e| format!("保存失败: {e}"))
}

struct TauriHooks {
    app: AppHandle,
}

impl GuardHooks for TauriHooks {
    fn status(&self, status: &GuardStatus) {
        let _ = self.app.emit("guard-status", status);
        if let Some(t) = self.app.try_state::<tray::TrayHandles>() {
            tray::update(&t, status);
        }
    }

    fn event(&self, event: &GuardEvent) {
        let _ = self.app.emit("guard-event", event);
    }

    fn notify(&self, title: &str, body: &str) {
        let _ = self.app.notification().builder().title(title).body(body).show();
    }
}

pub(crate) fn guard_of(app: &AppHandle) -> Guard {
    app.state::<Guard>().inner().clone()
}

pub(crate) fn toggle_guard(app: &AppHandle) {
    let g = guard_of(app);
    if g.is_running() {
        g.stop();
    } else if let Err(e) = g.start() {
        let _ = app.notification().builder().title("NetDect：无法开启守护").body(&e).show();
        tray::show_main(app);
    }
}

#[tauri::command]
fn guard_get(guard: State<'_, Guard>) -> GuardSnapshot {
    guard.snapshot()
}

#[tauri::command]
fn guard_start(guard: State<'_, Guard>) -> Result<GuardStatus, String> {
    guard.start()
}

#[tauri::command]
fn guard_stop(guard: State<'_, Guard>) -> GuardStatus {
    guard.stop()
}

#[tauri::command]
fn guard_verify(guard: State<'_, Guard>) {
    guard.verify_now();
}

#[tauri::command]
fn guard_clear(guard: State<'_, Guard>) {
    guard.clear();
}

#[tauri::command]
fn save_guard_settings(app: AppHandle, state: State<'_, AppState>, settings: GuardCfg) -> Result<StateView, String> {
    let autolaunch = app.autolaunch();
    let enabled = autolaunch.is_enabled().unwrap_or(false);
    if settings.autostart != enabled {
        let r = if settings.autostart { autolaunch.enable() } else { autolaunch.disable() };
        r.map_err(|e| format!("设置开机自启失败：{e}"))?;
    }
    {
        let mut cfg = state.config.lock().unwrap();
        cfg.guard = settings;
        state.save(&cfg)?;
    }
    Ok(view(&state))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| tray::show_main(app)))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec![AUTOSTART_FLAG])))
        .setup(|app| {
            let cfg_dir = app.path().app_config_dir()?;
            let data_dir = app.path().app_data_dir()?;
            let config_path = config::config_file(&cfg_dir);
            let providers_cache = data_dir.join("providers.json");
            let cfg = Arc::new(Mutex::new(AppConfig::load(&config_path)));
            let db = Arc::new(Mutex::new(providers::load(&providers_cache)));
            let guard = Guard::new(cfg.clone(), db.clone(), Arc::new(TauriHooks { app: app.handle().clone() }));
            app.manage(AppState {
                config_path,
                providers_cache,
                config: cfg.clone(),
                providers: db,
                cancel: Arc::new(AtomicBool::new(false)),
                running: AtomicBool::new(false),
                last_report: Mutex::new(None),
            });
            app.manage(guard.clone());
            let handles = tray::build(app.handle())?;
            app.manage(handles);

            let autostarted = std::env::args().any(|a| a == AUTOSTART_FLAG);
            let gcfg = cfg.lock().unwrap().guard.clone();
            if !autostarted {
                tray::show_main(app.handle());
            }
            if gcfg.start_on_launch || (autostarted && gcfg.autostart) {
                if let Err(e) = guard.start() {
                    let _ = app.notification().builder().title("NetDect：无法开启守护").body(&e).show();
                    tray::show_main(app.handle());
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let app = window.app_handle();
                let to_tray = app.state::<AppState>().config.lock().unwrap().guard.close_to_tray;
                if to_tray && guard_of(app).is_running() {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_state,
            save_exit,
            delete_exit,
            parse_exit_string,
            refresh_exit_ip,
            set_target_exit,
            set_selected_apps,
            save_settings,
            test_engine,
            update_providers,
            run_check,
            cancel_check,
            export_report,
            guard_get,
            guard_start,
            guard_stop,
            guard_verify,
            guard_clear,
            save_guard_settings
        ])
        .run(tauri::generate_context!())
        .expect("error while running NetDect");
}
