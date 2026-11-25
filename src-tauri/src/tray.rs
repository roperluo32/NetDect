use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

use crate::guard::GuardStatus;

pub const TRAY_ID: &str = "netdect";

pub struct TrayHandles {
    pub toggle: MenuItem<Wry>,
    pub verify: MenuItem<Wry>,
    pub tray: TrayIcon<Wry>,
    pub last_state: Mutex<String>,
}

fn color(state: &str) -> [u8; 3] {
    match state {
        "ok" => [22, 163, 74],
        "warn" | "starting" => [217, 119, 6],
        "alert" | "error" => [220, 38, 38],
        _ => [138, 147, 163],
    }
}

/// 32×32 status dot: colored disc with a white ring, anti-aliased.
pub fn status_icon(state: &str) -> Image<'static> {
    const S: usize = 32;
    let [r, g, b] = color(state);
    let mut px = vec![0u8; S * S * 4];
    let c = S as f32 / 2.0;
    for y in 0..S {
        for x in 0..S {
            let d = ((x as f32 + 0.5 - c).powi(2) + (y as f32 + 0.5 - c).powi(2)).sqrt();
            let outer = (15.0 - d).clamp(0.0, 1.0);
            if outer <= 0.0 {
                continue;
            }
            let inner = (12.5 - d).clamp(0.0, 1.0);
            let i = (y * S + x) * 4;
            let mix = |col: u8| (col as f32 * inner + 255.0 * (1.0 - inner)) as u8;
            px[i] = mix(r);
            px[i + 1] = mix(g);
            px[i + 2] = mix(b);
            px[i + 3] = (outer * 255.0) as u8;
        }
    }
    Image::new_owned(px, S as u32, S as u32)
}

pub fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn build(app: &AppHandle) -> tauri::Result<TrayHandles> {
    let show = MenuItem::with_id(app, "show", "显示 NetDect", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "开启守护", true, None::<&str>)?;
    let verify = MenuItem::with_id(app, "verify", "立即复核出口", false, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &verify, &sep, &quit])?;

    let tray = TrayIconBuilder::with_id(TRAY_ID)
        .icon(status_icon("off"))
        .tooltip("NetDect · 守护未开启")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "show" => show_main(app),
            "toggle" => crate::toggle_guard(app),
            "verify" => crate::guard_of(app).verify_now(),
            "quit" => {
                crate::guard_of(app).stop();
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;

    Ok(TrayHandles { toggle, verify, tray, last_state: Mutex::new("off".into()) })
}

pub fn update(h: &TrayHandles, s: &GuardStatus) {
    let _ = h.toggle.set_text(if s.running { "暂停守护" } else { "开启守护" });
    let _ = h.verify.set_enabled(s.running);
    let tip = if s.running {
        format!("NetDect · {}\n目标 {}（{}）", s.headline, s.target_name, s.expected_ip)
    } else {
        "NetDect · 守护未开启".to_string()
    };
    let _ = h.tray.set_tooltip(Some(tip));
    let mut last = h.last_state.lock().unwrap();
    if *last != s.state {
        let _ = h.tray.set_icon(Some(status_icon(&s.state)));
        *last = s.state.clone();
    }
}
