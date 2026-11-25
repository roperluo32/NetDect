use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Discovered {
    pub roots: Vec<String>,
    /// (process name, example path)
    pub processes: Vec<(String, String)>,
}

#[allow(dead_code)] // each platform reads only its own fields
struct Known {
    provider: &'static str,
    win_appx: &'static [&'static str],
    win_dirs: &'static [&'static str],
    mac_apps: &'static [&'static str],
    /// (directory, file name) for CLIs living in shared bin directories.
    win_cli: &'static [(&'static str, &'static str)],
    mac_cli: &'static [(&'static str, &'static str)],
}

const KNOWN: &[Known] = &[
    Known {
        provider: "anthropic",
        win_appx: &["Claude"],
        win_dirs: &["%LOCALAPPDATA%\\AnthropicClaude"],
        mac_apps: &["/Applications/Claude.app", "~/Applications/Claude.app"],
        win_cli: &[("%USERPROFILE%\\.local\\bin", "claude.exe")],
        mac_cli: &[("~/.local/bin", "claude"), ("~/.claude/local", "claude")],
    },
    Known {
        provider: "openai",
        win_appx: &["OpenAI.ChatGPT-Desktop", "OpenAI.Codex"],
        win_dirs: &[],
        mac_apps: &["/Applications/ChatGPT.app", "/Applications/Codex.app"],
        win_cli: &[],
        mac_cli: &[],
    },
    Known {
        provider: "cursor",
        win_appx: &[],
        win_dirs: &["%LOCALAPPDATA%\\Programs\\cursor"],
        mac_apps: &["/Applications/Cursor.app"],
        win_cli: &[],
        mac_cli: &[],
    },
    Known {
        provider: "windsurf",
        win_appx: &[],
        win_dirs: &["%LOCALAPPDATA%\\Programs\\Windsurf"],
        mac_apps: &["/Applications/Windsurf.app"],
        win_cli: &[],
        mac_cli: &[],
    },
];

fn expand(p: &str) -> PathBuf {
    let mut s = p.to_string();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
            s = format!("{home}/{rest}");
        }
    }
    while let Some(start) = s.find('%') {
        let Some(len) = s[start + 1..].find('%') else { break };
        let var = &s[start + 1..start + 1 + len];
        let val = std::env::var(var).unwrap_or_default();
        s.replace_range(start..start + len + 2, &val);
    }
    PathBuf::from(s)
}

#[cfg(windows)]
fn appx_locations(names: &[&str]) -> Vec<PathBuf> {
    if names.is_empty() {
        return Vec::new();
    }
    let list = names.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(",");
    let script = format!("foreach($n in @({list})){{ Get-AppxPackage -Name $n | ForEach-Object {{ $_.InstallLocation }} }}");
    crate::env_check::platform_powershell(&script)
        .unwrap_or_default()
        .lines()
        .map(|l| PathBuf::from(l.trim()))
        .filter(|p| p.is_dir())
        .collect()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(windows)]
    {
        path.extension().map(|e| e.eq_ignore_ascii_case("exe")).unwrap_or(false)
    }
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::fs::PermissionsExt;
        let Ok(meta) = std::fs::metadata(path) else { return false };
        if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
            return false;
        }
        let mut magic = [0u8; 4];
        let Ok(mut f) = std::fs::File::open(path) else { return false };
        if f.read_exact(&mut magic).is_err() {
            return false;
        }
        matches!(
            u32::from_be_bytes(magic),
            0xfeedface | 0xfeedfacf | 0xcefaedfe | 0xcffaedfe | 0xcafebabe | 0x7f454c46
        )
    }
}

fn walk(dir: &Path, depth: usize, out: &mut Vec<(String, String)>) {
    if depth > 7 || out.len() > 300 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let path = e.path();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            let name = e.file_name().to_string_lossy().to_lowercase();
            if name == "node_modules" || name == "locales" || name.ends_with(".lproj") {
                continue;
            }
            walk(&path, depth + 1, out);
        } else if is_executable(&path) {
            out.push((e.file_name().to_string_lossy().to_string(), path.to_string_lossy().to_string()));
        }
    }
}

/// Bundled runtimes and Chromium/Electron helpers share names with unrelated
/// software, so a PROCESS-NAME rule for them would be wrong advice.
fn is_generic(name: &str) -> bool {
    const GENERIC: &[&str] = &[
        "node", "python", "python3", "pythonw", "git", "rg", "bash", "sh", "uv", "bun", "deno", "tectonic",
        "chrome_proxy", "chrome_pwa_launcher", "elevation_service", "elevated_tracing_service",
        "notification_helper", "crashpad_handler", "chrome_crashpad_handler", "squirrel", "update",
        "createdump", "7z", "7za", "esbuild",
    ];
    let lower = name.to_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    GENERIC.contains(&stem) || stem.starts_with("uninstall")
}

fn same_name(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn running_under(roots: &[PathBuf], out: &mut Vec<(String, String)>) {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    if roots.is_empty() {
        return;
    }
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    let lower_roots: Vec<String> = roots.iter().map(|r| r.to_string_lossy().to_lowercase()).collect();
    for p in sys.processes().values() {
        let Some(exe) = p.exe() else { continue };
        let exe_s = exe.to_string_lossy().to_string();
        let lower = exe_s.to_lowercase();
        if lower_roots.iter().any(|r| lower.starts_with(r)) {
            out.push((p.name().to_string_lossy().to_string(), exe_s));
        }
    }
}

/// Finds executables belonging to `provider` installed on this machine.
pub fn discover(provider: &str, extra: &[String]) -> Discovered {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut files: Vec<(String, String)> = Vec::new();

    if let Some(k) = KNOWN.iter().find(|k| k.provider == provider) {
        #[cfg(windows)]
        {
            roots.extend(appx_locations(k.win_appx));
            roots.extend(k.win_dirs.iter().map(|d| expand(d)).filter(|p| p.is_dir()));
            for (dir, file) in k.win_cli {
                let p = expand(dir).join(file);
                if p.is_file() {
                    files.push((file.to_string(), p.to_string_lossy().to_string()));
                }
            }
        }
        #[cfg(target_os = "macos")]
        {
            roots.extend(k.mac_apps.iter().map(|d| expand(d)).filter(|p| p.is_dir()));
            for (dir, file) in k.mac_cli {
                let p = expand(dir).join(file);
                if p.exists() {
                    files.push((file.to_string(), p.to_string_lossy().to_string()));
                }
            }
        }
        let _ = k;
    }
    roots.extend(extra.iter().map(|d| expand(d)).filter(|p| p.is_dir()));
    roots.sort();
    roots.dedup();

    for r in &roots {
        walk(r, 0, &mut files);
    }
    running_under(&roots, &mut files);

    let mut processes: Vec<(String, String)> = Vec::new();
    for (name, path) in files {
        if is_generic(&name) {
            continue;
        }
        if !processes.iter().any(|(n, _)| same_name(n, &name)) {
            processes.push((name, path));
        }
    }
    processes.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));
    Discovered { roots: roots.iter().map(|r| r.to_string_lossy().to_string()).collect(), processes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_vars() {
        std::env::set_var("NETDECT_TEST_VAR", "X");
        assert_eq!(expand("%NETDECT_TEST_VAR%\\a"), PathBuf::from("X\\a"));
    }

    #[test]
    fn generic_names() {
        assert!(is_generic("node.exe"));
        assert!(!is_generic("Claude Helper (Renderer)"));
        assert!(is_generic("Uninstall Claude.exe"));
        assert!(!is_generic("claude.exe"));
        assert!(!is_generic("cowork-svc.exe"));
    }
}
