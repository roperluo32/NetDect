import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  EngineCfg,
  ExitInput,
  GuardCfg,
  GuardEvent,
  GuardSnapshot,
  GuardStatus,
  ProbeCfg,
  Progress,
  Report,
  StateView,
} from "./types";

export const api = {
  getState: () => invoke<StateView>("get_state"),
  saveExit: (input: ExitInput) => invoke<StateView>("save_exit", { input }),
  deleteExit: (id: string) => invoke<StateView>("delete_exit", { id }),
  refreshExitIp: (id: string) => invoke<StateView>("refresh_exit_ip", { id }),
  setTargetExit: (id: string) => invoke<StateView>("set_target_exit", { id }),
  setSelectedApps: (ids: string[]) => invoke<StateView>("set_selected_apps", { ids }),
  saveSettings: (engine: EngineCfg, probe: ProbeCfg) => invoke<StateView>("save_settings", { engine, probe }),
  testEngine: (engine: EngineCfg) => invoke<string>("test_engine", { engine }),
  updateProviders: () => invoke<StateView>("update_providers"),
  runCheck: () => invoke<Report>("run_check"),
  cancelCheck: () => invoke<void>("cancel_check"),
  exportReport: (path: string) => invoke<void>("export_report", { path }),
  onProgress: (cb: (p: Progress) => void): Promise<UnlistenFn> => listen<Progress>("check-progress", (e) => cb(e.payload)),

  guardGet: () => invoke<GuardSnapshot>("guard_get"),
  guardStart: () => invoke<GuardStatus>("guard_start"),
  guardStop: () => invoke<GuardStatus>("guard_stop"),
  guardVerify: () => invoke<void>("guard_verify"),
  guardClear: () => invoke<void>("guard_clear"),
  saveGuardSettings: (settings: GuardCfg) => invoke<StateView>("save_guard_settings", { settings }),
  onGuardStatus: (cb: (s: GuardStatus) => void): Promise<UnlistenFn> => listen<GuardStatus>("guard-status", (e) => cb(e.payload)),
  onGuardEvent: (cb: (ev: GuardEvent) => void): Promise<UnlistenFn> => listen<GuardEvent>("guard-event", (e) => cb(e.payload)),
};

/** Splits `host:port:user:pass`; only the first three colons separate fields. */
export function parseExitString(s: string): { host: string; port: number; username: string; password: string } | null {
  const parts = s.trim().split(":");
  if (parts.length < 2 || !parts[0]) return null;
  const port = Number(parts[1]);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
  return { host: parts[0], port, username: parts[2] ?? "", password: parts.slice(3).join(":") };
}

export function guardDot(s: GuardStatus): string {
  return { ok: "pass", warn: "warn", starting: "pending", alert: "fail", error: "fail", off: "skip" }[s.state];
}

export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return JSON.stringify(e);
}

export function formatTime(secs: number | null | undefined): string {
  if (!secs) return "";
  return new Date(secs * 1000).toLocaleString("zh-CN", { hour12: false });
}
