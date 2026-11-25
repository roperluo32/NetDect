export type Status = "pass" | "fail" | "warn" | "skip" | "info" | "pending";

export interface ExitView {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  pinned_ip: string | null;
  last_ip: string | null;
  last_country: string | null;
  last_org: string | null;
  last_checked: number | null;
  last_error: string | null;
  has_password: boolean;
}

export interface EngineCfg {
  kind: "auto" | "http" | "pipe" | "unix" | "none";
  address: string;
  secret: string;
}

export interface ProbeCfg {
  mode: "auto" | "tun" | "system" | "env";
  concurrency: number;
  timeout_secs: number;
}

export interface GuardCfg {
  start_on_launch: boolean;
  autostart: boolean;
  poll_ms: number;
  verify_minutes: number;
  notify: boolean;
  verify_on_app_start: boolean;
  close_to_tray: boolean;
}

export type GuardLevel = "ok" | "leak" | "unverified" | "blocked" | "system";

export interface GuardEvent {
  seq: number;
  time: number;
  level: GuardLevel;
  app: string;
  app_name: string;
  process: string;
  host: string;
  dst: string;
  network: string;
  matched_by: "process" | "domain" | "ip" | "";
  rule: string;
  chain: string[];
  node: string;
  note: string;
}

export interface GuardStatus {
  running: boolean;
  state: "off" | "starting" | "ok" | "warn" | "alert" | "error";
  headline: string;
  started_at: number | null;
  target_name: string;
  expected_ip: string;
  engine: string | null;
  engine_error: string | null;
  last_verify: number | null;
  verify_ok: boolean | null;
  verify_note: string;
  verifying: boolean;
  nodes: { node: string; ip: string; good: boolean; checked_at: number; via: string }[];
  apps: { id: string; name: string; running: string[]; process_names: number; roots: string[] }[];
  counts: { ok: number; leak: number; unverified: number; blocked: number };
  active: number;
  env_problems: string[];
}

export interface GuardSnapshot {
  status: GuardStatus;
  events: GuardEvent[];
}

export interface ProviderView {
  id: string;
  name: string;
  description: string;
  scope: string;
  categories: string[];
  aliases: string[];
  rule_count: number;
}

export interface StateView {
  exits: ExitView[];
  target_exit: string | null;
  selected_apps: string[];
  engine: EngineCfg;
  probe: ProbeCfg;
  guard: GuardCfg;
  providers: ProviderView[];
  providers_source: string;
  providers_updated_at: number;
  platform: string;
  config_path: string;
}

export interface CheckItem {
  name: string;
  status: Status;
  detail: string;
}

export interface ItemResult {
  id: number;
  app: string;
  kind: "domain" | "suffix" | "keyword" | "process" | "cidr" | "cidr6" | "asn";
  target: string;
  probe: string;
  source: "rules" | "local" | "both";
  status: Status;
  method: "measured" | "attributed" | "sampled" | "none";
  observed_ip: string | null;
  observed_loc: string | null;
  rule: string | null;
  chain: string[];
  node: string | null;
  note: string;
}

export interface AppReport {
  id: string;
  name: string;
  status: Status;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  discovered_roots: string[];
  items: ItemResult[];
}

export interface Report {
  started_at: number;
  finished_at: number;
  status: Status;
  summary: string;
  cancelled: boolean;
  target_id: string;
  target_name: string;
  expected_ip: string;
  expected_source: "pinned" | "resolved";
  route: string;
  engine: string | null;
  engine_error: string | null;
  echo_url: string | null;
  baseline_ip: string | null;
  env: CheckItem[];
  apps: AppReport[];
}

export interface Progress {
  stage: string;
  done: number;
  total: number;
  item: ItemResult | null;
}

export interface ExitInput {
  id?: string;
  name: string;
  host: string;
  port: number;
  username: string;
  password?: string;
  pinned_ip?: string;
}
