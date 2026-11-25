import { useMemo, useState } from "react";
import { formatTime } from "../api";
import type { GuardEvent, GuardLevel, GuardStatus } from "../types";

interface Props {
  status: GuardStatus;
  events: GuardEvent[];
  busy: boolean;
  onStart: () => void;
  onStop: () => void;
  onVerify: () => void;
  onClear: () => void;
}

const STATE_CLASS: Record<GuardStatus["state"], string> = {
  off: "idle",
  starting: "idle",
  ok: "pass",
  warn: "warn",
  alert: "fail",
  error: "fail",
};
const STATE_ICON: Record<GuardStatus["state"], string> = {
  off: "⏸️",
  starting: "⏳",
  ok: "🛡️",
  warn: "⚠️",
  alert: "🚨",
  error: "❌",
};
const LEVEL: Record<GuardLevel, { text: string; dot: string }> = {
  ok: { text: "正常", dot: "pass" },
  leak: { text: "泄漏", dot: "fail" },
  unverified: { text: "待确认", dot: "warn" },
  blocked: { text: "已拦截", dot: "skip" },
  system: { text: "系统", dot: "info" },
};
const MATCHED: Record<string, string> = { process: "进程", domain: "域名", ip: "IP 段" };

function clock(secs: number) {
  return new Date(secs * 1000).toLocaleTimeString("zh-CN", { hour12: false });
}

export default function GuardPanel({ status, events, busy, onStart, onStop, onVerify, onClear }: Props) {
  const [onlyIssues, setOnlyIssues] = useState(true);
  const rows = useMemo(() => {
    const list = onlyIssues ? events.filter((e) => !e.app || (e.level !== "ok" && e.level !== "blocked")) : events;
    return [...list].sort((a, b) => b.seq - a.seq);
  }, [events, onlyIssues]);
  const s = status;

  return (
    <div className="panel">
      <div className="panel-head">
        实时守护
        <span className="spacer" />
        {s.running ? (
          <>
            <button className="btn small" disabled={s.verifying} onClick={onVerify}>
              {s.verifying ? "复核中…" : "立即复核"}
            </button>
            <button className="btn small danger" onClick={onStop}>
              暂停守护
            </button>
          </>
        ) : (
          <button className="btn small primary" disabled={busy} onClick={onStart}>
            开启守护
          </button>
        )}
      </div>
      <div className="panel-body">
        <div className={`summary ${STATE_CLASS[s.state]}`}>
          <div className="icon">{STATE_ICON[s.state]}</div>
          <div>
            <div className="headline">{s.headline}</div>
            <div className="sub">
              {s.running ? (
                <>
                  目标 {s.target_name} · <span className="mono">{s.expected_ip}</span> · 开启于 {formatTime(s.started_at)}
                </>
              ) : (
                "开启后持续读取代理软件的实时连接：所选应用的任何连接没走目标出口都会立即告警，并定时复核目标出口本身。"
              )}
            </div>
          </div>
        </div>

        {s.running && (
          <>
            <div className="chips" style={{ marginBottom: 10 }}>
              <span className="badge measured">正常 {s.counts.ok}</span>
              <span className="badge" style={{ background: "var(--fail-soft)", color: "var(--fail)" }}>
                泄漏 {s.counts.leak}
              </span>
              <span className="badge sampled">待确认 {s.counts.unverified}</span>
              <span className="badge">已拦截 {s.counts.blocked}</span>
              <span className="badge attributed">当前连接 {s.active}</span>
            </div>
            <div className="kv">
              <span className="k">代理软件 API</span>
              <span className="v">{s.engine ?? <span className="err-text">{s.engine_error ?? "连接中…"}</span>}</span>
              <span className="k">出口复核</span>
              <span className="v">
                {s.last_verify ? (
                  <>
                    {formatTime(s.last_verify)} ·{" "}
                    <span className={s.verify_ok === false ? "err-text" : s.verify_ok ? "ok-text" : ""}>{s.verify_note}</span>
                  </>
                ) : (
                  "进行中…"
                )}
              </span>
              <span className="k">节点出口</span>
              <span className="v">
                {s.nodes.length === 0
                  ? "尚未实测"
                  : s.nodes.map((n) => (
                      <div key={n.node}>
                        <span className={`dot ${n.good ? "pass" : "fail"}`} /> {n.node} ={" "}
                        <span className="mono">{n.ip}</span> <span className="note">（{n.via}）</span>
                      </div>
                    ))}
              </span>
              <span className="k">监视的应用</span>
              <span className="v">
                {s.apps.map((a) => (
                  <div key={a.id}>
                    {a.name}：
                    {a.running.length > 0 ? <span className="ok-text">运行中（{a.running.join("、")}）</span> : <span className="note">未运行</span>}
                    <span className="note"> · {a.process_names} 个进程名</span>
                  </div>
                ))}
              </span>
              {s.env_problems.length > 0 && (
                <>
                  <span className="k">环境异常</span>
                  <span className="v err-text">{s.env_problems.join("；")}</span>
                </>
              )}
            </div>
          </>
        )}

        <div className="section">
          <div className="section-head">
            <span className="title">连接记录</span>
            <span className="counts">{events.length} 条</span>
            <span className="spacer" />
            <label style={{ display: "flex", gap: 4, alignItems: "center" }} onClick={(e) => e.stopPropagation()}>
              <input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} />
              只看异常和系统消息
            </label>
            <button className="btn small" onClick={onClear} disabled={events.length === 0}>
              清空
            </button>
          </div>
          <div className="section-body">
            {rows.length === 0 ? (
              <div className="empty">{s.running ? "暂无记录" : "守护未开启"}</div>
            ) : (
              <table>
                <thead>
                  <tr>
                    <th style={{ width: 72 }}>时间</th>
                    <th style={{ width: 70 }}>状态</th>
                    <th style={{ width: 150 }}>应用 / 进程</th>
                    <th>目标</th>
                    <th>规则 → 节点</th>
                    <th>说明</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((e) =>
                    e.app ? (
                      <tr key={e.seq} className={e.level === "leak" ? "fail" : ""}>
                        <td className="mono nowrap">{clock(e.time)}</td>
                        <td>
                          <span className={`dot ${LEVEL[e.level].dot}`} /> {LEVEL[e.level].text}
                        </td>
                        <td>
                          {e.app_name}
                          <div className="note">
                            {e.process || "未知进程"}
                            {e.matched_by && ` · 按${MATCHED[e.matched_by]}`}
                          </div>
                        </td>
                        <td className="mono">
                          {e.host || e.dst}
                          {e.host && e.dst && !e.dst.startsWith(":") && <div className="note">{e.dst}</div>}
                        </td>
                        <td>
                          {e.rule}
                          {e.chain.length > 0 && <div className="note">→ {e.chain.join(" → ")}</div>}
                        </td>
                        <td className="note">{e.note}</td>
                      </tr>
                    ) : (
                      <tr key={e.seq} className={e.level === "leak" ? "fail" : ""}>
                        <td className="mono nowrap">{clock(e.time)}</td>
                        <td>
                          <span className={`dot ${LEVEL[e.level].dot}`} /> {e.level === "system" ? "系统" : LEVEL[e.level].text}
                        </td>
                        <td colSpan={4}>{e.note}</td>
                      </tr>
                    ),
                  )}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
