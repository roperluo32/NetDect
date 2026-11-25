import { guardDot } from "../api";
import type { GuardStatus, Progress, StateView } from "../types";

interface Props {
  state: StateView;
  running: boolean;
  progress: Progress | null;
  guard: GuardStatus | null;
  onGuard: () => void;
  onTarget: (id: string) => void;
  onRun: () => void;
  onCancel: () => void;
  onSettings: () => void;
}

export default function TopBar({ state, running, progress, guard, onGuard, onTarget, onRun, onCancel, onSettings }: Props) {
  const target = state.exits.find((e) => e.id === state.target_exit);
  const expected = target?.pinned_ip ?? target?.last_ip;
  const reason = !target
    ? "请先添加并选择目标出口"
    : !expected
      ? "目标出口还没有 IP：请点「刷新 IP」或手动固定 IP"
      : state.selected_apps.length === 0
        ? "请至少勾选一个应用"
        : null;
  const pct = progress && progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0;

  return (
    <div className="topbar">
      <span className="brand">NetDect</span>
      <label>目标出口</label>
      <select value={state.target_exit ?? ""} disabled={running} onChange={(e) => onTarget(e.target.value)}>
        {state.exits.length === 0 && <option value="">（未配置）</option>}
        {state.exits.map((e) => (
          <option key={e.id} value={e.id}>
            {e.name}
            {e.pinned_ip ?? e.last_ip ? ` · ${e.pinned_ip ?? e.last_ip}` : " · 无 IP"}
          </option>
        ))}
      </select>
      {running ? (
        <>
          <button className="btn big danger" onClick={onCancel}>
            取消
          </button>
          <div className="progress">
            <div className="progress-text">
              {progress?.stage}
              {progress && progress.total > 0 && ` · ${progress.done}/${progress.total}`}
            </div>
            <div className="bar">
              <div style={{ width: `${pct}%` }} />
            </div>
          </div>
        </>
      ) : (
        <>
          <button className="btn big primary" disabled={!!reason} title={reason ?? ""} onClick={onRun}>
            检测
          </button>
          {reason && <span className="err-text">{reason}</span>}
        </>
      )}
      <span className="spacer" />
      {guard && (
        <button className={`guard-pill ${guard.running ? guardDot(guard) : "skip"}`} onClick={onGuard} title={guard.headline}>
          <span className={`dot ${guard.running ? guardDot(guard) : "skip"}`} />
          {guard.running ? guard.headline : "守护未开启"}
        </button>
      )}
      <button className="btn" onClick={onSettings} disabled={running}>
        设置
      </button>
    </div>
  );
}
