import { useState } from "react";
import { formatTime } from "../api";
import type { ExitView, StateView } from "../types";

interface Props {
  state: StateView;
  disabled: boolean;
  onAdd: () => void;
  onEdit: (e: ExitView) => void;
  onDelete: (e: ExitView) => void;
  onRefresh: (e: ExitView) => Promise<unknown>;
  onTarget: (id: string) => void;
}

export default function ExitsPanel({ state, disabled, onAdd, onEdit, onDelete, onRefresh, onTarget }: Props) {
  const [refreshing, setRefreshing] = useState<string | null>(null);

  return (
    <div className="panel">
      <div className="panel-head">
        出口
        <span className="spacer" />
        <button className="btn small" onClick={onAdd} disabled={disabled}>
          + 添加
        </button>
      </div>
      <div className="panel-body">
        {state.exits.length === 0 && (
          <div className="empty">
            还没有出口。
            <br />
            点「添加」，粘贴 host:port:user:pass 即可。
          </div>
        )}
        {state.exits.map((e) => {
          const isTarget = e.id === state.target_exit;
          const ip = e.pinned_ip ?? e.last_ip;
          return (
            <div key={e.id} className={`exit-card ${isTarget ? "target" : ""}`} onClick={() => !disabled && onTarget(e.id)}>
              <div className="name">
                {e.name}
                {isTarget && <span className="tag">目标</span>}
                {e.pinned_ip && <span className="tag muted">固定 IP</span>}
              </div>
              <div className="meta">
                {e.host}:{e.port}
                {e.username && ` · ${e.username}`}
                {!e.has_password && e.username && " · 未存密码"}
              </div>
              <div className="ip">
                {ip ? (
                  <>
                    {ip}
                    {e.last_country && ` · ${e.last_country}`}
                    {e.last_org && ` · ${e.last_org}`}
                  </>
                ) : (
                  <span className="note">尚未获取出口 IP</span>
                )}
              </div>
              {e.last_checked && <div className="meta">刷新于 {formatTime(e.last_checked)}</div>}
              {e.last_error && <div className="err">{e.last_error}</div>}
              <div className="actions" onClick={(ev) => ev.stopPropagation()}>
                <button
                  className="btn small"
                  disabled={disabled || refreshing === e.id}
                  onClick={async () => {
                    setRefreshing(e.id);
                    await onRefresh(e);
                    setRefreshing(null);
                  }}
                >
                  {refreshing === e.id ? "获取中…" : "刷新 IP"}
                </button>
                <button className="btn small" disabled={disabled} onClick={() => onEdit(e)}>
                  编辑
                </button>
                <button className="btn small danger" disabled={disabled} onClick={() => onDelete(e)}>
                  删除
                </button>
              </div>
            </div>
          );
        })}
      </div>
      <div className="panel-foot">「刷新 IP」会经该代理连一次 ipinfo.io，消耗少量流量。</div>
    </div>
  );
}
