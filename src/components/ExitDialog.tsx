import { useState } from "react";
import { parseExitString } from "../api";
import type { ExitInput, ExitView } from "../types";

interface Props {
  exit: ExitView | null;
  onClose: () => void;
  onSave: (input: ExitInput, refresh: boolean) => Promise<boolean>;
}

export default function ExitDialog({ exit, onClose, onSave }: Props) {
  const [raw, setRaw] = useState("");
  const [name, setName] = useState(exit?.name ?? "");
  const [host, setHost] = useState(exit?.host ?? "");
  const [port, setPort] = useState(exit ? String(exit.port) : "");
  const [username, setUsername] = useState(exit?.username ?? "");
  const [password, setPassword] = useState("");
  const [pinned, setPinned] = useState(exit?.pinned_ip ?? "");
  const [refresh, setRefresh] = useState(!exit);
  const [saving, setSaving] = useState(false);
  const [rawError, setRawError] = useState<string | null>(null);

  const onRaw = (v: string) => {
    setRaw(v);
    if (!v.trim()) return setRawError(null);
    const p = parseExitString(v);
    if (!p) return setRawError("格式应为 host:port:user:pass");
    setRawError(null);
    setHost(p.host);
    setPort(String(p.port));
    setUsername(p.username);
    setPassword(p.password);
  };

  const portNum = Number(port);
  const valid = name.trim() && host.trim() && Number.isInteger(portNum) && portNum > 0 && portNum < 65536;

  const submit = async () => {
    setSaving(true);
    const ok = await onSave(
      {
        id: exit?.id,
        name: name.trim(),
        host: host.trim(),
        port: portNum,
        username,
        password: password || undefined,
        pinned_ip: pinned.trim() || undefined,
      },
      refresh,
    );
    if (!ok) setSaving(false);
  };

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">{exit ? `编辑出口「${exit.name}」` : "添加出口"}</div>
        <div className="modal-body">
          <label className="field">
            <span>快速粘贴</span>
            <input type="text" value={raw} placeholder="isp.decodo.com:10001:user:password" onChange={(e) => onRaw(e.target.value)} />
            {rawError ? <span className="err-text">{rawError}</span> : <span className="hint">粘贴后自动拆分到下面各项</span>}
          </label>
          <label className="field">
            <span>名称</span>
            <input type="text" value={name} placeholder="japan01" onChange={(e) => setName(e.target.value)} autoFocus />
          </label>
          <div className="row">
            <label className="field" style={{ flex: 3 }}>
              <span>主机</span>
              <input type="text" value={host} onChange={(e) => setHost(e.target.value)} />
            </label>
            <label className="field" style={{ flex: 1 }}>
              <span>端口</span>
              <input type="text" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ""))} />
            </label>
          </div>
          <div className="row">
            <label className="field">
              <span>用户名</span>
              <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} />
            </label>
            <label className="field">
              <span>密码</span>
              <input
                type="password"
                value={password}
                placeholder={exit?.has_password ? "留空保持不变" : ""}
                onChange={(e) => setPassword(e.target.value)}
              />
            </label>
          </div>
          <label className="field">
            <span>固定出口 IP（可选）</span>
            <input type="text" value={pinned} placeholder="例如 104.253.94.121" onChange={(e) => setPinned(e.target.value)} />
            <span className="hint">填写后检测以此 IP 为准，不再依赖「刷新 IP」的结果。密码保存在系统钥匙串，不写入配置文件。</span>
          </label>
          <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input type="checkbox" checked={refresh} onChange={(e) => setRefresh(e.target.checked)} />
            保存后立即经该代理获取出口 IP
          </label>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" disabled={!valid || saving} onClick={submit}>
            {saving ? "保存中…" : "保存"}
          </button>
        </div>
      </div>
    </div>
  );
}
