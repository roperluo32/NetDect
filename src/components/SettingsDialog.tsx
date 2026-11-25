import { useState } from "react";
import { api, errorText } from "../api";
import type { EngineCfg, GuardCfg, ProbeCfg, StateView } from "../types";

interface Props {
  state: StateView;
  onClose: () => void;
  onSave: (engine: EngineCfg, probe: ProbeCfg, guard: GuardCfg) => Promise<void>;
}

const ADDRESS_HINT: Record<EngineCfg["kind"], string> = {
  auto: "自动读取 Clash Verge 配置，并尝试 127.0.0.1:9090 / 9097",
  http: "例如 127.0.0.1:9090",
  pipe: "例如 \\\\.\\pipe\\verge-mihomo（Windows）",
  unix: "例如 /tmp/verge/verge-mihomo.sock（macOS）",
  none: "不连接代理软件，只做实测",
};

export default function SettingsDialog({ state, onClose, onSave }: Props) {
  const [engine, setEngine] = useState<EngineCfg>(state.engine);
  const [probe, setProbe] = useState<ProbeCfg>(state.probe);
  const [guard, setGuard] = useState<GuardCfg>(state.guard);
  const flag = (k: keyof GuardCfg, label: string, hint?: string) => (
    <label className="check-row" title={hint}>
      <input type="checkbox" checked={guard[k] as boolean} onChange={(e) => setGuard({ ...guard, [k]: e.target.checked })} />
      {label}
    </label>
  );
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      setTestResult({ ok: true, text: await api.testEngine(engine) });
    } catch (e) {
      setTestResult({ ok: false, text: errorText(e) });
    }
    setTesting(false);
  };

  return (
    <div className="modal-mask" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">设置</div>
        <div className="modal-body">
          <div className="field">
            <span>代理软件 API（用于查看每条连接命中的规则和节点）</span>
            <div className="row">
              <select
                style={{ flex: 1 }}
                value={engine.kind}
                onChange={(e) => setEngine({ ...engine, kind: e.target.value as EngineCfg["kind"] })}
              >
                <option value="auto">自动发现</option>
                <option value="http">HTTP 地址</option>
                <option value="pipe">命名管道</option>
                <option value="unix">Unix 套接字</option>
                <option value="none">不使用</option>
              </select>
              <input
                type="text"
                style={{ flex: 2 }}
                disabled={engine.kind === "none"}
                placeholder={engine.kind === "auto" ? "留空自动" : ""}
                value={engine.address}
                onChange={(e) => setEngine({ ...engine, address: e.target.value })}
              />
            </div>
            <span className="hint">{ADDRESS_HINT[engine.kind]}</span>
          </div>
          <label className="field">
            <span>API 密钥（secret）</span>
            <input
              type="password"
              value={engine.secret}
              placeholder={engine.kind === "auto" ? "留空则读取 Clash Verge 配置" : ""}
              disabled={engine.kind === "none"}
              onChange={(e) => setEngine({ ...engine, secret: e.target.value })}
            />
          </label>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <button className="btn small" disabled={testing || engine.kind === "none"} onClick={test}>
              {testing ? "连接中…" : "测试连接"}
            </button>
            {testResult && <span className={testResult.ok ? "ok-text" : "err-text"}>{testResult.text}</span>}
          </div>
          <label className="field">
            <span>探测方式</span>
            <select value={probe.mode} onChange={(e) => setProbe({ ...probe, mode: e.target.value as ProbeCfg["mode"] })}>
              <option value="auto">自动（TUN 优先，其次系统代理，再次环境变量）</option>
              <option value="tun">直连（依赖 TUN 接管）</option>
              <option value="system">经系统代理</option>
              <option value="env">经环境变量代理</option>
            </select>
          </label>
          <div className="row">
            <label className="field">
              <span>并发数</span>
              <input
                type="number"
                min={1}
                max={32}
                value={probe.concurrency}
                onChange={(e) => setProbe({ ...probe, concurrency: Math.max(1, Math.min(32, Number(e.target.value) || 1)) })}
              />
            </label>
            <label className="field">
              <span>单项超时（秒）</span>
              <input
                type="number"
                min={2}
                max={60}
                value={probe.timeout_secs}
                onChange={(e) => setProbe({ ...probe, timeout_secs: Math.max(2, Math.min(60, Number(e.target.value) || 10)) })}
              />
            </label>
          </div>
          <div className="settings-section">实时守护</div>
          <div className="row">
            <label className="field">
              <span>轮询间隔（毫秒）</span>
              <input
                type="number"
                min={300}
                max={10000}
                step={100}
                value={guard.poll_ms}
                onChange={(e) => setGuard({ ...guard, poll_ms: Math.max(300, Math.min(10000, Number(e.target.value) || 1000)) })}
              />
            </label>
            <label className="field">
              <span>出口复核间隔（分钟）</span>
              <input
                type="number"
                min={1}
                max={120}
                value={guard.verify_minutes}
                onChange={(e) => setGuard({ ...guard, verify_minutes: Math.max(1, Math.min(120, Number(e.target.value) || 5)) })}
              />
            </label>
          </div>
          <span className="hint">轮询越快越不容易漏掉短连接；复核每次会实际访问几个所选应用的域名。</span>
          {flag("notify", "发现泄漏或出口异常时弹出系统通知")}
          {flag("verify_on_app_start", "所选应用启动时立即复核出口并通知结果")}
          {flag("close_to_tray", "守护开启时，关闭窗口改为最小化到托盘")}
          {flag("start_on_launch", "打开 NetDect 时自动开启守护")}
          {flag("autostart", "开机自动启动 NetDect（后台运行并开启守护）")}
          <span className="hint">配置文件：{state.config_path}</span>
        </div>
        <div className="modal-foot">
          <button className="btn" onClick={onClose}>
            取消
          </button>
          <button className="btn primary" onClick={() => onSave(engine, probe, guard)}>
            保存
          </button>
        </div>
      </div>
    </div>
  );
}
