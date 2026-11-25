import { useMemo, useState } from "react";
import { save } from "@tauri-apps/plugin-dialog";
import { api, errorText, formatTime } from "../api";
import type { AppReport, ItemResult, Report, StateView, Status } from "../types";

interface Props {
  state: StateView;
  running: boolean;
  report: Report | null;
  liveItems: ItemResult[];
  onError: (e: string) => void;
}

const KIND: Record<ItemResult["kind"], string> = {
  domain: "域名",
  suffix: "后缀",
  keyword: "关键词",
  process: "进程",
  cidr: "IP 段",
  cidr6: "IPv6 段",
  asn: "ASN",
};
const METHOD: Record<ItemResult["method"], string> = { measured: "实测", attributed: "归因", sampled: "抽样", none: "-" };
const STATUS: Record<Status, string> = { pass: "通过", fail: "失败", warn: "未验证", skip: "跳过", info: "信息", pending: "归因中" };
const ICON: Record<string, string> = { pass: "✅", fail: "❌", warn: "⚠️" };

function headline(r: Report) {
  if (r.cancelled) return "检测已取消";
  if (r.status === "pass") return "全部流量经目标出口";
  if (r.status === "fail") return "有流量没走目标出口";
  return "部分流量无法确认";
}

function ItemsTable({ items, onlyIssues }: { items: ItemResult[]; onlyIssues: boolean }) {
  const rows = onlyIssues ? items.filter((i) => i.status === "fail" || i.status === "warn") : items;
  if (rows.length === 0) return <div className="empty">{onlyIssues ? "没有异常项" : "暂无结果"}</div>;
  return (
    <table>
      <thead>
        <tr>
          <th style={{ width: 70 }}>状态</th>
          <th style={{ width: 60 }}>类型</th>
          <th>目标</th>
          <th style={{ width: 50 }}>方法</th>
          <th style={{ width: 150 }}>出口 IP</th>
          <th>命中规则 → 节点</th>
          <th>说明</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((i) => (
          <tr key={i.id} className={i.status === "fail" ? "fail" : ""}>
            <td>
              <span className={`dot ${i.status}`} /> {STATUS[i.status]}
            </td>
            <td>{KIND[i.kind] ?? i.kind}</td>
            <td className="mono">
              {i.target}
              {i.probe !== i.target && <div className="note">探测 {i.probe}</div>}
              {i.source !== "rules" && <div className="note">{i.source === "local" ? "本机发现" : "规则 + 本机"}</div>}
            </td>
            <td>
              <span className={`badge ${i.method}`}>{METHOD[i.method]}</span>
            </td>
            <td className="mono">
              {i.observed_ip}
              {i.observed_loc && <div className="note">{i.observed_loc}</div>}
            </td>
            <td>
              {i.rule}
              {i.chain.length > 0 && <div className="note">→ {[...i.chain].reverse().join(" → ")}</div>}
            </td>
            <td className="note">{i.note}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function AppSection({ app, onlyIssues }: { app: AppReport; onlyIssues: boolean }) {
  const [open, setOpen] = useState(app.status !== "pass");
  return (
    <div className="section">
      <div className="section-head" onClick={() => setOpen(!open)}>
        <span className={`dot ${app.status}`} />
        <span className="title">{app.name}</span>
        <span className="counts">
          通过 {app.pass} · 失败 {app.fail} · 未验证 {app.warn} · 跳过 {app.skip}
        </span>
        <span className="spacer" />
        <span className="note">{open ? "收起" : "展开"}</span>
      </div>
      {open && (
        <div className="section-body">
          {app.discovered_roots.length > 0 && (
            <div className="env-row">
              <span className="name">本机安装</span>
              <span className="detail mono">{app.discovered_roots.join("；")}</span>
            </div>
          )}
          <ItemsTable items={app.items} onlyIssues={onlyIssues} />
        </div>
      )}
    </div>
  );
}

export default function ResultsPanel({ state, running, report, liveItems, onError }: Props) {
  const [onlyIssues, setOnlyIssues] = useState(false);
  const names = useMemo(() => new Map(state.providers.map((p) => [p.id, p.name])), [state.providers]);

  const liveGroups = useMemo(() => {
    const g = new Map<string, ItemResult[]>();
    for (const i of [...liveItems].sort((a, b) => a.id - b.id)) {
      if (!g.has(i.app)) g.set(i.app, []);
      g.get(i.app)!.push(i);
    }
    return [...g.entries()];
  }, [liveItems]);

  const exportReport = async () => {
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
    const path = await save({
      defaultPath: `netdect-${stamp}.md`,
      filters: [
        { name: "Markdown", extensions: ["md"] },
        { name: "JSON", extensions: ["json"] },
      ],
    });
    if (!path) return;
    try {
      await api.exportReport(path);
    } catch (e) {
      onError(errorText(e));
    }
  };

  return (
    <div className="panel">
      <div className="panel-head">
        结果
        <span className="spacer" />
        <label style={{ display: "flex", gap: 4, alignItems: "center", fontWeight: 400 }}>
          <input type="checkbox" checked={onlyIssues} onChange={(e) => setOnlyIssues(e.target.checked)} />
          只看异常
        </label>
        <button className="btn small" disabled={!report || running} onClick={exportReport}>
          导出报告
        </button>
      </div>
      <div className="panel-body">
        {!report && !running && (
          <div className="summary idle">
            <div className="icon">🛰️</div>
            <div>
              <div className="headline">尚未检测</div>
              <div className="sub">选好目标出口和应用后点「检测」。检测会实际访问所选应用的域名，并核对每条连接的出口 IP。</div>
            </div>
          </div>
        )}

        {running && (
          <>
            <div className="summary idle">
              <div className="icon">⏳</div>
              <div>
                <div className="headline">检测中…</div>
                <div className="sub">结果会边测边显示；「归因中」的条目要等实测结果出来后统一判定。</div>
              </div>
            </div>
            {liveGroups.map(([app, items]) => (
              <div className="section" key={app}>
                <div className="section-head">
                  <span className="title">{names.get(app) ?? app}</span>
                  <span className="counts">{items.length} 项</span>
                </div>
                <div className="section-body">
                  <ItemsTable items={items} onlyIssues={onlyIssues} />
                </div>
              </div>
            ))}
          </>
        )}

        {report && !running && (
          <>
            <div className={`summary ${report.cancelled ? "warn" : report.status}`}>
              <div className="icon">{ICON[report.cancelled ? "warn" : report.status] ?? "ℹ️"}</div>
              <div>
                <div className="headline">{headline(report)}</div>
                <div className="sub">{report.summary}</div>
              </div>
            </div>
            <div className="kv">
              <span className="k">目标出口</span>
              <span className="v">
                {report.target_name} · <span className="mono">{report.expected_ip}</span>（
                {report.expected_source === "pinned" ? "手动固定" : "经该出口实测"}）
              </span>
              <span className="k">探测方式</span>
              <span className="v">{report.route}</span>
              <span className="k">代理软件 API</span>
              <span className="v">{report.engine ?? `不可用：${report.engine_error ?? "未知原因"}`}</span>
              <span className="k">IP 回显服务</span>
              <span className="v">
                {report.echo_url ?? "无可用服务"}
                {report.baseline_ip && `（NetDect 自身出口 ${report.baseline_ip}）`}
              </span>
              <span className="k">完成时间</span>
              <span className="v">
                {formatTime(report.finished_at)} · 用时 {report.finished_at - report.started_at} 秒
              </span>
            </div>
            <div className="section">
              <div className="section-head">
                <span className="title">环境检查</span>
              </div>
              <div className="section-body">
                {report.env.map((c) => (
                  <div className="env-row" key={c.name}>
                    <span className={`dot ${c.status}`} />
                    <span className="name">{c.name}</span>
                    <span className="detail">{c.detail}</span>
                  </div>
                ))}
              </div>
            </div>
            {report.apps.map((a) => (
              <AppSection key={a.id} app={a} onlyIssues={onlyIssues} />
            ))}
          </>
        )}
      </div>
    </div>
  );
}
