import { useMemo, useState } from "react";
import { formatTime } from "../api";
import type { StateView } from "../types";

interface Props {
  state: StateView;
  disabled: boolean;
  onChange: (ids: string[]) => void;
  onUpdate: () => Promise<unknown>;
}

const CATEGORY_LABELS: Record<string, string> = {
  coding: "编程",
  model: "模型",
  media: "多媒体",
};

export default function AppsPanel({ state, disabled, onChange, onUpdate }: Props) {
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "global" | "cn">("all");
  const [category, setCategory] = useState<string | null>(null);
  const [onlySelected, setOnlySelected] = useState(false);
  const [updating, setUpdating] = useState(false);
  const selected = useMemo(() => new Set(state.selected_apps), [state.selected_apps]);

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const p of state.providers) for (const c of p.categories) counts.set(c, (counts.get(c) ?? 0) + 1);
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c);
  }, [state.providers]);

  const list = useMemo(() => {
    const q = query.trim().toLowerCase();
    return state.providers
      .filter((p) => scope === "all" || p.scope === scope)
      .filter((p) => !category || p.categories.includes(category))
      .filter((p) => !onlySelected || selected.has(p.id))
      .filter(
        (p) =>
          !q ||
          p.id.toLowerCase().includes(q) ||
          p.name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q) ||
          p.aliases.some((a) => a.toLowerCase().includes(q)),
      )
      .sort((a, b) => Number(selected.has(b.id)) - Number(selected.has(a.id)));
  }, [state.providers, query, scope, category, onlySelected, selected]);

  const toggle = (id: string) => {
    const next = new Set(selected);
    next.has(id) ? next.delete(id) : next.add(id);
    onChange(state.providers.map((p) => p.id).filter((x) => next.has(x)));
  };

  return (
    <div className="panel">
      <div className="panel-head">
        应用
        <span className="tag muted">已选 {selected.size}</span>
        <span className="spacer" />
        <button className="btn small" disabled={disabled} onClick={() => onChange(["anthropic"])} title="只保留 Claude">
          默认
        </button>
      </div>
      <div className="filters">
        <input type="text" placeholder="搜索应用 / 别名" value={query} onChange={(e) => setQuery(e.target.value)} />
        <div className="chips">
          {(["all", "global", "cn"] as const).map((s) => (
            <span key={s} className={`chip ${scope === s ? "on" : ""}`} onClick={() => setScope(s)}>
              {s === "all" ? "全部" : s === "global" ? "海外" : "国内"}
            </span>
          ))}
          <span className={`chip ${onlySelected ? "on" : ""}`} onClick={() => setOnlySelected(!onlySelected)}>
            只看已选
          </span>
        </div>
        <div className="chips">
          <span className={`chip ${category === null ? "on" : ""}`} onClick={() => setCategory(null)}>
            全部分类
          </span>
          {categories.map((c) => (
            <span key={c} className={`chip ${category === c ? "on" : ""}`} onClick={() => setCategory(category === c ? null : c)}>
              {CATEGORY_LABELS[c] ?? c}
            </span>
          ))}
        </div>
      </div>
      <div className="panel-body">
        {list.length === 0 && <div className="empty">没有匹配的应用</div>}
        {list.map((p) => (
          <label key={p.id} className="app-row">
            <input type="checkbox" checked={selected.has(p.id)} disabled={disabled} onChange={() => toggle(p.id)} />
            <div>
              <div className="title">{p.name}</div>
              {p.description && <div className="desc">{p.description}</div>}
            </div>
            <span className="count">{p.rule_count} 条</span>
          </label>
        ))}
      </div>
      <div className="panel-foot">
        <span>
          规则 {state.providers.length} 个 · 更新于 {formatTime(state.providers_updated_at)}
        </span>
        <span className="spacer" style={{ flex: 1 }} />
        <button
          className="btn small"
          disabled={disabled || updating}
          onClick={async () => {
            setUpdating(true);
            await onUpdate();
            setUpdating(false);
          }}
        >
          {updating ? "更新中…" : "更新规则"}
        </button>
      </div>
    </div>
  );
}
