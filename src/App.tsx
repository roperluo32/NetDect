import { useCallback, useEffect, useRef, useState } from "react";
import { ask } from "@tauri-apps/plugin-dialog";
import { api, errorText, guardDot } from "./api";
import type { ExitView, GuardEvent, GuardStatus, ItemResult, Progress, Report, StateView } from "./types";
import TopBar from "./components/TopBar";
import ExitsPanel from "./components/ExitsPanel";
import ExitDialog from "./components/ExitDialog";
import AppsPanel from "./components/AppsPanel";
import ResultsPanel from "./components/ResultsPanel";
import GuardPanel from "./components/GuardPanel";
import SettingsDialog from "./components/SettingsDialog";

const MAX_EVENTS = 1000;

export default function App() {
  const [state, setState] = useState<StateView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<Progress | null>(null);
  const [liveItems, setLiveItems] = useState<ItemResult[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [editing, setEditing] = useState<ExitView | "new" | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [tab, setTab] = useState<"check" | "guard">("check");
  const [guardStatus, setGuardStatus] = useState<GuardStatus | null>(null);
  const [guardEvents, setGuardEvents] = useState<GuardEvent[]>([]);
  const [guardBusy, setGuardBusy] = useState(false);
  const liveRef = useRef(new Map<number, ItemResult>());
  const eventsRef = useRef(new Map<number, GuardEvent>());

  const attempt = useCallback(async <T,>(p: Promise<T>): Promise<T | undefined> => {
    try {
      return await p;
    } catch (e) {
      setError(errorText(e));
      return undefined;
    }
  }, []);

  const apply = useCallback(
    async (p: Promise<StateView>) => {
      const s = await attempt(p);
      if (s) setState(s);
      return s;
    },
    [attempt],
  );

  const flushEvents = useCallback(() => {
    const m = eventsRef.current;
    while (m.size > MAX_EVENTS) m.delete(m.keys().next().value!);
    setGuardEvents(Array.from(m.values()));
  }, []);

  useEffect(() => {
    apply(api.getState());
    attempt(api.guardGet()).then((g) => {
      if (!g) return;
      setGuardStatus(g.status);
      eventsRef.current = new Map(g.events.map((e) => [e.seq, e]));
      flushEvents();
      if (g.status.running) setTab("guard");
    });
    const unlisteners: Promise<() => void>[] = [
      api.onProgress((p) => {
        setProgress(p);
        if (p.item) {
          liveRef.current.set(p.item.id, p.item);
          setLiveItems(Array.from(liveRef.current.values()));
        }
      }),
      api.onGuardStatus(setGuardStatus),
      api.onGuardEvent((e) => {
        eventsRef.current.set(e.seq, e);
        flushEvents();
      }),
    ];
    return () => {
      unlisteners.forEach((u) => u.then((f) => f()));
    };
  }, [apply, attempt, flushEvents]);

  const runCheck = async () => {
    setError(null);
    setTab("check");
    setRunning(true);
    setReport(null);
    setProgress({ stage: "准备中", done: 0, total: 0, item: null });
    liveRef.current.clear();
    setLiveItems([]);
    const r = await attempt(api.runCheck());
    if (r) setReport(r);
    setRunning(false);
    setProgress(null);
    apply(api.getState());
  };

  const startGuard = async () => {
    setGuardBusy(true);
    setTab("guard");
    const s = await attempt(api.guardStart());
    if (s) setGuardStatus(s);
    setGuardBusy(false);
  };

  if (!state) {
    return <div className="empty">加载中…{error && <div className="err-text">{error}</div>}</div>;
  }

  return (
    <div className="app">
      <TopBar
        state={state}
        running={running}
        progress={progress}
        guard={guardStatus}
        onGuard={() => setTab("guard")}
        onTarget={(id) => apply(api.setTargetExit(id))}
        onRun={runCheck}
        onCancel={() => api.cancelCheck()}
        onSettings={() => setSettingsOpen(true)}
      />
      {error && (
        <div className="banner">
          <span>{error}</span>
          <span className="spacer" />
          <button onClick={() => setError(null)}>✕</button>
        </div>
      )}
      <div className="main">
        <ExitsPanel
          state={state}
          disabled={running}
          onAdd={() => setEditing("new")}
          onEdit={(e) => setEditing(e)}
          onDelete={async (e) => {
            if (await ask(`删除出口「${e.name}」？密码也会从系统钥匙串移除。`, { title: "NetDect", kind: "warning" }))
              apply(api.deleteExit(e.id));
          }}
          onRefresh={(e) => apply(api.refreshExitIp(e.id))}
          onTarget={(id) => apply(api.setTargetExit(id))}
        />
        <AppsPanel
          state={state}
          disabled={running}
          onChange={(ids) => apply(api.setSelectedApps(ids))}
          onUpdate={() => apply(api.updateProviders())}
        />
        <div className="right">
          <div className="tabs">
            <button className={`tab ${tab === "check" ? "on" : ""}`} onClick={() => setTab("check")}>
              检测结果
            </button>
            <button className={`tab ${tab === "guard" ? "on" : ""}`} onClick={() => setTab("guard")}>
              实时守护
              {guardStatus?.running && <span className={`dot ${guardDot(guardStatus)}`} style={{ marginLeft: 6 }} />}
            </button>
          </div>
          {tab === "check" ? (
            <ResultsPanel state={state} running={running} report={report} liveItems={liveItems} onError={setError} />
          ) : (
            guardStatus && (
              <GuardPanel
                status={guardStatus}
                events={guardEvents}
                busy={guardBusy}
                onStart={startGuard}
                onStop={async () => {
                  const s = await attempt(api.guardStop());
                  if (s) setGuardStatus(s);
                }}
                onVerify={() => attempt(api.guardVerify())}
                onClear={() => {
                  eventsRef.current.clear();
                  flushEvents();
                  attempt(api.guardClear());
                }}
              />
            )
          )}
        </div>
      </div>
      {editing && (
        <ExitDialog
          exit={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSave={async (input, refresh) => {
            const s = await apply(api.saveExit(input));
            if (!s) return false;
            setEditing(null);
            if (refresh) {
              const id = input.id ?? s.exits[s.exits.length - 1]?.id;
              if (id) apply(api.refreshExitIp(id));
            }
            return true;
          }}
        />
      )}
      {settingsOpen && (
        <SettingsDialog
          state={state}
          onClose={() => setSettingsOpen(false)}
          onSave={async (engine, probe, guardCfg) => {
            const a = await apply(api.saveSettings(engine, probe));
            const b = a && (await apply(api.saveGuardSettings(guardCfg)));
            if (b) setSettingsOpen(false);
          }}
        />
      )}
    </div>
  );
}