import React, { useState } from "react";
import { useOSmosisWebSocket } from "./hooks/useWebSocket";
import { ProcessTable }      from "./components/ProcessTable";
import { SyscallHeatmap }    from "./components/SyscallHeatmap";
import { SchedulerTimeline } from "./components/SchedulerTimeline";
import { MemoryPressure }    from "./components/MemoryPressure";
import { ContainerView }     from "./components/ContainerView";
import { AlertPanel }        from "./components/AlertPanel";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from "recharts";

const WS_URL = "ws://localhost:8000/ws/events";

function EventRate({ events }) {
  const now = Date.now() / 1000;
  const buckets = Array.from({ length: 30 }, (_, i) => {
    const s = now - (30 - i), e = now - (29 - i);
    return {
      t: `-${29-i}s`,
      total:    events.filter(ev => ev.ts_s >= s && ev.ts_s < e).length,
      syscalls: events.filter(ev => ev.ts_s >= s && ev.ts_s < e && ev.type === "syscall").length,
    };
  });
  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-3">📈 Event Rate (30s)</h2>
      <ResponsiveContainer width="100%" height={160}>
        <LineChart data={buckets}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 9 }} interval={4} />
          <YAxis tick={{ fill: "#64748b", fontSize: 9 }} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }} />
          <Line type="monotone" dataKey="total"    name="All Events" stroke="#06b6d4" dot={false} strokeWidth={2} />
          <Line type="monotone" dataKey="syscalls" name="Syscalls"   stroke="#8b5cf6" dot={false} strokeWidth={1.5} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function LiveFeed({ events }) {
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
      <h2 className="text-cyan-400 font-bold text-lg mb-2">📡 Live Event Feed</h2>
      <div className="font-mono text-xs text-slate-300 h-36 overflow-y-auto space-y-0.5">
        {events.slice(0, 60).map((e, i) => (
          <div key={i} className="hover:bg-slate-800/50 px-2 py-0.5 rounded flex gap-2">
            <span className="text-slate-500 shrink-0">
              {e.ts_s ? new Date(e.ts_s * 1000).toLocaleTimeString("en-GB", { hour12: false }) : ""}
            </span>
            <span className={{
              "syscall":     "text-blue-300",
              "sched_switch":"text-orange-300",
              "memory":      "text-purple-300",
              "io":          "text-yellow-300",
            }[e.type] || "text-slate-400"}>
              [{e.type}]
            </span>
            <span className="text-white shrink-0">PID:{e.pid}</span>
            <span className="text-cyan-300 shrink-0">{e.comm}</span>
            {e.syscall     && <span className="text-green-300">→ {e.syscall}</span>}
            {e.io_op       && <span className="text-yellow-200">→ {e.io_op}</span>}
            {e.risk_score > 0.6 && (
              <span className="text-red-400 font-bold ml-auto shrink-0">
                ⚠ {(e.risk_score * 100).toFixed(0)}%
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

const TABS = ["Overview", "Scheduler", "Memory", "Containers", "Alerts"];

export default function App() {
  const { events, processes, containers, schedEvents, connected } =
    useOSmosisWebSocket(WS_URL);
  const [tab, setTab] = useState("Overview");

  const anomalyCount = events.filter(e => (e.risk_score || 0) > 0.7).length;

  return (
    <div className="min-h-screen p-4 md:p-6">
      {/* ── Header ────────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-3xl font-bold text-white">
            OS<span className="text-cyan-400">mosis</span>
            <span className="text-slate-600 text-base font-normal ml-3">v2.0</span>
          </h1>
          <p className="text-slate-400 text-sm mt-0.5">
            Real-Time Linux Kernel Behavioral Fingerprinting & ML Anomaly Detection
          </p>
        </div>
        <div className={`px-4 py-1.5 rounded-full text-sm font-mono border ${
          connected
            ? "bg-green-900/30 text-green-400 border-green-700"
            : "bg-red-900/30 text-red-400 border-red-700"
        }`}>
          {connected ? "● LIVE" : "○ DISCONNECTED"}
        </div>
      </div>

      {/* ── Stats Bar ─────────────────────────────────────────────────────── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Events Captured",    val: events.length.toLocaleString(),             color: "text-blue-400" },
          { label: "Active Processes",   val: Object.keys(processes).length,              color: "text-purple-400" },
          { label: "Containers Tracked", val: Object.keys(containers).length,             color: "text-cyan-400" },
          { label: "Anomalies Flagged",  val: anomalyCount, color: anomalyCount > 0 ? "text-red-400" : "text-green-400" },
        ].map(s => (
          <div key={s.label} className="bg-slate-900 border border-slate-700 rounded-xl p-4 text-center">
            <div className={`text-3xl font-bold ${s.color}`}>{s.val}</div>
            <div className="text-slate-400 text-xs mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* ── Tabs ──────────────────────────────────────────────────────────── */}
      <div className="flex gap-1 mb-4 bg-slate-900/60 p-1 rounded-lg border border-slate-700 w-fit">
        {TABS.map(t => (
          <button key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition ${
              tab === t
                ? "bg-cyan-600 text-white"
                : "text-slate-400 hover:text-white"
            }`}>
            {t === "Alerts" && anomalyCount > 0
              ? `Alerts (${anomalyCount})`
              : t}
          </button>
        ))}
      </div>

      {/* ── Tab Content ───────────────────────────────────────────────────── */}
      {tab === "Overview" && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <EventRate events={events} />
            <SyscallHeatmap events={events} />
          </div>
          <ProcessTable processes={processes} />
          <LiveFeed events={events} />
        </div>
      )}

      {tab === "Scheduler" && (
        <div className="space-y-4">
          <SchedulerTimeline schedEvents={schedEvents} />
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
            <h3 className="text-cyan-400 font-bold mb-2">
              About the Scheduler Timeline
            </h3>
            <p className="text-slate-400 text-sm leading-relaxed">
              Each bar represents one process running on a CPU core. Data comes
              directly from the <code className="text-cyan-300">sched:sched_switch</code> eBPF
              tracepoint — these are not simulated, they are the actual Linux
              Completely Fair Scheduler (CFS) decisions captured at nanosecond
              resolution. A horizontal bar width equals the on-CPU time of that
              process on that core.
            </p>
          </div>
        </div>
      )}

      {tab === "Memory" && (
        <div className="space-y-4">
          <MemoryPressure events={events} />
          <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
            <h3 className="text-cyan-400 font-bold mb-2">Memory Subsystem Legend</h3>
            <div className="text-slate-400 text-sm space-y-1">
              <div><span className="text-purple-300">Minor Faults</span> — page in physical memory but not mapped in this process's page table. Fast (&lt;100µs).</div>
              <div><span className="text-red-400">Major Faults</span> — page not in physical memory; requires disk I/O. Slow (&gt;1ms). Spike = swap or cold-start.</div>
              <div>Rising <span className="text-yellow-300">alloc - free</span> delta = memory leak.</div>
            </div>
          </div>
        </div>
      )}

      {tab === "Containers" && (
        <ContainerView containers={containers} />
      )}

      {tab === "Alerts" && (
        <AlertPanel events={events} />
      )}
    </div>
  );
}
