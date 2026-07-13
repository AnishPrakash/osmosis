import React, { useMemo, useRef, useEffect } from "react";

// Assign a consistent color to each process name
const PALETTE = [
  "#06b6d4", "#8b5cf6", "#f59e0b", "#10b981",
  "#ef4444", "#3b82f6", "#ec4899", "#84cc16",
  "#f97316", "#a855f7", "#14b8a6", "#eab308",
];
const colorCache = {};
let colorIdx = 0;

function getProcessColor(comm) {
  if (!colorCache[comm]) {
    colorCache[comm] = PALETTE[colorIdx % PALETTE.length];
    colorIdx++;
  }
  return colorCache[comm];
}

export function SchedulerTimeline({ schedEvents }) {
  const canvasRef = useRef(null);
  const WINDOW_MS = 3000;    // Show 3 seconds of scheduling history
  const ROW_HEIGHT = 28;
  const LABEL_WIDTH = 100;

  // Build timeline: for each unique (cpu, process), compute time segments
  const { lanes, processes, timeRange } = useMemo(() => {
    if (!schedEvents.length) return { lanes: [], processes: [], timeRange: [0, 1] };

    const now     = Date.now() / 1000;
    const cutoff  = now - WINDOW_MS / 1000;
    const recent  = schedEvents.filter(e => (e.ts_s || 0) >= cutoff);

    const cpuCurrent = {}; // cpu → { comm, startTs }
    const segments   = []; // { cpu, comm, start_s, end_s }

    // Process in chronological order (schedEvents is most-recent-first, so reverse)
    const sorted = [...recent].sort((a, b) => (a.ts_s || 0) - (b.ts_s || 0));

    sorted.forEach(ev => {
      const cpu  = ev.cpu ?? 0;
      const prev = ev.prev_comm || "idle";
      const next = ev.next_comm || "idle";
      const ts   = ev.ts_s || 0;

      // Close the previous segment for this CPU
      if (cpuCurrent[cpu]) {
        segments.push({
          cpu,
          comm:    cpuCurrent[cpu].comm,
          start_s: cpuCurrent[cpu].startTs,
          end_s:   ts,
        });
      }
      cpuCurrent[cpu] = { comm: next, startTs: ts };
    });

    // Close open segments at current time
    Object.entries(cpuCurrent).forEach(([cpu, cur]) => {
      segments.push({
        cpu: parseInt(cpu), comm: cur.comm,
        start_s: cur.startTs, end_s: now,
      });
    });

    const cpus       = [...new Set(segments.map(s => s.cpu))].sort();
    const processes  = [...new Set(segments.map(s => s.comm).filter(c => c !== "swapper/0"))];
    const minTs      = Math.min(...segments.map(s => s.start_s), cutoff);
    const maxTs      = Math.max(...segments.map(s => s.end_s), now);
    const lanes      = cpus.map(cpu => ({
      cpu,
      label: `CPU ${cpu}`,
      segments: segments.filter(s => s.cpu === cpu),
    }));

    return { lanes, processes, timeRange: [minTs, maxTs] };
  }, [schedEvents]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !lanes.length) return;

    const ctx    = canvas.getContext("2d");
    const width  = canvas.width;
    const height = Math.max(lanes.length * ROW_HEIGHT + 40, 120);
    canvas.height = height;

    // Clear
    ctx.fillStyle = "#0f172a";
    ctx.fillRect(0, 0, width, height);

    const [minTs, maxTs] = timeRange;
    const timeSpan = Math.max(maxTs - minTs, 0.001);

    const toX = (ts) => LABEL_WIDTH + ((ts - minTs) / timeSpan) * (width - LABEL_WIDTH - 10);

    // Draw grid lines (time ticks)
    ctx.strokeStyle = "#1e293b";
    ctx.lineWidth   = 1;
    for (let i = 0; i <= 6; i++) {
      const x = LABEL_WIDTH + (i / 6) * (width - LABEL_WIDTH - 10);
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, height);
      ctx.stroke();
    }

    // Draw lanes
    lanes.forEach((lane, laneIdx) => {
      const y = laneIdx * ROW_HEIGHT + 20;

      // CPU label
      ctx.fillStyle = "#64748b";
      ctx.font      = "11px monospace";
      ctx.fillText(lane.label, 4, y + ROW_HEIGHT / 2 + 4);

      // Draw segments
      lane.segments.forEach(seg => {
        if (seg.end_s < minTs || seg.start_s > maxTs) return;
        if (seg.comm === "swapper/0" || seg.comm === "idle") return;

        const x1 = Math.max(toX(seg.start_s), LABEL_WIDTH);
        const x2 = Math.min(toX(seg.end_s), width - 10);
        const w  = Math.max(x2 - x1, 1);

        const color = getProcessColor(seg.comm);
        ctx.fillStyle = color;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(x1, y + 2, w, ROW_HEIGHT - 6);
        ctx.globalAlpha = 1;

        // Label if wide enough
        if (w > 30) {
          ctx.fillStyle = "#0f172a";
          ctx.font      = "9px monospace";
          ctx.fillText(seg.comm.slice(0, Math.floor(w / 7)), x1 + 2, y + ROW_HEIGHT / 2 + 3);
        }
      });
    });

    // Timeline header
    ctx.fillStyle = "#475569";
    ctx.font      = "10px monospace";
    ctx.fillText(`← ${(WINDOW_MS / 1000).toFixed(0)}s window`, LABEL_WIDTH + 4, 14);
    ctx.fillText("NOW →", width - 50, 14);

  }, [lanes, timeRange]);

  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-2">
        🗂 Live Scheduler Timeline — Actual Kernel Context Switches
      </h2>
      <p className="text-slate-500 text-xs mb-3">
        Each bar = one process on a CPU core. Captured via <code>sched:sched_switch</code> eBPF tracepoint in real-time.
      </p>

      {lanes.length === 0 ? (
        <div className="text-slate-500 text-sm text-center py-6">
          Waiting for scheduler events... (run <code>make backend</code> with sudo)
        </div>
      ) : (
        <>
          <canvas
            ref={canvasRef}
            width={900}
            style={{ width: "100%", borderRadius: "6px" }}
          />
          {/* Legend */}
          <div className="flex flex-wrap gap-2 mt-3">
            {[...new Set(schedEvents.slice(0, 50).map(e => e.next_comm).filter(Boolean))]
              .slice(0, 10)
              .map(comm => (
                <span key={comm} className="text-xs px-2 py-0.5 rounded-full font-mono"
                  style={{
                    background: getProcessColor(comm) + "33",
                    border: `1px solid ${getProcessColor(comm)}`,
                    color: getProcessColor(comm)
                  }}>
                  {comm}
                </span>
              ))}
          </div>
        </>
      )}
    </div>
  );
}
