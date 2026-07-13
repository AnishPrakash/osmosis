import React, { useMemo } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from "recharts";

export function MemoryPressure({ events }) {
  const data = useMemo(() => {
    const now = Date.now() / 1000;
    return Array.from({ length: 30 }, (_, i) => {
      const start = now - (30 - i);
      const end   = now - (29 - i);
      const slice = events.filter(e => e.ts_s >= start && e.ts_s < end && e.type === "memory");
      const minor_faults  = slice.filter(e => e.mem_event === "page_fault" && !e.is_major).length;
      const major_faults  = slice.filter(e => e.mem_event === "page_fault" && e.is_major).length;
      const page_allocs   = slice.filter(e => e.mem_event === "page_alloc").length;
      const page_frees    = slice.filter(e => e.mem_event === "page_free").length;
      return { t: `-${29-i}s`, minor_faults, major_faults, page_allocs, page_frees };
    });
  }, [events]);

  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-3">💾 Memory Pressure (30s)</h2>
      <p className="text-slate-500 text-xs mb-2">
        Major faults (&gt;1ms) require disk I/O. Rising alloc - free delta indicates memory leak.
      </p>
      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={data}>
          <defs>
            <linearGradient id="minor" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#8b5cf6" stopOpacity={0.3} />
              <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="major" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="t" tick={{ fill: "#64748b", fontSize: 9 }} interval={4} />
          <YAxis tick={{ fill: "#64748b", fontSize: 9 }} />
          <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b" }}
                   labelStyle={{ color: "#94a3b8" }} />
          <Legend wrapperStyle={{ fontSize: "11px" }} />
          <Area type="monotone" dataKey="minor_faults" name="Minor Faults" stroke="#8b5cf6" fill="url(#minor)" strokeWidth={1.5} />
          <Area type="monotone" dataKey="major_faults" name="Major Faults" stroke="#ef4444" fill="url(#major)" strokeWidth={2} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
