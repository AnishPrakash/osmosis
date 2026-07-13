import React, { useMemo } from "react";

const TOP_SYSCALLS = [
  "read", "write", "open", "close", "stat",
  "mmap", "fork", "execve", "wait4", "openat", "brk", "mprotect"
];

export function SyscallHeatmap({ events }) {
  const matrix = useMemo(() => {
    const counts = {};
    events
      .filter(e => e.type === "syscall")
      .slice(0, 200)
      .forEach(e => {
        const key = `${e.comm}::${e.syscall}`;
        counts[key] = (counts[key] || 0) + 1;
      });
    const comms = [...new Set(events.filter(e => e.comm).map(e => e.comm))].slice(0, 8);
    return comms.map(comm => ({
      comm,
      cells: TOP_SYSCALLS.map(sc => ({
        syscall: sc, count: counts[`${comm}::${sc}`] || 0,
      }))
    }));
  }, [events]);

  const maxVal = Math.max(...matrix.flatMap(r => r.cells.map(c => c.count)), 1);

  const heatColor = (count) => {
    const t = count / maxVal;
    return `rgba(${Math.round(t * 239)}, ${Math.round((1-t) * 68 + 20)}, ${Math.round((1-t) * 130)}, ${0.3 + t * 0.7})`;
  };

  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-3">🔥 Syscall Heatmap</h2>
      <div className="overflow-x-auto">
        <table className="text-xs w-full">
          <thead>
            <tr>
              <th className="text-left text-slate-400 pr-4 pb-2">PROCESS</th>
              {TOP_SYSCALLS.map(sc => (
                <th key={sc} className="text-slate-400 px-1 text-center"
                    style={{ writingMode: "vertical-rl", height: "55px", fontSize: "10px" }}>
                  {sc}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {matrix.map(row => (
              <tr key={row.comm}>
                <td className="font-mono text-white pr-4 py-1">{row.comm}</td>
                {row.cells.map(cell => (
                  <td key={cell.syscall}
                      className="w-6 h-6 text-center cursor-default"
                      style={{ backgroundColor: heatColor(cell.count) }}
                      title={`${row.comm} | ${cell.syscall}: ${cell.count}`}>
                    &nbsp;
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
        {!matrix.length && (
          <div className="text-slate-500 text-sm text-center py-4">Waiting for syscall events...</div>
        )}
      </div>
    </div>
  );
}
