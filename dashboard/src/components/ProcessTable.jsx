import React from "react";

const riskColor = (score) => {
  if (score > 0.8) return "text-red-400 font-bold";
  if (score > 0.5) return "text-yellow-400";
  return "text-green-400";
};
const riskLabel = (score) => {
  if (score > 0.8) return "⚠ HIGH";
  if (score > 0.5) return "~ MED";
  return "✓ OK";
};

export function ProcessTable({ processes }) {
  const sorted = Object.values(processes)
    .filter(p => p.syscall_count > 5)
    .sort((a, b) => b.risk_score - a.risk_score || b.syscall_count - a.syscall_count)
    .slice(0, 20);

  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-3">⚙ Live Process Monitor</h2>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 text-xs border-b border-slate-700">
              {["PID","PROCESS","CONTAINER","SYSCALLS","PG FAULTS","VFS WR","RENAMES","RISK"].map(h => (
                <th key={h} className="text-left py-2 pr-4">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map(p => (
              <tr key={p.pid} className="border-b border-slate-800 hover:bg-slate-800/50 transition">
                <td className="py-1.5 text-slate-400 pr-4">{p.pid}</td>
                <td className="font-mono text-white pr-4">{p.comm}</td>
                <td className="text-cyan-600 text-xs pr-4">{(p.container_id || "host").slice(0,12)}</td>
                <td className="text-blue-300 pr-4">{p.syscall_count.toLocaleString()}</td>
                <td className="text-purple-300 pr-4">{p.page_faults}</td>
                <td className="text-orange-300 pr-4">{p.vfs_writes}</td>
                <td className={`pr-4 ${p.vfs_renames > 5 ? "text-red-400 font-bold" : "text-slate-500"}`}>
                  {p.vfs_renames}
                </td>
                <td className={riskColor(p.risk_score)}>
                  {riskLabel(p.risk_score)} ({(p.risk_score * 100).toFixed(0)}%)
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
