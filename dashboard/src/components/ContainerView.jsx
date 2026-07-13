import React from "react";

export function ContainerView({ containers }) {
  const sorted = Object.values(containers)
    .sort((a, b) => b.syscall_count - a.syscall_count);

  return (
    <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
      <h2 className="text-cyan-400 font-bold text-lg mb-3">🐳 Container Attribution</h2>
      {!sorted.length ? (
        <div className="text-slate-500 text-sm text-center py-4">
          No containers detected (showing host processes)
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="text-slate-400 text-xs border-b border-slate-700">
              {["CONTAINER", "SYSCALLS", "VFS WRITES", "RENAMES", "MAX RISK"].map(h => (
                <th key={h} className="text-left py-2 pr-4">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map(c => (
              <tr key={c.container_id} className="border-b border-slate-800 hover:bg-slate-800/50">
                <td className="py-1.5 font-mono text-cyan-300 pr-4">
                  {c.container_id || "host"}
                </td>
                <td className="text-blue-300 pr-4">{c.syscall_count.toLocaleString()}</td>
                <td className="text-orange-300 pr-4">{c.vfs_writes}</td>
                <td className={`pr-4 font-bold ${c.vfs_renames > 10 ? "text-red-400" : "text-slate-500"}`}>
                  {c.vfs_renames}
                </td>
                <td className={`font-bold ${
                  c.max_risk > 0.8 ? "text-red-400" :
                  c.max_risk > 0.5 ? "text-yellow-400" : "text-green-400"
                }`}>
                  {(c.max_risk * 100).toFixed(0)}%
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
