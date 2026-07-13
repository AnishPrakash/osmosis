import React from "react";

const ALERT_REASONS = {
  high_rename: "Mass file rename (ransomware pattern)",
  high_risk:   "ML anomaly score exceeded threshold",
  fork_spike:  "Rapid process spawning (fork bomb pattern)",
};

function classifyAlert(evt) {
  if (evt.vfs_renames > 20) return "high_rename";
  if (evt.risk_score > 0.8)  return "high_risk";
  if (evt.fork_count > 50)   return "fork_spike";
  return "high_risk";
}

export function AlertPanel({ events }) {
  const alerts = events
    .filter(e => (e.risk_score || 0) > 0.6)
    .slice(0, 10);

  if (!alerts.length) {
    return (
      <div className="bg-slate-900 rounded-xl p-4 border border-slate-700">
        <h2 className="text-cyan-400 font-bold text-lg mb-2">🛡 Alert Panel</h2>
        <div className="text-green-400 text-sm text-center py-4">
          ✓ No anomalies detected — system behavioral baseline is normal
        </div>
      </div>
    );
  }

  return (
    <div className="bg-red-950/30 rounded-xl p-4 border border-red-800">
      <h2 className="text-red-400 font-bold text-lg mb-3">
        ⚠ Active Alerts ({alerts.length})
      </h2>
      <div className="space-y-2">
        {alerts.map((a, i) => {
          const reason = ALERT_REASONS[classifyAlert(a)] || "Behavioral anomaly";
          return (
            <div key={i} className="bg-red-900/20 border border-red-800/50 rounded-lg p-3">
              <div className="flex justify-between items-start">
                <div>
                  <span className="text-red-300 font-bold font-mono">
                    PID {a.pid} ({a.comm})
                  </span>
                  {a.container_id && a.container_id !== "host" && (
                    <span className="ml-2 text-red-400/60 text-xs">
                      [{a.container_id?.slice(0,12)}]
                    </span>
                  )}
                </div>
                <span className={`text-sm font-bold ${
                  a.risk_score > 0.8 ? "text-red-400" : "text-yellow-400"
                }`}>
                  {(a.risk_score * 100).toFixed(1)}% risk
                </span>
              </div>
              <div className="text-red-400/80 text-xs mt-1">{reason}</div>
              <div className="text-slate-500 text-xs mt-1">
                {a.ts_s ? new Date(a.ts_s * 1000).toLocaleTimeString() : ""}
                {a.type === "io" && a.io_op === "vfs_rename" && (
                  <span className="ml-2 text-red-300">🔴 vfs_rename burst</span>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
