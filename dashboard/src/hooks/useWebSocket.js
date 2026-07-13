import { useEffect, useRef, useState, useCallback } from "react";

export function useOSmosisWebSocket(url) {
  const [events,     setEvents]     = useState([]);
  const [processes,  setProcesses]  = useState({});
  const [containers, setContainers] = useState({});
  const [schedEvents, setSchedEvents] = useState([]);
  const [connected,  setConnected]  = useState(false);
  const wsRef = useRef(null);

  const connect = useCallback(() => {
    wsRef.current = new WebSocket(url);
    wsRef.current.onopen  = () => setConnected(true);
    wsRef.current.onclose = () => { setConnected(false); setTimeout(connect, 2000); };

    wsRef.current.onmessage = (msg) => {
      try {
        const evt = JSON.parse(msg.data);

        setEvents(prev => [evt, ...prev].slice(0, 500));

        // Scheduler events for Gantt timeline
        if (evt.type === "sched_switch") {
          setSchedEvents(prev => [evt, ...prev].slice(0, 200));
        }

        if (evt.pid) {
          setProcesses(prev => {
            const ps = prev[evt.pid] || {
              pid: evt.pid, comm: evt.comm || "?",
              container_id: evt.container_id || "host",
              syscall_count: 0, page_faults: 0, major_faults: 0,
              sched_preemptions: 0, vfs_reads: 0, vfs_writes: 0,
              vfs_renames: 0, risk_score: 0,
            };
            if (evt.type === "syscall")      ps.syscall_count++;
            if (evt.type === "memory" && evt.mem_event === "page_fault") {
              ps.page_faults++;
              if (evt.is_major) ps.major_faults++;
            }
            if (evt.type === "sched_switch") ps.sched_preemptions++;
            if (evt.type === "io") {
              if (evt.io_op === "vfs_read")   ps.vfs_reads++;
              if (evt.io_op === "vfs_write")  ps.vfs_writes++;
              if (evt.io_op === "vfs_rename") ps.vfs_renames++;
            }
            if (evt.risk_score !== undefined) ps.risk_score = evt.risk_score;
            ps.comm         = evt.comm || ps.comm;
            ps.container_id = evt.container_id || ps.container_id;
            return { ...prev, [evt.pid]: { ...ps } };
          });

          const cid = evt.container_id || "host";
          setContainers(prev => {
            const c = prev[cid] || { container_id: cid, syscall_count: 0,
              vfs_writes: 0, vfs_renames: 0, max_risk: 0 };
            if (evt.type === "syscall")       c.syscall_count++;
            if (evt.io_op === "vfs_write")    c.vfs_writes++;
            if (evt.io_op === "vfs_rename")   c.vfs_renames++;
            if ((evt.risk_score || 0) > c.max_risk) c.max_risk = evt.risk_score;
            return { ...prev, [cid]: { ...c } };
          });
        }
      } catch (e) { /* skip malformed */ }
    };
  }, [url]);

  useEffect(() => { connect(); return () => wsRef.current?.close(); }, [connect]);

  return { events, processes, containers, schedEvents, connected };
}
