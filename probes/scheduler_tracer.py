#!/usr/bin/env python3
"""
OSmosis - Scheduler Tracer
Hooks into sched:sched_switch — fires on every CPU context switch.
This reveals the ACTUAL Linux CFS scheduler decisions in nanosecond resolution.
Data feeds the SchedulerTimeline Gantt chart in the React dashboard.

Run: sudo python3 probes/scheduler_tracer.py 2>/dev/null | head -20
"""

from bcc import BPF
import ctypes, json, time, sys

EBPF_PROG = r"""
#include <linux/sched.h>

struct sched_event_t {
    u32  prev_pid;
    u32  next_pid;
    u64  cgroup_id;
    char prev_comm[TASK_COMM_LEN];
    char next_comm[TASK_COMM_LEN];
    s32  prev_prio;
    s32  next_prio;
    u64  timestamp_ns;
    u32  cpu;
};

BPF_PERF_OUTPUT(sched_events);

TRACEPOINT_PROBE(sched, sched_switch) {
    struct sched_event_t evt = {};
    evt.prev_pid     = args->prev_pid;
    evt.next_pid     = args->next_pid;
    evt.prev_prio    = args->prev_prio;
    evt.next_prio    = args->next_prio;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.cpu          = bpf_get_smp_processor_id();
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    __builtin_memcpy(evt.prev_comm, args->prev_comm, TASK_COMM_LEN);
    __builtin_memcpy(evt.next_comm, args->next_comm, TASK_COMM_LEN);
    sched_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

class SchedEvent(ctypes.Structure):
    _fields_ = [
        ("prev_pid",     ctypes.c_uint32),
        ("next_pid",     ctypes.c_uint32),
        ("cgroup_id",    ctypes.c_uint64),
        ("prev_comm",    ctypes.c_char * 16),
        ("next_comm",    ctypes.c_char * 16),
        ("prev_prio",    ctypes.c_int32),
        ("next_prio",    ctypes.c_int32),
        ("timestamp_ns", ctypes.c_uint64),
        ("cpu",          ctypes.c_uint32),
    ]

bpf = BPF(text=EBPF_PROG)

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(SchedEvent)).contents
    record = {
        "type":       "sched_switch",
        "prev_pid":   evt.prev_pid,
        "prev_comm":  evt.prev_comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "next_pid":   evt.next_pid,
        "next_comm":  evt.next_comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "prev_prio":  evt.prev_prio,
        "next_prio":  evt.next_prio,
        "cpu":        evt.cpu,
        "cgroup_id":  evt.cgroup_id,
        "ts_ns":      evt.timestamp_ns,
        "ts_s":       time.time(),
    }
    print(json.dumps(record), flush=True)

bpf["sched_events"].open_perf_buffer(handle_event, page_cnt=256)
print("[OSmosis] Scheduler tracer active.", file=sys.stderr)

while True:
    try:
        bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        break
