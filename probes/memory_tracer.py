#!/usr/bin/env python3
"""
OSmosis - Memory Tracer (Enhanced)
- Page faults with latency measurement (kprobe entry + kretprobe exit)
- Minor vs major fault classification (>1ms = major, requires disk I/O)
- kmem page allocation vs free tracking (delta = memory leak detector)
- mmap syscall tracing

Run: sudo python3 probes/memory_tracer.py 2>/dev/null | head -20
"""

from bcc import BPF
import ctypes, json, time, sys

EBPF_PROG = r"""
#include <uapi/linux/ptrace.h>
#include <linux/mm.h>

// Latency tracking: store entry timestamp keyed by TID
BPF_HASH(fault_start, u32, u64);

struct mem_event_t {
    u32  pid;
    u64  cgroup_id;
    char comm[TASK_COMM_LEN];
    u8   event_type;   // 0=page_fault, 1=mmap, 2=page_alloc, 3=page_free
    u64  address;
    u64  latency_ns;   // Only valid for event_type=0
    u8   is_major;     // 1 if latency > 1ms
    u64  timestamp_ns;
};

BPF_PERF_OUTPUT(mem_events);

// Record entry time for page fault latency measurement
int kprobe__handle_mm_fault(struct pt_regs *ctx, struct vm_area_struct *vma,
                             unsigned long address, unsigned int flags) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 ts  = bpf_ktime_get_ns();
    fault_start.update(&tid, &ts);
    return 0;
}

// Measure latency on return — classify major vs minor
int kretprobe__handle_mm_fault(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *start_ts = fault_start.lookup(&tid);
    if (!start_ts) return 0;

    u64 latency = bpf_ktime_get_ns() - *start_ts;
    fault_start.delete(&tid);

    struct mem_event_t evt = {};
    evt.pid          = tid;
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    evt.event_type   = 0;
    evt.latency_ns   = latency;
    evt.is_major     = latency > 1000000 ? 1 : 0;  // >1ms = major
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    mem_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// mmap syscall
TRACEPOINT_PROBE(syscalls, sys_enter_mmap) {
    struct mem_event_t evt = {};
    evt.pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    evt.event_type   = 1;
    evt.address      = args->addr;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    mem_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// Page allocation (kmem tracepoint) — for leak detection
TRACEPOINT_PROBE(kmem, mm_page_alloc) {
    struct mem_event_t evt = {};
    evt.pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    evt.event_type   = 2;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    mem_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

// Page free — paired with alloc to detect growing delta (memory leak)
TRACEPOINT_PROBE(kmem, mm_page_free) {
    struct mem_event_t evt = {};
    evt.pid          = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    evt.event_type   = 3;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    mem_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

EVENT_NAMES = {0: "page_fault", 1: "mmap", 2: "page_alloc", 3: "page_free"}

class MemEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("cgroup_id",    ctypes.c_uint64),
        ("comm",         ctypes.c_char * 16),
        ("event_type",   ctypes.c_uint8),
        ("address",      ctypes.c_uint64),
        ("latency_ns",   ctypes.c_uint64),
        ("is_major",     ctypes.c_uint8),
        ("timestamp_ns", ctypes.c_uint64),
    ]

bpf = BPF(text=EBPF_PROG)

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(MemEvent)).contents
    record = {
        "type":        "memory",
        "pid":         evt.pid,
        "cgroup_id":   evt.cgroup_id,
        "comm":        evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "mem_event":   EVENT_NAMES.get(evt.event_type, "unknown"),
        "address_hex": hex(evt.address),
        "latency_ns":  evt.latency_ns,
        "is_major":    bool(evt.is_major),
        "ts_ns":       evt.timestamp_ns,
        "ts_s":        time.time(),
    }
    print(json.dumps(record), flush=True)

bpf["mem_events"].open_perf_buffer(handle_event, page_cnt=256)
print("[OSmosis] Memory tracer active (latency + kmem tracking).", file=sys.stderr)

while True:
    try:
        bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        break
