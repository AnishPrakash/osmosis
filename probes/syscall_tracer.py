#!/usr/bin/env python3
"""
OSmosis - Syscall Tracer
Hooks into raw_syscalls:sys_enter tracepoint via eBPF.
Emits JSON per syscall invocation with cgroup context for container attribution.

Run: sudo python3 probes/syscall_tracer.py 2>/dev/null | head -20
"""

from bcc import BPF
import ctypes, json, time, sys

EBPF_PROG = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct syscall_event_t {
    u32  pid;
    u32  tgid;
    u64  cgroup_id;
    char comm[TASK_COMM_LEN];
    s64  syscall_id;
    u64  timestamp_ns;
};

BPF_PERF_OUTPUT(syscall_events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u32 pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    struct syscall_event_t evt = {};
    evt.pid          = pid;
    evt.tgid         = bpf_get_current_pid_tgid() >> 32;
    evt.syscall_id   = args->id;
    evt.timestamp_ns = bpf_ktime_get_ns();
    evt.cgroup_id    = bpf_get_current_cgroup_id();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    syscall_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""

class SyscallEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("tgid",         ctypes.c_uint32),
        ("cgroup_id",    ctypes.c_uint64),
        ("comm",         ctypes.c_char * 16),
        ("syscall_id",   ctypes.c_int64),
        ("timestamp_ns", ctypes.c_uint64),
    ]

# Linux x86_64 syscall table (partial)
SYSCALL_NAMES = {
    0: "read", 1: "write", 2: "open", 3: "close", 4: "stat",
    5: "fstat", 8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
    12: "brk", 21: "access", 56: "clone", 57: "fork", 58: "vfork",
    59: "execve", 60: "exit", 61: "wait4", 62: "kill", 257: "openat",
    231: "exit_group", 318: "getrandom", 302: "prlimit64",
}

def get_syscall_name(sid):
    return SYSCALL_NAMES.get(sid, f"syscall_{sid}")

bpf = BPF(text=EBPF_PROG)

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(SyscallEvent)).contents
    record = {
        "type":       "syscall",
        "pid":        evt.pid,
        "tgid":       evt.tgid,
        "cgroup_id":  evt.cgroup_id,
        "comm":       evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "syscall_id": evt.syscall_id,
        "syscall":    get_syscall_name(evt.syscall_id),
        "ts_ns":      evt.timestamp_ns,
        "ts_s":       time.time(),
    }
    print(json.dumps(record), flush=True)

bpf["syscall_events"].open_perf_buffer(handle_event, page_cnt=256)
print("[OSmosis] Syscall tracer active. Ctrl+C to stop.", file=sys.stderr)

while True:
    try:
        bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        break
