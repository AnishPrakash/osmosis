#!/usr/bin/env python3
"""
OSmosis - VFS/IO Tracer
Hooks into vfs_read, vfs_write, vfs_open, vfs_rename at the VFS layer.

WHY VFS LAYER (not syscall layer, not block layer):
- Syscall layer: write() → kernel may batch and defer to kworker async flush.
  kworker attribution is lost (you can't tell which process caused the write).
- Block layer: block:block_rq_issue shows the actual disk write but it's done
  by kworker — the original PID is gone.
- VFS layer: synchronous, attributed to the originating PID. Perfect for
  ransomware fingerprinting (vfs_write + vfs_rename burst from one PID).

Run: sudo python3 probes/io_tracer.py 2>/dev/null | head -20
"""

from bcc import BPF
import ctypes, json, time, sys

EBPF_PROG = r"""
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>

BPF_HASH(io_start, u32, u64);

struct io_event_t {
    u32  pid;
    u64  cgroup_id;
    char comm[TASK_COMM_LEN];
    u8   op;         // 0=read, 1=write, 2=open, 3=rename
    s64  bytes;
    u64  latency_ns;
    u64  timestamp_ns;
};

BPF_PERF_OUTPUT(io_events);

// vfs_read
int kprobe__vfs_read(struct pt_regs *ctx, struct file *file,
                     char __user *buf, size_t count, loff_t *pos) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 ts  = bpf_ktime_get_ns();
    io_start.update(&tid, &ts);
    return 0;
}

int kretprobe__vfs_read(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *start = io_start.lookup(&tid);
    if (!start) return 0;
    u64 latency = bpf_ktime_get_ns() - *start;
    io_start.delete(&tid);
    s64 ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    struct io_event_t evt = {};
    evt.pid = tid; evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.op = 0; evt.bytes = ret; evt.latency_ns = latency;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    io_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// vfs_write
int kprobe__vfs_write(struct pt_regs *ctx, struct file *file,
                      const char __user *buf, size_t count, loff_t *pos) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 ts  = bpf_ktime_get_ns();
    io_start.update(&tid, &ts);
    return 0;
}

int kretprobe__vfs_write(struct pt_regs *ctx) {
    u32 tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    u64 *start = io_start.lookup(&tid);
    if (!start) return 0;
    u64 latency = bpf_ktime_get_ns() - *start;
    io_start.delete(&tid);
    s64 ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;
    struct io_event_t evt = {};
    evt.pid = tid; evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.op = 1; evt.bytes = ret; evt.latency_ns = latency;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    io_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// vfs_open
int kprobe__vfs_open(struct pt_regs *ctx) {
    struct io_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.op = 2; evt.bytes = 0;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    io_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// vfs_rename — ransomware's primary signature (open → encrypt → rename)
int kprobe__vfs_rename(struct pt_regs *ctx) {
    struct io_event_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt.cgroup_id = bpf_get_current_cgroup_id();
    evt.op = 3; evt.bytes = 0;
    evt.timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    io_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

OP_NAMES = {0: "vfs_read", 1: "vfs_write", 2: "vfs_open", 3: "vfs_rename"}

class IOEvent(ctypes.Structure):
    _fields_ = [
        ("pid",          ctypes.c_uint32),
        ("cgroup_id",    ctypes.c_uint64),
        ("comm",         ctypes.c_char * 16),
        ("op",           ctypes.c_uint8),
        ("bytes",        ctypes.c_int64),
        ("latency_ns",   ctypes.c_uint64),
        ("timestamp_ns", ctypes.c_uint64),
    ]

bpf = BPF(text=EBPF_PROG)

def handle_event(cpu, data, size):
    evt = ctypes.cast(data, ctypes.POINTER(IOEvent)).contents
    record = {
        "type":       "io",
        "pid":        evt.pid,
        "cgroup_id":  evt.cgroup_id,
        "comm":       evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "io_op":      OP_NAMES.get(evt.op, "unknown"),
        "bytes":      evt.bytes,
        "latency_ns": evt.latency_ns,
        "ts_ns":      evt.timestamp_ns,
        "ts_s":       time.time(),
    }
    print(json.dumps(record), flush=True)

bpf["io_events"].open_perf_buffer(handle_event, page_cnt=512)
print("[OSmosis] VFS/IO tracer active (read/write/open/rename).", file=sys.stderr)

while True:
    try:
        bpf.perf_buffer_poll(timeout=100)
    except KeyboardInterrupt:
        break
