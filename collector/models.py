"""
OSmosis - Pydantic event schemas
All events flowing through the collector are validated against these models.
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from enum import Enum

class EventType(str, Enum):
    SYSCALL      = "syscall"
    SCHED_SWITCH = "sched_switch"
    MEMORY       = "memory"
    IO           = "io"
    CGROUP_MAP   = "cgroup_map"

class BaseEvent(BaseModel):
    type:         EventType
    pid:          Optional[int] = None
    comm:         Optional[str] = None
    cgroup_id:    Optional[int] = None
    container_id: Optional[str] = "host"
    ts_ns:        Optional[int] = None
    ts_s:         Optional[float] = None
    risk_score:   Optional[float] = 0.0

class SyscallEvent(BaseEvent):
    type:       Literal[EventType.SYSCALL] = EventType.SYSCALL
    tgid:       Optional[int] = None
    syscall_id: Optional[int] = None
    syscall:    Optional[str] = None

class SchedEvent(BaseEvent):
    type:        Literal[EventType.SCHED_SWITCH] = EventType.SCHED_SWITCH
    prev_pid:    Optional[int] = None
    prev_comm:   Optional[str] = None
    next_pid:    Optional[int] = None
    next_comm:   Optional[str] = None
    prev_prio:   Optional[int] = None
    next_prio:   Optional[int] = None
    cpu:         Optional[int] = None

class MemoryEvent(BaseEvent):
    type:       Literal[EventType.MEMORY] = EventType.MEMORY
    mem_event:  Optional[str] = None   # page_fault, mmap, page_alloc, page_free
    address_hex: Optional[str] = None
    latency_ns: Optional[int] = None
    is_major:   Optional[bool] = False

class IOEvent(BaseEvent):
    type:       Literal[EventType.IO] = EventType.IO
    io_op:      Optional[str] = None   # vfs_read, vfs_write, vfs_open, vfs_rename
    bytes:      Optional[int] = None
    latency_ns: Optional[int] = None

class ProcessSummary(BaseModel):
    pid:               int
    comm:              str
    container_id:      str = "host"
    cgroup_id:         int = 0
    syscall_count:     int = 0
    page_faults:       int = 0
    major_faults:      int = 0
    sched_preemptions: int = 0
    vfs_reads:         int = 0
    vfs_writes:        int = 0
    vfs_renames:       int = 0
    page_allocs:       int = 0
    page_frees:        int = 0
    write_count:       int = 0
    open_count:        int = 0
    fork_count:        int = 0
    mmap_count:        int = 0
    syscall_diversity: int = 0
    risk_score:        float = 0.0

class AnomalyAlert(BaseModel):
    pid:          int
    comm:         str
    container_id: str
    risk_score:   float
    ts_s:         float
    reason:       str = ""
