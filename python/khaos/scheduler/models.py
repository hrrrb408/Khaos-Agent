"""Cron-like scheduled task models."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class TaskStatus(Enum):
    """Scheduled task lifecycle."""

    PENDING = "pending"      # 已创建，等待首次执行
    RUNNING = "running"      # 正在执行
    PAUSED = "paused"        # 用户暂停
    COMPLETED = "completed"  # 一次性任务已完成
    FAILED = "failed"        # 执行失败
    CANCELLED = "cancelled"  # 用户取消


@dataclass
class ScheduleConfig:
    """调度配置。"""

    # cron 表达式（分 时 日 月 星期），或 ISO 时间戳（一次性），或间隔字符串
    cron: Optional[str] = None
    iso_time: Optional[str] = None      # 一次性，ISO 8601
    interval_seconds: Optional[int] = None  # 固定间隔
    repeat: Optional[int] = None         # 最大重复次数，None = 无限


@dataclass
class ScheduledTask:
    """一个定时任务。"""

    id: Optional[str]
    name: str
    prompt: str                         # 执行时的 prompt
    status: TaskStatus = TaskStatus.PENDING
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    run_count: int = 0
    last_result: Optional[str] = None
    error: Optional[str] = None
    deliver_to: str = "local"           # local | session:<id> | all
    enabled: bool = True
    meta: dict = field(default_factory=dict)  # 额外元数据
    # HIGH-3 (batch 3.1.8): durable lifecycle version for optimistic
    # concurrency on terminal-state writes.  Control operations
    # (pause / remove / resume) unconditionally increment this; the
    # executor's terminal write is conditional on the version it
    # captured at start — if a control operation bumped the version,
    # the executor's UPDATE matches 0 rows and the stale write is
    # discarded.  This is the durable equivalent of the in-memory
    # ``_execution_epoch`` fence: the in-memory fence prevents the
    # executor from overwriting the in-memory desired state, and the
    # lifecycle_version prevents the executor from overwriting the DB
    # desired state (which matters across process restarts).
    lifecycle_version: int = 0
