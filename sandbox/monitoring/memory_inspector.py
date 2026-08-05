"""
Memory Inspector — 长期记忆读写监控
- Redis MONITOR / Qdrant/Chroma log / SQLite WAL 解析
- 跨用户记忆污染、不可信数据写入长期记忆、记忆投毒检测

历史:原在 _secondary_monitors.py(与 CredentialMonitor/EBPFRunner 混在一起)。
Commit 3 拆成独立模块,使 monitoring/__init__.py 的 import 路径成立(原 C1 bug)。
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class MemoryEvent:
    timestamp: float
    layer: str = "memory"
    event_type: str = ""      # read | write | update | delete
    backend: str = ""         # redis | qdrant | chroma | postgres | sqlite
    key: str = ""
    value_preview: str = ""
    user_id: str = ""
    verdict: str = "neutral"  # neutral | suspicious | malicious
    trace_id: str = ""


class MemoryInspector:
    """记忆读写监控

    通过监听 Agent 的记忆后端来检测：
    - 跨用户记忆污染
    - 不可信数据写入长期记忆
    - 记忆投毒（preference 注入）
    """

    POISON_KEYWORDS = [
        "ignore previous", "preference:", "always cc", "all transactions",
        "bypass", "admin", "trusted sender",
    ]

    def __init__(self, output_dir: str = "./output/evidence"):
        self.output_dir = output_dir
        self.events: list[MemoryEvent] = []

    def ingest_redis_monitor(self, log_path: str | Path) -> list[MemoryEvent]:
        """从 Redis MONITOR 输出解析"""
        events = []
        log = Path(log_path)
        if not log.exists():
            return []

        for line in log.read_text(errors="ignore").splitlines():
            # MONITOR 输出格式: timestamp [db id addr] "command" "key" ...
            m = re.match(
                r"^[\d.]+\s+\[\d+\s+\S+\]\s+\"(\w+)\"\s+\"([^\"]+)\"(.*)$",
                line,
            )
            if not m:
                continue
            cmd, key, rest = m.groups()
            evt = MemoryEvent(
                timestamp=time.time(),
                backend="redis",
                event_type=cmd.lower(),
                key=key,
                value_preview=rest[:500],
                verdict=self._verdict(key, rest),
            )
            events.append(evt)

        self.events.extend(events)
        return events

    def ingest_vector_db_log(self, log_path: str | Path) -> list[MemoryEvent]:
        """从 Qdrant / Chroma / Weaviate log 解析"""
        log = Path(log_path)
        if not log.exists():
            return []
        events = []
        for line in log.read_text(errors="ignore").splitlines():
            try:
                entry = json.loads(line)
                # Qdrant 格式：{"time": ..., "operation": "upsert", "collection": "...", "payload": {...}}
                op = entry.get("operation", "")
                if op not in ("upsert", "delete", "search", "scroll"):
                    continue
                events.append(MemoryEvent(
                    timestamp=entry.get("time", time.time()),
                    backend="qdrant",
                    event_type=op,
                    key=entry.get("collection", ""),
                    value_preview=json.dumps(entry.get("payload", {}))[:500],
                    verdict=self._verdict("", json.dumps(entry.get("payload", {}))),
                ))
            except Exception:
                continue
        self.events.extend(events)
        return events

    def ingest_sqlite_wal(self, db_path: str | Path) -> list[MemoryEvent]:
        """从 SQLite WAL 解析"""
        db_path = Path(db_path)
        if not db_path.exists():
            return []

        events = []
        try:
            result = subprocess.run(
                ["sqlite3", str(db_path), ".dump"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if line.startswith("INSERT INTO") or line.startswith("UPDATE"):
                    events.append(MemoryEvent(
                        timestamp=time.time(),
                        backend="sqlite",
                        event_type="write",
                        key=line[:100],
                        value_preview=line[:500],
                    ))
        except Exception:
            pass
        self.events.extend(events)
        return events

    def _verdict(self, key: str, value: str) -> str:
        text = (key + " " + value).lower()
        if any(k in text for k in self.POISON_KEYWORDS):
            return "malicious"
        return "neutral"

    def save_events(self):
        out = Path(self.output_dir) / "memory_events.json"
        out.write_text(json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False), encoding="utf-8")
