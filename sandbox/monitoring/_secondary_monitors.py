"""
Memory Inspector + Credential Monitor + eBPF Runner
- 记忆读写监控（Redis/Vector DB/SQLite）
- 凭据访问监控
- Tracee eBPF 编排
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any


# ============ Memory Inspector ============
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


# ============ Credential Monitor ============
@dataclass
class CredentialEvent:
    timestamp: float
    layer: str = "credential"
    event_type: str = ""      # read | write | exfil
    path: str = ""
    actor_pid: int = 0
    actor_cmd: str = ""
    value_preview: str = ""
    verdict: str = "neutral"
    trace_id: str = ""


class CredentialMonitor:
    """凭据访问监控"""

    CREDENTIAL_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
        "/root/.bash_history", "/root/.aws/credentials",
        "/home/*/.ssh/id_rsa", "/home/*/.ssh/authorized_keys",
        "/home/*/.aws/credentials", "/home/*/.bash_history",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/proc/self/environ",
        ".env", "id_rsa", "*.pem", "*.key",
    ]

    def __init__(self, output_dir: str = "./output/evidence"):
        self.output_dir = output_dir
        self.events: list[CredentialEvent] = []

    def ingest_auditd_log(self, log_path: str | Path) -> list[CredentialEvent]:
        """从 auditd 日志识别凭据访问"""
        log = Path(log_path)
        if not log.exists():
            return []
        events = []
        for line in log.read_text(errors="ignore").splitlines():
            if "type=SYSCALL" not in line:
                continue
            # 解析 syscall + filename
            syscall = self._field(line, "syscall")
            if syscall not in ("2", "257", "open", "openat"):  # open/openat
                continue
            exe = self._field(line, "exe")
            if not exe or "python" not in exe.lower() and "node" not in exe.lower():
                continue
            # filename 通常在 PATH 字段
            # 简化：从 raw audit log 中找 path=...
            m = re.search(r'item=\d+ name="([^"]+)"', line)
            if not m:
                continue
            path = m.group(1)
            if not self._is_credential_path(path):
                continue
            events.append(CredentialEvent(
                timestamp=time.time(),
                event_type="read",
                path=path,
                actor_cmd=exe or "",
                verdict="malicious",
            ))
        self.events.extend(events)
        return events

    def _field(self, line: str, field: str) -> str | None:
        m = re.search(rf'{field}=("([^"]*)"|(\S+))', line)
        return (m.group(2) or m.group(3)) if m else None

    def _is_credential_path(self, path: str) -> bool:
        for cp in self.CREDENTIAL_PATHS:
            if Path(path).match(cp):
                return True
        return False

    def save_events(self):
        out = Path(self.output_dir) / "credential_events.json"
        out.write_text(json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False), encoding="utf-8")


# ============ eBPF Runner (Tracee) ============
class EBPFRunner:
    """eBPF / Tracee 编排器"""

    DEFAULT_EVENTS = [
        "security_sensitive_process_exec",
        "security_file_open",
        "security_socket_connect",
        "security_dns_request",
        "security_file_write",
        "sched_process_exec",
    ]

    def __init__(self, output_dir: str = "./output/evidence", tracee_container: str = "ast-tracee"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.container_name = tracee_container
        self.event_log = self.output_dir / "tracee-events.json"

    def start(self, events: list[str] | None = None, container_filter: str = ""):
        """启动 Tracee 监控"""
        events = events or self.DEFAULT_EVENTS
        filter_expr = ",".join(events)
        if container_filter:
            filter_expr = f"container={container_filter}"

        cmd = [
            "docker", "exec", self.container_name,
            "tracee", "--containers",
            "--output", f"json:{self.event_log.absolute()}",
            "--filter", filter_expr,
        ]
        try:
            subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            print(f"[!] Tracee start error: {e}")

    def stop(self):
        """停止 Tracee"""
        try:
            subprocess.run(["docker", "exec", self.container_name, "pkill", "tracee"],
                         capture_output=True, timeout=5)
        except Exception:
            pass

    def read_events(self) -> list[dict[str, Any]]:
        """读取事件"""
        if not self.event_log.exists():
            return []
        events = []
        for line in self.event_log.read_text(errors="ignore").splitlines():
            try:
                events.append(json.loads(line))
            except Exception:
                continue
        return events

    def filter_suspicious(self) -> list[dict[str, Any]]:
        """过滤可疑事件"""
        all_events = self.read_events()
        suspicious = []
        for evt in all_events:
            event_name = evt.get("event", "")
            if event_name in ("security_sensitive_process_exec", "security_dns_request"):
                suspicious.append(evt)
        return suspicious