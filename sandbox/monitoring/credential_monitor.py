"""
Credential Monitor — 凭据访问监控
- 解析 auditd 日志识别 /etc/shadow, .aws/credentials, .ssh/id_rsa 等敏感路径访问
- actor 进程识别（python/node exe）

历史:原在 _secondary_monitors.py。Commit 3 拆成独立模块(修 C1)。
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path


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
