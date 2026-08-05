"""
eBPF Runner — Tracee 编排
- 在 docker 容器里跑 Tracee,捕获 security_* syscall 事件
- 过滤可疑事件（敏感进程执行、DNS 请求）

历史:原在 _secondary_monitors.py。Commit 3 拆成独立模块(修 C1)。
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


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
