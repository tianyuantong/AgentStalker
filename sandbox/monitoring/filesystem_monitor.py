"""
Filesystem Monitor — 文件系统读写监控
- inotifywait 实时监控
- 敏感路径访问（/etc/passwd, /etc/shadow, .ssh, .aws）
- 写入模式（zip slip、可执行文件）
"""
from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class FilesystemEvent:
    timestamp: float
    layer: str = "filesystem"
    event_type: str = ""     # read | write | create | delete | modify | chmod
    path: str = ""
    actor_pid: int = 0
    actor_cmd: str = ""
    bytes: int = 0
    verdict: str = "neutral"  # neutral | suspicious | malicious
    trace_id: str = ""


class FilesystemMonitor:
    """文件系统监控"""

    SENSITIVE_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/",
        "/etc/ssh/sshd_config", "/etc/crontab", "/var/spool/cron/",
        "/proc/self/environ", "/proc/net/", "/proc/*/cmdline",
        "/root/", "/home/*/.ssh/", "/home/*/.aws/",
        "/var/run/secrets/", "/var/lib/kubelet/",
        "/.env", "/.git/", "/.docker/",
    ]

    EXECUTABLE_WRITE_PATHS = [
        "/tmp/", "/var/tmp/", "/dev/shm/",
    ]

    ZIP_SLIP_PATTERNS = [
        r"\.\./\.\./",
        r"\.\.\\\.\.\\",
    ]

    def __init__(self, output_dir: str | Path = "./output/evidence", watch_paths: list[str] | None = None):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.watch_paths = watch_paths or ["/tmp", "/etc", "/home", "/root", "/var/log"]
        self.events: list[FilesystemEvent] = []
        self.inotify_proc: subprocess.Popen | None = None

    def start(self):
        """启动 inotifywait 后台监控"""
        try:
            self.inotify_proc = subprocess.Popen(
                [
                    "inotifywait", "-m", "-r", "--format",
                    "%T %w%f %e",
                    "--timefmt", "%s",
                ] + self.watch_paths,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            # 在另一线程中消费输出
            import threading
            t = threading.Thread(target=self._consume, daemon=True)
            t.start()
        except FileNotFoundError:
            print("[!] inotifywait not found; install with apt-get install inotify-tools")

    def _consume(self):
        """消费 inotifywait 输出"""
        if not self.inotify_proc or not self.inotify_proc.stdout:
            return
        for line in self.inotify_proc.stdout:
            parts = line.strip().split(" ", 2)
            if len(parts) < 3:
                continue
            try:
                ts = float(parts[0])
                path = parts[1]
                events = parts[2].split(",")
                for evt in events:
                    self.events.append(FilesystemEvent(
                        timestamp=ts,
                        event_type=evt.lower(),
                        path=path,
                        verdict=self._verdict(path, evt),
                    ))
            except Exception:
                continue

    def stop(self):
        if self.inotify_proc:
            try:
                self.inotify_proc.terminate()
                self.inotify_proc.wait(timeout=5)
            except Exception:
                self.inotify_proc.kill()

    def ingest_audit_log(self, audit_log_path: str | Path) -> list[FilesystemEvent]:
        """从 auditd 日志读取 syscall 事件

        auditd 配置示例：
        auditctl -w /etc -p wa -k etc_changes
        auditctl -w /home -p r -k home_reads
        """
        log_path = Path(audit_log_path)
        if not log_path.exists():
            return []

        events = []
        for line in log_path.read_text(errors="ignore").splitlines():
            # 解析 auditd 格式：
            # type=SYSCALL ... uid=0 auid=1000 ... exe="/usr/bin/python3" ... key="etc_changes"
            if "type=SYSCALL" not in line:
                continue
            try:
                # 提取关键字段
                ts_match = self._audit_field(line, "msg")
                exe_match = self._audit_field(line, "exe")
                syscall_match = self._audit_field(line, "syscall")
                key_match = self._audit_field(line, "key")
                # ... (简化)
                events.append(FilesystemEvent(
                    timestamp=time.time(),
                    event_type=syscall_match or "unknown",
                    actor_cmd=exe_match or "",
                    verdict=self._verdict_audit(key_match),
                ))
            except Exception:
                continue

        self.events.extend(events)
        return events

    def _audit_field(self, line: str, field: str) -> str | None:
        m = re.search(rf'{field}=("([^"]*)"|(\S+))', line)
        if not m:
            return None
        return m.group(2) or m.group(3)

    def _verdict(self, path: str, event: str) -> str:
        # 敏感路径访问
        for sp in self.SENSITIVE_PATHS:
            if Path(path).match(sp) or sp.rstrip("/") in path:
                if event in ("OPEN", "ACCESS", "MODIFY", "READ"):
                    return "malicious"
                return "suspicious"
        # 可执行目录写入
        if event in ("CREATE", "MODIFY", "MOVED_TO"):
            for ep in self.EXECUTABLE_WRITE_PATHS:
                if path.startswith(ep):
                    return "suspicious"
        # Zip slip 模式
        for pat in self.ZIP_SLIP_PATTERNS:
            if re.search(pat, path):
                return "malicious"
        return "neutral"

    def _verdict_audit(self, key: str | None) -> str:
        if not key:
            return "neutral"
        if any(k in key for k in ["etc_changes", "passwd_read", "shadow_read", "ssh_read"]):
            return "malicious"
        if "home_reads" in key or "tmp_writes" in key:
            return "suspicious"
        return "neutral"

    def save_events(self):
        out = self.output_dir / "filesystem_events.json"
        out.write_text(
            json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )


import re