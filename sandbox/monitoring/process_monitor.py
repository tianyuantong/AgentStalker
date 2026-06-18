"""
Process Monitor — 进程派生监控
- fork/execve 系统调用
- shell 派生 (/bin/sh, /bin/bash, cmd.exe)
- 网络工具 (curl, wget, nc)
- 加密挖矿 (xmrig, minerd)
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path


@dataclass
class ProcessEvent:
    timestamp: float
    layer: str = "process"
    event_type: str = ""    # fork | exec | exit | signal
    pid: int = 0
    ppid: int = 0
    cmd: str = ""
    argv: list[str] = field(default_factory=list)
    user: str = ""
    verdict: str = "neutral"
    trace_id: str = ""


class ProcessMonitor:
    """进程监控"""

    SHELL_PATTERNS = [
        r"/bin/sh$", r"/bin/bash$", r"/bin/zsh$", r"/bin/dash$",
        r"sh$", r"bash$", r"cmd\.exe$", r"powershell",
        r"pwsh", r"/usr/bin/env\s+(sh|bash|python|node|ruby|perl)",
    ]

    NETWORK_TOOLS = [
        "curl", "wget", "nc", "netcat", "ncat", "telnet", "ssh", "scp",
        "rsync", "ftp", "tftp", "smbclient", "rpcclient",
    ]

    CRYPTO_MINERS = [
        "xmrig", "minerd", "cpuminer", "ethminer", "cgminer",
        "bfgminer", "minergate", "nicehash",
    ]

    SUSPICIOUS_PATTERNS = [
        r"bash\s+-i",
        r"/dev/tcp/",
        r"nc\s+-e",
        r"curl\s+.*\s*\|\s*(sh|bash)",
        r"wget\s+.*\s*\|\s*(sh|bash)",
        r"python\s+-c.*exec",
        r"perl\s+-e",
    ]

    def __init__(self, output_dir: str | Path = "./output/evidence"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.events: list[ProcessEvent] = []

    def ingest_tracee_events(self, tracee_log: str | Path) -> list[ProcessEvent]:
        """从 Tracee JSON 输出解析进程事件"""
        log_path = Path(tracee_log)
        if not log_path.exists():
            return []

        events = []
        for line in log_path.read_text(errors="ignore").splitlines():
            try:
                evt = json.loads(line)
                # Tracee 事件格式：
                # {"timestamp": ..., "process": {"pid": ..., "ppid": ..., "executable": ..., "arguments": ...},
                #  "event": "security_sensitive_process_exec", ...}
                proc = evt.get("process", {})
                event_name = evt.get("event", "")

                if event_name in ("security_sensitive_process_exec",
                                  "process_execute_failed",
                                  "sched_process_exec"):
                    argv = proc.get("arguments", [])
                    cmd = proc.get("executable", "")
                    events.append(ProcessEvent(
                        timestamp=evt.get("timestamp", time.time()),
                        event_type="exec",
                        pid=proc.get("pid", 0),
                        ppid=proc.get("ppid", 0),
                        cmd=cmd,
                        argv=argv if isinstance(argv, list) else [str(argv)],
                        user=proc.get("uid", 0),
                        verdict=self._verdict(cmd, argv),
                    ))
            except Exception:
                continue

        self.events.extend(events)
        return events

    def poll_processes(self, agent_pid: int = 0, interval: int = 1) -> list[ProcessEvent]:
        """通过 ps 轮询进程（fallback）"""
        events = []
        try:
            result = subprocess.run(
                ["ps", "-eo", "pid,ppid,user,cmd", "--no-headers"],
                capture_output=True, text=True, timeout=5,
            )
            for line in result.stdout.splitlines():
                parts = line.split(None, 3)
                if len(parts) < 4:
                    continue
                try:
                    pid = int(parts[0])
                    ppid = int(parts[1])
                except ValueError:
                    continue
                user = parts[2]
                cmd = parts[3]
                if agent_pid and pid != agent_pid and ppid != agent_pid:
                    continue
                events.append(ProcessEvent(
                    timestamp=time.time(),
                    event_type="exec",
                    pid=pid, ppid=ppid, cmd=cmd,
                    argv=cmd.split(),
                    user=user,
                    verdict=self._verdict(cmd, cmd.split()),
                ))
        except Exception:
            pass
        return events

    def _verdict(self, cmd: str, argv: list[str]) -> str:
        cmd_lower = cmd.lower()
        argv_str = " ".join(argv).lower()

        # shell 派生
        for pat in self.SHELL_PATTERNS:
            if re.search(pat, cmd_lower):
                # 评估是否含 suspicious 模式
                if any(re.search(p, argv_str) for p in self.SUSPICIOUS_PATTERNS):
                    return "malicious"
                return "suspicious"

        # 挖矿
        for m in self.CRYPTO_MINERS:
            if m in cmd_lower:
                return "malicious"

        # 网络工具（除 curl/wget 之外）
        for tool in self.NETWORK_TOOLS:
            if cmd_lower.endswith(f"/{tool}") or cmd_lower == tool:
                if tool in ("ssh", "scp"):
                    return "neutral"  # SSH 是合法操作
                return "suspicious"

        return "neutral"

    def save_events(self):
        out = self.output_dir / "process_events.json"
        out.write_text(
            json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )