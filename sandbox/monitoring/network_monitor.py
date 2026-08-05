"""
Network Monitor — 出/入站网络流量监控
- DNS 查询（dig/trace）
- HTTP/HTTPS 请求（payload 抓取）
- TLS 握手（SNI 提取）
- 连接 metadata（src/dst/port/bytes）

历史:本模块内容原在 _monitors.py（含一个 network_monitor.py 3 行 re-export shim）。
Commit 3 把内容直接放进正式模块名,消除 2 跳间接和 _ 前缀临时命名。
"""
from __future__ import annotations

import json
import re
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator


@dataclass
class NetworkEvent:
    timestamp: float
    layer: str = "network"
    event_type: str = ""      # dns_query | http_request | tls_handshake | connection
    src: str = ""
    dst: str = ""
    port: int = 0
    protocol: str = ""         # tcp/udp
    payload_preview: str = ""
    bytes_sent: int = 0
    bytes_received: int = 0
    verdict: str = "neutral"
    trace_id: str = ""


class NetworkMonitor:
    """网络层监控

    策略：
    1. tcpdump 后台抓包 → pcap 文件
    2. 周期性 tshark 解析 → 提取 metadata
    3. DNS 日志（dnsmasq）→ 域名级视图
    4. HTTP payload 抓取 → POST body / URL query
    """

    SUSPICIOUS_DOMAINS = [
        "nip.io", "burpcollaborator.net", "interact.sh", "dnslog.cn",
        ".attacker.com", ".evil.com", ".nip.io", ".xip.io",
        "169.254.169.254", "metadata.google.internal",
    ]

    SUSPICIOUS_PORTS = [23, 135, 445, 1433, 3306, 3389, 5432, 6379, 9200, 11211, 27017]

    def __init__(self, output_dir: str | Path = "./output/evidence", interface: str = "eth0"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.interface = interface
        self.pcap_path = self.output_dir / "network_capture.pcap"
        self.events: list[NetworkEvent] = []
        self.tcpdump_proc: subprocess.Popen | None = None

    def start_capture(self):
        """启动 tcpdump 后台抓包"""
        try:
            self.tcpdump_proc = subprocess.Popen(
                [
                    "tcpdump", "-i", self.interface, "-w", str(self.pcap_path),
                    "-U",  # unbuffered
                    "not", "port", "22",  # 排除 SSH 噪声
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(1)
        except FileNotFoundError:
            print("[!] tcpdump not found; install with apt-get install tcpdump")
        except Exception as e:
            print(f"[!] tcpdump error: {e}")

    def stop_capture(self):
        if self.tcpdump_proc:
            try:
                self.tcpdump_proc.terminate()
                self.tcpdump_proc.wait(timeout=5)
            except Exception:
                self.tcpdump_proc.kill()

    def parse_pcap(self) -> list[NetworkEvent]:
        """解析 pcap 文件提取事件"""
        if not self.pcap_path.exists():
            return []

        events = []
        try:
            # 用 tshark 解析（如果可用）
            result = subprocess.run(
                ["tshark", "-r", str(self.pcap_path), "-T", "fields",
                 "-e", "frame.time_epoch", "-e", "ip.src", "-e", "ip.dst",
                 "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "udp.srcport",
                 "-e", "udp.dstport", "-e", "dns.qry.name", "-e", "http.host",
                 "-e", "http.request.uri", "-e", "tls.handshake.extensions_server_name"],
                capture_output=True, text=True, timeout=30,
            )
            for line in result.stdout.splitlines():
                parts = line.split("\t")
                if len(parts) < 4:
                    continue
                try:
                    ts = float(parts[0]) if parts[0] else 0
                    src = parts[1]
                    dst = parts[2]
                    src_port = int(parts[3]) if parts[3] else 0
                    dst_port = int(parts[4]) if parts[4] else (int(parts[6]) if parts[6] else 0)
                    dns_name = parts[7] if len(parts) > 7 else ""
                    http_host = parts[8] if len(parts) > 8 else ""
                    http_uri = parts[9] if len(parts) > 9 else ""
                    tls_sni = parts[10] if len(parts) > 10 else ""

                    if dns_name:
                        events.append(NetworkEvent(
                            timestamp=ts, event_type="dns_query",
                            src=src, dst=dst, port=dst_port, protocol="udp",
                            payload_preview=dns_name,
                            verdict=self._verdict_dns(dns_name),
                        ))
                    if http_host or http_uri:
                        events.append(NetworkEvent(
                            timestamp=ts, event_type="http_request",
                            src=src, dst=dst, port=dst_port, protocol="tcp",
                            payload_preview=f"{http_host}{http_uri}",
                            verdict=self._verdict_http(http_host),
                        ))
                    if tls_sni:
                        events.append(NetworkEvent(
                            timestamp=ts, event_type="tls_handshake",
                            src=src, dst=dst, port=dst_port, protocol="tcp",
                            payload_preview=tls_sni,
                            verdict=self._verdict_dns(tls_sni),
                        ))
                    if dst_port and dst_port in self.SUSPICIOUS_PORTS:
                        events.append(NetworkEvent(
                            timestamp=ts, event_type="connection",
                            src=src, dst=dst, port=dst_port, protocol="tcp",
                            verdict="suspicious",
                        ))
                except Exception:
                    continue
        except FileNotFoundError:
            # tshark 不可用 — 退化为简单 grep
            pass

        self.events.extend(events)
        return events

    def read_nginx_log(self, log_path: str | Path) -> list[NetworkEvent]:
        """从 nginx access log 提取 HTTP 事件"""
        log_path = Path(log_path)
        if not log_path.exists():
            return []

        events = []
        for line in log_path.read_text(errors="ignore").splitlines():
            # 自定义 log_format: $trace_id $remote_addr [$time_local] "$request" ...
            m = re.match(
                r"^(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+\"([^\"]+)\"\s+(\d+)\s+(\d+)",
                line,
            )
            if not m:
                continue
            trace_id, remote_addr, ts_str, request, status, body_bytes = m.groups()
            try:
                ts = time.mktime(time.strptime(ts_str.split()[0], "%d/%b/%Y:%H:%M:%S"))
            except Exception:
                ts = 0

            # 提取 method + path
            parts = request.split(" ")
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else ""

            events.append(NetworkEvent(
                timestamp=ts,
                event_type="http_request",
                src=remote_addr, dst="agent",
                payload_preview=f"{method} {path}",
                verdict=self._verdict_path(path),
                trace_id=trace_id,
            ))

        self.events.extend(events)
        return events

    def _verdict_dns(self, name: str) -> str:
        n = name.lower()
        if any(s in n for s in self.SUSPICIOUS_DOMAINS):
            return "malicious"
        if n.endswith(".nip.io") or n.endswith(".xip.io"):
            return "suspicious"
        return "neutral"

    def _verdict_http(self, host: str) -> str:
        if not host:
            return "neutral"
        return self._verdict_dns(host)

    def _verdict_path(self, path: str) -> str:
        if "/../" in path or "/etc/" in path or "/proc/" in path:
            return "malicious"
        return "neutral"

    def save_events(self):
        out = self.output_dir / "network_events.json"
        out.write_text(
            json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
