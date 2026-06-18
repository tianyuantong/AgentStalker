"""
AgentStalker Multi-layer Monitoring
===================================
7 层监控组件，捕获 Agent 行为的所有副效应：

1. network_monitor — 出/入站网络流量（含 DNS、TLS 握手、payload 抓取）
2. filesystem_monitor — 文件系统读写（敏感路径、写入模式）
3. process_monitor — 进程派生（shell、curl、bash）
4. llm_proxy — LLM 调用代理（LiteLLM wrapper）— 记录所有 prompt/response
5. memory_inspector — 长期记忆读写（Redis/Vector DB query log）
6. credential_monitor — 凭据访问（/etc/shadow, .aws, .ssh）
7. ebpf_runner — eBPF / Tracee 编排（系统调用级别）

每个组件输出统一格式的 Event：
{
    "timestamp": float,
    "layer": str,  # network | filesystem | process | llm | memory | credential | syscall
    "event_type": str,
    "actor": str,  # agent pid / container / process
    "target": str,
    "payload_preview": str,
    "verdict": "neutral" | "suspicious" | "malicious",
    "trace_id": str,
}
"""
from .network_monitor import NetworkMonitor
from .filesystem_monitor import FilesystemMonitor
from .process_monitor import ProcessMonitor
from .llm_proxy import LLMProxy
from .memory_inspector import MemoryInspector
from .credential_monitor import CredentialMonitor
from .ebpf_runner import EBPFRunner

__all__ = [
    "NetworkMonitor",
    "FilesystemMonitor",
    "ProcessMonitor",
    "LLMProxy",
    "MemoryInspector",
    "CredentialMonitor",
    "EBPFRunner",
]