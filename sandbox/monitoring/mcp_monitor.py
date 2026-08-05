"""
MCP Monitor — MCP (Model Context Protocol) 行为监控

Commit 9 完整实现(Commit 3 仅骨架)。通过 MCPExecutor 驱动被测 MCP server,
产生 MCP 行为事件,供 VerdictEngine R009-R011 判定。

工作流:
1. 启动 server(MCPExecutor 握手)
2. tools/list 拿真实工具表(运行时权威,补静态抽取盲区)
3. 比对 local_tool_names 检测 squatting → 事件 mcp.tool_squatting
4. 扫描 description 检测投毒 → 事件 mcp.description_poisoning
5. 对每个工具 tools/call,捕获响应检测注入 → 事件 mcp.response_injection
   (token passthrough 由静态层 MCPAuditor 检测,本层补充运行时确认)

注:本 monitor 不直接 spawn server —— MCPExecutor 负责进程管理。
本 monitor 接收一个已配好的 MCPExecutor 或 server_command,做审计逻辑。
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path

# 复用静态层的检测正则(保持单一真相源)
from core.mcp_auditor import SUSPICIOUS_DESCRIPTION_PATTERNS


@dataclass
class MCPEvent:
    """MCP 行为事件（与 NetworkEvent/MemoryEvent 同构）"""
    timestamp: float
    layer: str = "mcp"
    event_type: str = ""        # tool_squatting | description_poisoning | token_passthrough | response_injection
    server_name: str = ""
    tool_name: str = ""
    payload_preview: str = ""
    evidence: str = ""          # 命中的具体证据(供 VerdictEngine 参考)
    verdict: str = "neutral"    # neutral | suspicious | malicious
    trace_id: str = ""


class MCPMonitor:
    """MCP 行为监控

    用法:
        mon = MCPMonitor()
        events = mon.inspect_server(
            server_command="python -m testbeds.mcp_mini_server.server",
            local_tool_names=["read_file", "search"],  # agent 的本地工具名
        )
        # events 可直接喂给 EvidenceBuilder.build(mcp_events=events)
    """

    def __init__(self, output_dir: str = "./output/evidence"):
        self.output_dir = output_dir
        self.events: list[MCPEvent] = []

    def inspect_server(
        self,
        server_command: str | list[str],
        local_tool_names: list[str] | None = None,
        probe_tools: bool = True,
    ) -> list[MCPEvent]:
        """驱动一个 MCP server 并产生审计事件。

        Args:
            server_command: 启动命令(str 或 list),如 "python server.py"
            local_tool_names: agent 本地工具名列表(用于 squatting 比对)
            probe_tools: 是否对每个工具做 tools/call 探测响应注入
        Returns: MCPEvent 列表
        """
        local_tool_names = local_tool_names or []
        events: list[MCPEvent] = []

        # 延迟 import 避免循环(MCPExecutor 在 sandbox.executors)
        from sandbox.executors.mcp import MCPExecutor

        executor = MCPExecutor(mcp_command=server_command)
        try:
            # 1. 拿真实工具表
            tools = executor.list_tools()
            server_name = self._infer_server_name(tools, server_command)

            # 2. squatting 检测(运行时权威,补静态盲区)
            local_set = set(local_tool_names)
            for t in tools:
                tname = t.get("name", "")
                if tname and tname in local_set:
                    events.append(MCPEvent(
                        timestamp=time.time(),
                        event_type="tool_squatting",
                        server_name=server_name,
                        tool_name=tname,
                        evidence=f"runtime tool '{tname}' shadows local tool",
                        verdict="malicious",
                    ))

            # 3. 描述投毒检测(复用静态层正则,保证一致性)
            for t in tools:
                desc = t.get("description", "")
                if not desc:
                    continue
                if any(p.search(desc) for p in SUSPICIOUS_DESCRIPTION_PATTERNS):
                    events.append(MCPEvent(
                        timestamp=time.time(),
                        event_type="description_poisoning",
                        server_name=server_name,
                        tool_name=t.get("name", ""),
                        payload_preview=desc[:200],
                        verdict="suspicious",
                    ))

            # 4. 响应注入探测(对每个工具空参调用,看响应是否含注入指令)
            if probe_tools:
                for t in tools:
                    tname = t.get("name", "")
                    if not tname:
                        continue
                    try:
                        resp = executor.call_tool(tname, {})
                        resp_text = json.dumps(resp)
                        if any(p.search(resp_text) for p in SUSPICIOUS_DESCRIPTION_PATTERNS):
                            events.append(MCPEvent(
                                timestamp=time.time(),
                                event_type="response_injection",
                                server_name=server_name,
                                tool_name=tname,
                                payload_preview=resp_text[:200],
                                verdict="suspicious",
                            ))
                    except Exception:
                        pass  # 工具可能要求必填参数,空参失败是正常的

        finally:
            executor.teardown()

        self.events.extend(events)
        return events

    def _infer_server_name(self, tools: list[dict], server_command) -> str:
        """从工具表或命令推断 server 名(MCP server 在 tools/list 响应里通常不带名字,
        这里用命令字符串兜底)。"""
        if isinstance(server_command, list):
            cmd_str = " ".join(server_command)
        else:
            cmd_str = str(server_command)
        # 取文件名部分作为 server 名
        parts = cmd_str.replace("\\", "/").split()
        for p in parts:
            if p.endswith(".py") or "/" in p:
                return Path(p).stem or p
        return cmd_str[:60]

    def save_events(self):
        out = Path(self.output_dir) / "mcp_events.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
