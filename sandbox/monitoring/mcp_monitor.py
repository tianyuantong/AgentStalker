"""
MCP Monitor — MCP (Model Context Protocol) 行为监控（骨架）

这是 monitoring 第 8 层,填补 sandbox/discovery.py 推荐的悬空 "mcp_io" 监控字符串。
本文件为骨架,完整实现见 Commit 9（MCP 运行时验证）。

设计目标(Commit 9 填充):
- 通过 sandbox/executors/mcp.py 的 MCPExecutor 驱动被测 MCP server
- tools/list 拿真实工具表（运行时权威,补静态抽取盲区）
- tools/call 捕获 server 真实响应（检测响应注入）
- 产生事件:
    mcp.tool_squatting_detected    — 工具名与本地工具冲突
    mcp.description_poisoning      — 描述含隐藏指令
    mcp.token_passthrough          — 原样转发 Authorization
    mcp.response_injection         — 响应含指令注入
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MCPEvent:
    """MCP 行为事件（与 NetworkEvent/MemoryEvent 同构）"""
    timestamp: float
    layer: str = "mcp"
    event_type: str = ""        # tool_squatting | description_poisoning | token_passthrough | response_injection
    server_name: str = ""
    tool_name: str = ""
    payload_preview: str = ""
    verdict: str = "neutral"    # neutral | suspicious | malicious
    trace_id: str = ""


class MCPMonitor:
    """MCP 行为监控（骨架）

    Commit 3 仅提供类骨架与数据结构,使 monitoring/__init__.py 能解析
    discovery.py 推荐的 'mcp_io' 监控层。Commit 9 实现驱动逻辑。
    """

    def __init__(self, output_dir: str = "./output/evidence"):
        self.output_dir = output_dir
        self.events: list[MCPEvent] = []

    def inspect_server(self, server_command: str, local_tool_names: list[str] | None = None) -> list[MCPEvent]:
        """驱动一个 MCP server 并产生审计事件。

        Commit 9 实现:
        1. 启动 server,MCPExecutor 握手
        2. tools/list 拿工具表
        3. 比对 local_tool_names 检测 squatting
        4. 扫描 description 检测投毒
        5. 对每个工具 tools/call,捕获响应检测注入
        """
        raise NotImplementedError(
            "MCPMonitor.inspect_server is implemented in Commit 9 "
            "(MCP runtime verification). This is a skeleton."
        )

    def save_events(self):
        import json
        from dataclasses import asdict
        from pathlib import Path
        out = Path(self.output_dir) / "mcp_events.json"
        out.write_text(
            json.dumps([asdict(e) for e in self.events], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
