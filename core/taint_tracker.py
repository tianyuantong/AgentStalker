"""
AgentStalker Taint Tracker
===========================
Agent 感知的污点追踪器

与传统 taint analysis 的差异：
1. Source 不止是 HTTP/RPC，而是 **5 个 Agent 特有的入口**：
   - user_message（用户输入）
   - rag_context（RAG 检索内容）
   - mcp_response（MCP Server 返回）
   - memory_value（长期记忆读取）
   - tool_result（前序工具调用结果）
2. Sink 不止是 SQL/exec，而是 **Agent 特有的危险操作**：
   - tool_call 参数
   - memory_write
   - mcp_request
   - send_external（外发通道）
3. 追踪跨**多轮对话**的污染传递

移植并适配自 codeaudit/references/core/taint_analysis.md
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


# ============ Taint 类型 ============
class TaintKind(str, Enum):
    """Agent 特有的污点源类型"""
    USER_INPUT = "user_input"            # 用户直接消息
    RAG_CONTEXT = "rag_context"          # RAG 检索内容
    MCP_RESPONSE = "mcp_response"        # MCP Server 返回
    MEMORY_READ = "memory_read"          # 长期记忆读取
    TOOL_RESULT = "tool_result"          # 前序工具调用结果
    WEB_FETCH = "web_fetch"              # 网页抓取
    FILE_CONTENT = "file_content"        # 文件读取内容


class SinkKind(str, Enum):
    """Agent 特有的危险汇聚点"""
    TOOL_CALL = "tool_call"              # 工具调用
    SQL_QUERY = "sql_query"
    SHELL_CMD = "shell_cmd"
    FILE_PATH = "file_path"
    URL_FETCH = "url_fetch"
    MEMORY_WRITE = "memory_write"        # 写入长期记忆
    MCP_REQUEST = "mcp_request"          # 调用 MCP Server
    EMAIL_SEND = "email_send"            # 外发邮件
    HTTP_POST = "http_post"
    TEMPLATE_RENDER = "template_render"
    PROMPT_CONSTRUCT = "prompt_construct"  # 拼接到 prompt


@dataclass
class TaintNode:
    """污点流图节点"""
    var_name: str
    kind: TaintKind
    source_location: str
    value_preview: str = ""
    tainted: bool = True
    sanitized: bool = False
    sanitizers: list[str] = field(default_factory=list)


@dataclass
class TaintFlow:
    """一条完整的污点流"""
    flow_id: str
    source: TaintNode
    sink: TaintNode
    path: list[str] = field(default_factory=list)  # 变量名传递链
    sanitizers: list[str] = field(default_factory=list)
    blocked: bool = False
    severity: str = "high"
    # Commit 11: 语义污点引擎字段(非破坏,默认值保持向后兼容)
    confidence: float = 1.0       # 累积传播概率 0.0-1.0(镜像 Stage4 Evidence.confidence)
    feature_type: str = ""        # direct_instruction|structured_data|indirect_reference|non_text
    llm_hops: list[dict] = field(default_factory=list)  # 经过的 LLM hop(每跳的传播概率)

    @property
    def is_exploitable(self) -> bool:
        # 布尔逻辑保持不变(向后兼容);confidence 是补充的连续度量
        return (
            not self.blocked
            and not self.source.sanitized
            and not self.sink.sanitized
            and len(self.sanitizers) == 0
        )


# ============ 净化器识别 ============
SANITIZER_PATTERNS = {
    "sql_escape": re.compile(r"(parameterized|cursor\.execute\([^)]*,\s*\(|sqlalchemy\.text\(|sql\.SQL\()", re.IGNORECASE),
    "shell_escape": re.compile(r"(shlex\.quote|shlex\.split|allowed_commands|whitelist)", re.IGNORECASE),
    "path_norm": re.compile(r"(os\.path\.normpath|os\.path\.realpath|safe_path|Path\(\))", re.IGNORECASE),
    "url_validate": re.compile(r"(urlparse|allowed_domains|allowed_schemes|is_safe_url)", re.IGNORECASE),
    "html_escape": re.compile(r"(bleach\.clean|html\.escape|sanitize|DOMPurify)", re.IGNORECASE),
    "pydantic": re.compile(r"(pydantic|BaseModel|Field\(|constr|conint)", re.IGNORECASE),
    "schema_validate": re.compile(r"(jsonschema|JSONSchema|validate\(|schema\.parse)", re.IGNORECASE),
}


# ============ Taint Tracker ============
class TaintTracker:
    """
    Agent 感知的污点追踪器
    输入: 源码 + agent_model.json
    输出: TaintFlow 列表
    """

    def __init__(self, source_dir: str | Path, agent_model: dict | None = None):
        self.source_dir = Path(source_dir)
        self.agent_model = agent_model or {}
        self.flows: list[TaintFlow] = []
        self._flow_counter = 0

    def track(self) -> list[TaintFlow]:
        """主入口"""
        py_files = [f for f in self.source_dir.rglob("*.py")
                    if "__pycache__" not in f.parts and ".git" not in f.parts]

        for path in py_files:
            self._track_file(path)

        return self.flows

    def _track_file(self, path: Path):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return

        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._track_function(node, path, source)

    def _track_function(self, func: ast.FunctionDef, path: Path, source: str):
        """
        追踪单个函数内的污点流：
        1. 识别函数参数是否含 TaintKind
        2. 识别函数内是否有 Sink
        3. 检查是否经过净化
        """
        # 启发式：根据函数名判断 taint kind
        func_name = func.name.lower()
        kind = self._classify_function(func_name, source)

        if not kind:
            return

        # 找该函数内的 sink 调用
        sinks = self._find_sinks_in_function(func, path, source)
        if not sinks:
            return

        # 对每个 sink 产生一条 flow
        for sink in sinks:
            # 检查函数体中是否有净化
            body_src = ast.unparse(func) if hasattr(ast, "unparse") else source[func.body[0].lineno-1:func.end_lineno]
            sanitizers = self._detect_sanitizers(body_src)

            self._flow_counter += 1
            flow = TaintFlow(
                flow_id=f"F{self._flow_counter:03d}",
                source=TaintNode(
                    var_name=func.args.args[0].arg if func.args.args else "?",
                    kind=kind,
                    source_location=f"{path.name}:{func.lineno}",
                ),
                sink=TaintNode(
                    var_name=sink["target"],
                    kind=sink["kind"],
                    source_location=f"{path.name}:{sink['line']}",
                ),
                sanitizers=sanitizers,
                blocked=len(sanitizers) > 0,
                severity=self._severity_for(kind, sink["kind"]),
            )
            self.flows.append(flow)

    def _classify_function(self, func_name: str, source: str) -> TaintKind | None:
        """根据函数名 + 上下文判断 taint kind"""
        n = func_name.lower()
        if any(k in n for k in ["execute_tool", "invoke_tool", "call_tool", "tool_call"]):
            return TaintKind.TOOL_RESULT
        if any(k in n for k in ["web_search", "web_fetch", "fetch_url", "http_get"]):
            return TaintKind.WEB_FETCH
        if any(k in n for k in ["rag", "retrieve", "vector_search", "semantic_search"]):
            return TaintKind.RAG_CONTEXT
        if any(k in n for k in ["memory", "recall", "load_memory"]):
            return TaintKind.MEMORY_READ
        if any(k in n for k in ["mcp", "call_mcp", "mcp_call"]):
            return TaintKind.MCP_RESPONSE
        if any(k in n for k in ["read_file", "open_file"]):
            return TaintKind.FILE_CONTENT
        if any(k in n for k in ["handle_message", "process_input", "chat"]):
            return TaintKind.USER_INPUT
        return None

    def _find_sinks_in_function(self, func: ast.FunctionDef, path: Path, source: str) -> list[dict]:
        """找函数内的 sink 调用"""
        sinks = []
        for node in ast.walk(func):
            if not isinstance(node, ast.Call):
                continue

            sink_kind = self._classify_call(node)
            if sink_kind:
                # 提取 target（第一个参数）
                target = "?"
                if node.args and isinstance(node.args[0], ast.Name):
                    target = node.args[0].id
                elif node.args:
                    target = ast.unparse(node.args[0])[:30] if hasattr(ast, "unparse") else "?"

                sinks.append({
                    "kind": sink_kind,
                    "target": target,
                    "line": node.lineno
                })
        return sinks

    def _classify_call(self, call: ast.Call) -> SinkKind | None:
        """判断函数调用是否为 sink"""
        # 提取被调用函数名
        func_str = ast.unparse(call.func) if hasattr(ast, "unparse") else ""

        if any(k in func_str for k in ["execute_sql", "cursor.execute", "db.execute", "session.execute"]):
            return SinkKind.SQL_QUERY
        if any(k in func_str for k in ["subprocess", "os.system", "os.popen"]):
            return SinkKind.SHELL_CMD
        if any(k in func_str for k in ["open(", "read_file", "Path("]):
            return SinkKind.FILE_PATH
        if any(k in func_str for k in ["requests.", "urlopen", "fetch_url"]):
            return SinkKind.URL_FETCH
        if any(k in func_str for k in ["memory.save", "memory.write", "save_memory"]):
            return SinkKind.MEMORY_WRITE
        if any(k in func_str for k in ["mcp.call", "mcp_client"]):
            return SinkKind.MCP_REQUEST
        if any(k in func_str for k in ["send_email", "smtp.send"]):
            return SinkKind.EMAIL_SEND
        if any(k in func_str for k in ["requests.post", "requests.put", "axios.post"]):
            return SinkKind.HTTP_POST
        if any(k in func_str for k in ["Template", "render", "jinja", "format("]):
            return SinkKind.TEMPLATE_RENDER
        return None

    def _detect_sanitizers(self, body_src: str) -> list[str]:
        """检测函数体中是否含净化器"""
        found = []
        for name, pattern in SANITIZER_PATTERNS.items():
            if pattern.search(body_src):
                found.append(name)
        return found

    def _severity_for(self, kind: TaintKind, sink: SinkKind) -> str:
        """评估严重度"""
        # 外发通道 + 不可信源 = critical
        if sink in {SinkKind.EMAIL_SEND, SinkKind.MEMORY_WRITE, SinkKind.SHELL_CMD}:
            return "critical"
        if kind in {TaintKind.RAG_CONTEXT, TaintKind.WEB_FETCH, TaintKind.MCP_RESPONSE}:
            if sink in {SinkKind.SQL_QUERY, SinkKind.FILE_PATH, SinkKind.MCP_REQUEST}:
                return "high"
        if sink in {SinkKind.TEMPLATE_RENDER, SinkKind.PROMPT_CONSTRUCT}:
            return "high"
        return "medium"


# ============ CLI ============
def main():
    import argparse
    import json
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--agent-model", help="agent_model.json 路径")
    ap.add_argument("--output", default="taint_flows.json")
    ap.add_argument("--semantic", action="store_true",
                    help="启用语义污点引擎:对 LLM hop 做概率传播,计算累积置信度")
    args = ap.parse_args()

    agent_model = {}
    if args.agent_model and Path(args.agent_model).exists():
        agent_model = json.loads(Path(args.agent_model).read_text())

    tracker = TaintTracker(args.source, agent_model)
    flows = tracker.track()

    # Commit 11: 语义污点引擎(可选,--semantic 开启)
    if args.semantic:
        from core.semantic_taint import SemanticTaintGraph
        stg = SemanticTaintGraph(agent_model)
        flows = stg.enrich(flows)

    # 序列化
    out = []
    for f in flows:
        out.append({
            "flow_id": f.flow_id,
            "source_kind": f.source.kind.value,
            "source_location": f.source.source_location,
            "sink_kind": f.sink.kind.value,
            "sink_location": f.sink.source_location,
            # Commit 11: path 原本被遗漏(从不序列化),现补上;confidence/feature_type 是新字段
            "path": f.path,
            "sanitizers": f.sanitizers,
            "blocked": f.blocked,
            "exploitable": f.is_exploitable,
            "severity": f.severity,
            "confidence": f.confidence,
            "feature_type": f.feature_type,
            "llm_hops": f.llm_hops,
        })

    Path(args.output).write_text(json.dumps(out, indent=2, ensure_ascii=False))
    exploitable = sum(1 for f in flows if f.is_exploitable)
    print(f"[+] Total flows: {len(flows)}")
    print(f"[+] Exploitable (no sanitizer): {exploitable}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()
