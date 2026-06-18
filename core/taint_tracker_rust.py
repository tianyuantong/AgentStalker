"""
AgentStalker Rust Taint Tracker
================================
针对 Rust Agent 项目的污点追踪器。复用 Python 版的 TaintKind/SinkKind 枚举语义。

关键 Source（Agent 特有）:
  - USER_INPUT: stdin / argv / config file
  - RAG_CONTEXT: 检索结果（RAG vector store query / web fetch）
  - MCP_RESPONSE: McpClient.call_tool 返回
  - MEMORY_READ: load_user_memory / load_memory_block
  - TOOL_RESULT: 前序 tool handler 返回
  - WEB_FETCH: fetch_url / web.run / reqwest
  - FILE_CONTENT: fs::read / include_str!

关键 Sink:
  - TOOL_CALL: invoke_tool / execute_tool_handler
  - SHELL_CMD: process::Command::new / arg
  - FILE_PATH: fs::write / OpenOptions
  - URL_FETCH: reqwest::get / Client::execute
  - MEMORY_WRITE: append_entry / write_memory
  - MCP_REQUEST: McpClient.call_tool
  - PROMPT_CONSTRUCT: format! into system_prompt / as_system_block
  - EXTERNAL_OUTPUT: hook webhooks / println! to stdout

追踪策略:
  - 不做完整 dataflow (Rust 借用检查 + 生命周期太复杂)
  - 改做 "函数级" 污点：识别 Source fn → 调用链上的 Sink fn
  - 借助 callgraph 启发式（grep 引用）
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path


class TaintKind(str, Enum):
    USER_INPUT = "user_input"
    RAG_CONTEXT = "rag_context"
    MCP_RESPONSE = "mcp_response"
    MEMORY_READ = "memory_read"
    TOOL_RESULT = "tool_result"
    WEB_FETCH = "web_fetch"
    FILE_CONTENT = "file_content"
    CONFIG_READ = "config_read"


class SinkKind(str, Enum):
    TOOL_CALL = "tool_call"
    SHELL_CMD = "shell_cmd"
    FILE_PATH = "file_path"
    FILE_WRITE = "file_write"
    URL_FETCH = "url_fetch"
    MEMORY_WRITE = "memory_write"
    MCP_REQUEST = "mcp_request"
    EXTERNAL_OUTPUT = "external_output"
    PROMPT_CONSTRUCT = "prompt_construct"


# 已知 Sanitizer
RUST_SANITIZERS = {
    "execpolicy": re.compile(r'(?:check_approval|check_command_safety|ExecPolicyEngine|evaluate_policy|check_exec)\s*\('),
    "allowlist": re.compile(r'(?:ALLOWED|allowlist|whitelist|allowed_commands)'),
    "shell_escape": re.compile(r'shellexpand|\bquote\b|escape'),
    "path_norm": re.compile(r'(?:Path::|canonicalize|normalize_path|strip_prefix)'),
    "url_validate": re.compile(r'(?:url::Url::parse|validate_url|is_safe_url|allowed_domains)'),
    "xml_escape": re.compile(r'(?:escape|sanitize|ammonia|html_escape)'),
}


# Source fn 识别规则
SOURCE_FN_PATTERNS = {
    TaintKind.USER_INPUT: [
        re.compile(r'fn\s+(?:handle_user_input|process_input|read_stdin|get_user_message|read_user_input)\s*\('),
        re.compile(r'std::env::args|args\(\)\.collect'),
    ],
    TaintKind.RAG_CONTEXT: [
        re.compile(r'fn\s+(?:retrieve|search|fetch_context|rag_query|retrieve_tool_result)\s*\('),
    ],
    TaintKind.MCP_RESPONSE: [
        re.compile(r'fn\s+(?:mcp_call|call_mcp|mcp_client_call)\s*\('),
    ],
    TaintKind.MEMORY_READ: [
        re.compile(r'fn\s+(?:load_user_memory|load_memory|load_handoff_block|read_memory)\s*\('),
    ],
    TaintKind.TOOL_RESULT: [
        re.compile(r'fn\s+(?:execute_tool|invoke_tool|run_tool|handle_tool_call)\s*\('),
    ],
    TaintKind.WEB_FETCH: [
        re.compile(r'fn\s+(?:fetch_url|web_search|web_run|web_fetch|http_get)\s*\('),
        re.compile(r'reqwest\s*::\s*(?:Client|get)'),
    ],
    TaintKind.FILE_CONTENT: [
        re.compile(r'fn\s+(?:read_file|load_file|fs::read|include_str!|read_to_string)\s*\('),
    ],
    TaintKind.CONFIG_READ: [
        re.compile(r'fn\s+(?:load_config|read_config|parse_config)\s*\('),
    ],
}

# Sink call 识别规则
SINK_CALL_PATTERNS = {
    SinkKind.TOOL_CALL: re.compile(r'(?:invoke_tool|execute_tool|register_tool|tool_handler|tool_registry.*?\.dispatch|handlers\.get)'),
    SinkKind.SHELL_CMD: re.compile(r'(?:std::process|::process|tokio::process)\s*::\s*Command\s*::\s*new'),
    SinkKind.FILE_PATH: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*(?:read|write|create|remove|open)\s*\('),
    SinkKind.FILE_WRITE: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*write\b|File::create|OpenOptions::new\(\)'),
    SinkKind.URL_FETCH: re.compile(r'reqwest\s*::\s*(?:Client|get|post)|ureq\s*::'),
    SinkKind.MEMORY_WRITE: re.compile(r'(?:append_entry|write_memory|save_to_memory|update_memory|as_system_block.*write)'),
    SinkKind.MCP_REQUEST: re.compile(r'(?:McpClient|mcp_manager|McpServerConfig).*?(?:call_tool|send_request)'),
    SinkKind.EXTERNAL_OUTPUT: re.compile(r'(?:StdoutHookSink|WebhookHookSink|JsonlHookSink).*?(?:write|send|emit)'),
    SinkKind.PROMPT_CONSTRUCT: re.compile(r'(?:format!|writeln!)\s*[\(\s].*?(?:<|<\!|\\{)'),
}


@dataclass
class TaintFlow:
    flow_id: str
    source_kind: str
    source_function: str
    source_file: str
    source_line: int
    sink_kind: str
    sink_call: str
    sink_file: str
    sink_line: int
    path_functions: list = field(default_factory=list)
    sanitizers: list = field(default_factory=list)
    blocked: bool = False
    exploitable: bool = True
    severity: str = "high"
    description: str = ""


class RustTaintTracker:
    def __init__(self, source_dir: str | Path, agent_model: dict | None = None):
        self.source_dir = Path(source_dir)
        self.agent_model = agent_model or {}
        self.rs_files = [
            f for f in self.source_dir.rglob("*.rs")
            if not any(p in f.parts for p in {"target", "tests", "examples", "benches", ".git"})
        ]
        self.all_source: str = ""
        self.flows: list[TaintFlow] = []
        self._flow_counter = 0
        # 索引
        self.fn_defs: dict[str, list[dict]] = {}  # fn_name -> [(file, line, body)]
        self.fn_refs: dict[str, list[dict]] = {}  # fn_name -> [(file, line)]

    def track(self) -> list[TaintFlow]:
        # 1. 读全文
        self.all_source = "\n".join(
            self._read_safe(f) for f in self.rs_files
        )

        # 2. 建 fn 索引
        self._index_functions()

        # 3. 找 source fn
        sources = self._find_sources()

        # 4. 对每个 source fn，遍历其可达 sink
        for source in sources:
            sinks_in_reach = self._find_sinks_reachable_from(source)
            for sink in sinks_in_reach:
                self._flow_counter += 1
                path = self._shortest_path(source["fn"], sink["fn"])
                sanitizers = self._detect_sanitizers_on_path(path)
                self.flows.append(TaintFlow(
                    flow_id=f"F{self._flow_counter:03d}",
                    source_kind=source["kind"].value,
                    source_function=source["fn"],
                    source_file=source["file"],
                    source_line=source["line"],
                    sink_kind=sink["kind"].value,
                    sink_call=sink["match"][:60],
                    sink_file=sink["file"],
                    sink_line=sink["line"],
                    path_functions=path,
                    sanitizers=sanitizers,
                    blocked=bool(sanitizers),
                    exploitable=not bool(sanitizers),
                    severity=self._severity_for(source["kind"], sink["kind"]),
                    description=f"{source['fn']} -> {sink['fn']} via {len(path)} hops",
                ))

        return self.flows

    def _read_safe(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _index_functions(self):
        """粗略索引: 找所有 fn xxx() { ... }"""
        fn_re = re.compile(
            r'(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->\s*[^{;]+)?\s*\{',
            re.MULTILINE,
        )
        for path in self.rs_files:
            source = self._read_safe(path)
            if not source:
                continue
            rel = str(path.relative_to(self.source_dir))
            for m in fn_re.finditer(source):
                fn_name = m.group(1)
                line_no = source[:m.start()].count("\n") + 1
                # body: 从 { 到 配对的 }
                body = self._extract_fn_body(source, m.end() - 1)
                self.fn_defs.setdefault(fn_name, []).append({
                    "file": rel, "line": line_no, "body": body
                })
                self.fn_refs.setdefault(fn_name, []).append({
                    "file": rel, "line": line_no
                })
        # 引用: 找所有 "fn_name(" 出现位置
        for path in self.rs_files:
            source = self._read_safe(path)
            if not source:
                continue
            rel = str(path.relative_to(self.source_dir))
            for m in re.finditer(r'\b(\w+)\s*\(', source):
                name = m.group(1)
                if name in self.fn_defs:
                    line_no = source[:m.start()].count("\n") + 1
                    if not (name == m.group(0) and line_no == 0):
                        # 排除定义本身
                        if not any(d["file"] == rel and d["line"] == line_no
                                   for d in self.fn_defs[name]):
                            self.fn_refs.setdefault(name, []).append({
                                "file": rel, "line": line_no, "caller_line": line_no
                            })

    def _extract_fn_body(self, source: str, open_brace_idx: int) -> str:
        depth = 0
        i = open_brace_idx
        while i < len(source):
            c = source[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return source[open_brace_idx:i+1]
            i += 1
        return source[open_brace_idx:open_brace_idx+500]

    def _find_sources(self) -> list[dict]:
        """找所有 source fn 定义"""
        results = []
        for kind, patterns in SOURCE_FN_PATTERNS.items():
            for pat in patterns:
                for m in pat.finditer(self.all_source):
                    line_no = self.all_source[:m.start()].count("\n") + 1
                    # 找 fn 名字
                    fn_m = re.search(r'fn\s+(\w+)', m.group(0))
                    if not fn_m:
                        continue
                    fn_name = fn_m.group(1)
                    # 找 file
                    file_loc = self._locate(line_no)
                    results.append({
                        "kind": kind,
                        "fn": fn_name,
                        "file": file_loc["file"],
                        "line": file_loc["line"],
                    })
        return results

    def _find_sinks_reachable_from(self, source: dict) -> list[dict]:
        """BFS 找 source 函数可达的所有 sink（1-3 hop）"""
        visited = {source["fn"]}
        queue = [(source["fn"], 0)]
        sinks = []
        max_hops = 4

        while queue:
            current, depth = queue.pop(0)
            if depth > max_hops:
                continue
            # 找 current 调用的 fn
            refs = self.fn_refs.get(current, [])
            # 1) 看 current 函数 body 本身有没有 sink
            for defn in self.fn_defs.get(current, []):
                body = defn["body"]
                for sink_kind, pat in SINK_CALL_PATTERNS.items():
                    for m in pat.finditer(body):
                        line_no = defn["line"] + body[:m.start()].count("\n")
                        sinks.append({
                            "kind": sink_kind,
                            "fn": current,
                            "file": defn["file"],
                            "line": line_no,
                            "match": m.group(0),
                        })
            # 2) 找调用了 current 的 fn（即调用方）
            callers = self._find_callers(current)
            for caller in callers:
                if caller["fn"] not in visited:
                    visited.add(caller["fn"])
                    queue.append((caller["fn"], depth + 1))
        return sinks

    def _find_callers(self, fn_name: str) -> list[dict]:
        """找调用了 fn_name 的所有 fn"""
        # 简化: 找包含 "fn_name(" 的所有 fn body
        callers = []
        for cand_name, defs in self.fn_defs.items():
            for defn in defs:
                if re.search(rf'\b{re.escape(fn_name)}\s*\(', defn["body"]):
                    callers.append({
                        "fn": cand_name,
                        "file": defn["file"],
                        "line": defn["line"],
                    })
        return callers

    def _shortest_path(self, src: str, dst: str) -> list[str]:
        """BFS 找 src -> dst 路径"""
        if src == dst:
            return [src]
        visited = {src}
        queue = [[src]]
        while queue:
            path = queue.pop(0)
            node = path[-1]
            if node == dst:
                return path
            for caller in self._find_callers(node):
                if caller["fn"] not in visited:
                    visited.add(caller["fn"])
                    queue.append(path + [caller["fn"]])
        return [src, "...", dst]

    def _detect_sanitizers_on_path(self, path: list[str]) -> list[str]:
        """检查路径上每个 fn body 是否包含 sanitizer"""
        found = []
        for fn in path:
            for defn in self.fn_defs.get(fn, []):
                body = defn["body"]
                for sname, pat in RUST_SANITIZERS.items():
                    if pat.search(body):
                        found.append(f"{fn}:{sname}")
        return list(set(found))

    def _locate(self, line_no: int) -> dict:
        """根据行号反查 file"""
        line_count = 0
        for path in self.rs_files:
            rel = str(path.relative_to(self.source_dir))
            try:
                with path.open(encoding="utf-8", errors="ignore") as f:
                    n = sum(1 for _ in f)
                if line_count + n >= line_no:
                    return {"file": rel, "line": line_no - line_count}
                line_count += n
            except Exception:
                continue
        return {"file": "?", "line": line_no}

    def _severity_for(self, kind: TaintKind, sink: SinkKind) -> str:
        critical = {SinkKind.SHELL_CMD, SinkKind.MEMORY_WRITE, SinkKind.EXTERNAL_OUTPUT}
        if sink in critical:
            return "critical"
        if kind in {TaintKind.WEB_FETCH, TaintKind.RAG_CONTEXT, TaintKind.MCP_RESPONSE}:
            if sink in {SinkKind.TOOL_CALL, SinkKind.PROMPT_CONSTRUCT, SinkKind.MCP_REQUEST}:
                return "high"
        if sink == SinkKind.PROMPT_CONSTRUCT:
            return "high"
        return "medium"

    def to_json(self) -> str:
        return json.dumps([asdict(f) for f in self.flows], indent=2, ensure_ascii=False)


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--agent-model", help="agent_model.json 路径")
    ap.add_argument("--output", default="taint_flows.json")
    args = ap.parse_args()

    am = {}
    if args.agent_model and Path(args.agent_model).exists():
        am = json.loads(Path(args.agent_model).read_text(encoding="utf-8"))

    tracker = RustTaintTracker(args.source, am)
    flows = tracker.track()
    Path(args.output).write_text(tracker.to_json(), encoding="utf-8")

    exploitable = sum(1 for f in flows if f.exploitable)
    critical = sum(1 for f in flows if f.severity == "critical" and f.exploitable)
    print(f"[+] Total flows: {len(flows)}")
    print(f"[+] Exploitable (no sanitizer): {exploitable}")
    print(f"[+] Critical & exploitable: {critical}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()
