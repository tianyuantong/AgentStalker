"""
AgentStalker Rust Taint Tracker
================================
针对 Rust Agent 项目的污点追踪器。复用 Python 版的 TaintKind/SinkKind 枚举语义。

关键 Source（Agent 特有）:
  - USER_INPUT: stdin / argv / config file
  - RAG_CONTEXT: 检索结果（RAG vector store query / web fetch / 项目上下文加载）
  - MCP_RESPONSE: McpClient.call_tool 返回
  - MEMORY_READ: load_user_memory / load_memory_block
  - TOOL_RESULT: 前序 tool handler 返回
  - WEB_FETCH: fetch_url / web.run / reqwest
  - FILE_CONTENT: fs::read / include_str!
  - CONFIG_READ: load_config / read_config

关键 Sink:
  - TOOL_CALL: invoke_tool / execute_tool_handler
  - SHELL_CMD: process::Command::new / arg（动态构造 + 字面量）
  - FILE_PATH: fs::write / OpenOptions
  - URL_FETCH: reqwest::get / Client::execute
  - MEMORY_WRITE: append_entry / write_memory
  - MCP_REQUEST: McpClient.call_tool
  - PROMPT_CONSTRUCT: format! into system_prompt / as_system_block
  - EXTERNAL_OUTPUT: hook webhooks / println! to stdout

追踪策略（两种，由 fast 开关选择）:
  - full（默认）: BFS callgraph（max_hops=4），跨函数路径精确
  - fast: 仅看 source body + ≤5 个直接 caller body，速度快但覆盖率低

两种模式共用 _detect_sanitizers_on_path，确保多跳 sanitizer 检测一致正确
（修复了 fast 旧版本 _emit_flow 里的 pass 占位 bug —— 旧版漏检 caller 侧 sanitizer）。

历史:本文件合并了原 taint_tracker_rust.py（full）与 taint_tracker_rust_fast.py。
合并理由:两版高度重复且 drift，且 fast 版有 C3（重复 dict key 静默漏报动态 SHELL_CMD）
和 C5（caller sanitizer 占位 pass）两个静默 bug。full 版的两处实现均正确，作为基底。
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


# 已知 Sanitizer（合并 full + fast，per-key union，采用更紧的正则避免误报）
RUST_SANITIZERS = {
    "execpolicy": re.compile(
        r'(?:check_approval|check_command_safety|ExecPolicyEngine|ExecPolicyCheck|exec_policy|evaluate_policy|check_exec)'
    ),
    "allowlist": re.compile(r'(?:ALLOWED|allowlist|whitelist|allowed_commands)'),
    # fast 版的 shellexpand|shell_escape|escape_arg 更紧；full 的 \bquote\b|escape 过松易误报
    "shell_escape": re.compile(r'shellexpand|shell_escape|escape_arg'),
    "path_norm": re.compile(r'(?:Path::|canonicalize|normalize_path|strip_prefix|sandbox_path)'),
    "url_validate": re.compile(r'(?:url::Url::parse|Url::parse|validate_url|is_safe_url|allowed_domains)'),
    # xml_escape: 收紧 —— 旧版 (?:escape|sanitize|ammonia|html_escape) 中的裸
    # "escape"/"sanitize" 过松,会把注释里的 "no sanitizer" 也匹配成 sanitizer,
    # 导致 flow 被误判为 blocked。改为要求 XML/HTML 转义的具体 API 形式。
    "xml_escape": re.compile(r'(?:html_escape|html::Escape|ammonia|xml_escape|encode_text|html_escape_owned)'),
}


# Source fn 识别规则（dict 形，full 风格；吸收 fast 的额外别名，按语义归类）
SOURCE_FN_PATTERNS = {
    TaintKind.USER_INPUT: [
        re.compile(r'fn\s+(?:handle_user_input|process_input|read_stdin|get_user_message|read_user_input)\s*\('),
        re.compile(r'fn\s+(?:handle_user_message|process_user_message|on_user_message|user_message_handler|input_handler|chat_handler)\s*\('),
        re.compile(r'std::env::args|args\(\)\.collect'),
        re.compile(r'(?:std::env::args|env::args).*next'),
    ],
    TaintKind.RAG_CONTEXT: [
        re.compile(r'fn\s+(?:retrieve|search|fetch_context|rag_query|retrieve_tool_result)\s*\('),
        # fast 引入的 RAG 别名（向量检索 / 文件搜索 / 项目上下文 / 子 agent / 技能）
        re.compile(r'fn\s+(?:vector_search|retrieve_context)\s*\('),
        re.compile(r'fn\s+(?:grep_files|file_search|search_files)\s*\('),
        re.compile(r'fn\s+(?:run_tests|run_verifiers|diagnostics)\s*\('),
        re.compile(r'fn\s+(?:agent_open|tool_agent|sub_agent)\s*\('),
        re.compile(r'fn\s+(?:review|read_code|analyze)\s*\('),
        re.compile(r'fn\s+(?:list_dir|load_project|load_workspace)\s*\('),
        re.compile(r'fn\s+(?:code_execution|validate_data)\s*\('),
        re.compile(r'fn\s+(?:apply_patch|edit_file)\s*\('),
        re.compile(r'fn\s+(?:load_skill|render_skills|list_skills)\s*\('),
    ],
    TaintKind.MCP_RESPONSE: [
        re.compile(r'fn\s+(?:mcp_call|call_mcp|mcp_client_call|invoke_mcp_tool|call_mcp_tool)\s*\('),
        re.compile(r'(?:McpClient|McpManager).*?call_tool'),
    ],
    TaintKind.MEMORY_READ: [
        re.compile(r'fn\s+(?:load_user_memory|load_memory|load_handoff_block|read_memory)\s*\('),
        re.compile(r'(?:append_entry|load_memory_block).*?read'),
    ],
    TaintKind.TOOL_RESULT: [
        re.compile(r'fn\s+(?:execute_tool|invoke_tool|run_tool|handle_tool_call|dispatch_tool)\s*\('),
        re.compile(r'fn\s+(?:retrieve_tool_result|get_tool_result)\s*\('),
    ],
    TaintKind.WEB_FETCH: [
        re.compile(r'fn\s+(?:fetch_url|web_search|web_run|web_fetch|http_get|http_post|http_request)\s*\('),
        re.compile(r'reqwest\s*::\s*(?:Client|get)'),
    ],
    TaintKind.FILE_CONTENT: [
        re.compile(r'fn\s+(?:read_file|load_file|fs::read|include_str!|read_to_string)\s*\('),
        re.compile(r'fn\s+(?:load_file_content|read_project_file|load_workspace_file)\s*\('),
    ],
    TaintKind.CONFIG_READ: [
        re.compile(r'fn\s+(?:load_config|read_config|parse_config)\s*\('),
    ],
}

# Sink call 识别规则
# 注意:每个 SinkKind 只能出现一次 —— Python dict 重复 key 会静默覆盖（C3 bug 根因）。
# SHELL_CMD 合并了"动态构造"(std::process::Command::new) 和"字面量"(Command::new("ls"))
# 两种意图为单 key 单正则，避免旧 fast 版重复 key 导致动态构造检测被静默丢弃。
SINK_CALL_PATTERNS = {
    SinkKind.TOOL_CALL: re.compile(r'(?:invoke_tool|execute_tool|dispatch_tool|tool_handler|handlers\.get|handlers\.insert|register_tool|tool_registry)'),
    SinkKind.SHELL_CMD: re.compile(
        # 三种 Command::new 形式都要捕获(C3 修复):
        # 1) 完全限定:std::process::Command::new / tokio::process::Command::new
        # 2) 字面量命令:Command::new("ls")
        # 3) 动态变量:Command::new(&cmd) / Command::new(user_input)
        #    (旧 fast 版重复 dict key 导致 #1 丢失;合并正则覆盖三种)
        r'(?:std::process|::process|tokio::process)\s*::\s*Command\s*::\s*new'
        r'|Command\s*::\s*new\s*\(\s*(?:"[^"]*"|&?\s*\w+)'
    ),
    SinkKind.FILE_PATH: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*(?:read|write|create|remove|open)\s*\('),
    SinkKind.FILE_WRITE: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*write\b|File::create|OpenOptions::new\(\)'),
    SinkKind.URL_FETCH: re.compile(r'reqwest\s*::\s*(?:Client|get|post)|\.send\(\)|ureq\s*::'),
    SinkKind.MEMORY_WRITE: re.compile(r'(?:append_entry|write_memory|save_to_memory|update_memory|as_system_block.*?write)'),
    SinkKind.MCP_REQUEST: re.compile(r'(?:McpClient|mcp_manager|McpServerConfig).*?(?:call_tool|send_request)'),
    SinkKind.EXTERNAL_OUTPUT: re.compile(r'(?:StdoutHookSink|WebhookHookSink|JsonlHookSink).*?(?:write|send|emit)'),
    SinkKind.PROMPT_CONSTRUCT: re.compile(r'(?:format!|writeln!)\s*[\(\s].*?(?:\{|<\!|<untrusted)'),
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
    def __init__(self, source_dir: str | Path, agent_model: dict | None = None, fast: bool = False):
        """
        :param fast: True = 仅看 source body + ≤5 直接 caller（快，覆盖率低）
                     False（默认）= BFS callgraph max_hops=4（慢，跨函数路径精确）
        """
        self.source_dir = Path(source_dir)
        self.agent_model = agent_model or {}
        self.fast = fast
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
        if self.fast:
            return self._track_fast()
        return self._track_full()

    # ============ full 模式（原 taint_tracker_rust.py 逻辑） ============
    def _track_full(self) -> list[TaintFlow]:
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
                path = self._shortest_path(source["fn"], sink["fn"])
                sanitizers = self._detect_sanitizers_on_path(path)
                self._emit_flow(source, sink, path, sanitizers)

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
        """BFS 找 source 函数可达的所有 sink（1-4 hop）"""
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
        """检查路径上每个 fn body 是否包含 sanitizer（full 模式正确实现）"""
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

    # ============ fast 模式（仅看 source body + ≤5 直接 caller） ============
    # 性能优化：跳过完整 BFS callgraph，改做 in-file 同 scope + 跨文件直接 caller。
    # 关键：sanitizer 检测复用 _detect_sanitizers_on_path（而非旧 fast 版的 pass 占位），
    # 确保 caller 侧的 sanitizer 不会被漏检。
    def _track_fast(self) -> list[TaintFlow]:
        # 0. 读全文（_find_sources 依赖 all_source）
        self.all_source = "\n".join(self._read_safe(f) for f in self.rs_files)
        # 1. 建 fn 索引（共用 _index_functions）
        self._index_functions()

        # 2. 找 source fn（需带上 body）
        sources = self._find_sources()
        # 补 body 字段（_find_sources 不带 body，从 fn_defs 取）
        for s in sources:
            defs = self.fn_defs.get(s["fn"], [])
            s["body"] = defs[0]["body"] if defs else ""

        # 3. 对每个 source: body 内 + ≤5 caller body 内找 sink
        for source in sources:
            # 3a. source body 内直接 sink
            for m, sink_kind, line_no in self._find_sinks_in_body(source["body"], source["line"]):
                path = [source["fn"]]
                sanitizers = self._detect_sanitizers_on_path(path)
                self._emit_flow_from_match(
                    source, sink_kind, m.group(0), source["file"], line_no, path, sanitizers
                )

            # 3b. caller body 内 sink（限 5 个 caller）
            callers = self._find_callers(source["fn"])[:5]
            for caller in callers:
                caller_body = self.fn_defs.get(caller["fn"], [{}])[0].get("body", "")
                for m, sink_kind, line_no in self._find_sinks_in_body(caller_body, caller["line"]):
                    path = [source["fn"], caller["fn"]]
                    # 复用 full 的 _detect_sanitizers_on_path，检查 source + caller 两层 sanitizer
                    sanitizers = self._detect_sanitizers_on_path(path)
                    self._emit_flow_from_match(
                        source, sink_kind, m.group(0), caller["file"], line_no, path, sanitizers
                    )

        return self.flows

    def _find_sinks_in_body(self, body: str, base_line: int):
        """yield (match, sink_kind, abs_line) for each sink in body"""
        for sink_kind, pat in SINK_CALL_PATTERNS.items():
            for m in pat.finditer(body):
                line_no = base_line + body[:m.start()].count("\n")
                yield m, sink_kind, line_no

    # ============ 共用 flow 构造 ============
    def _emit_flow(self, source: dict, sink: dict, path: list[str], sanitizers: list[str]):
        """full 模式用:从 _find_sinks_reachable_from 的 sink dict 构造 flow"""
        self._flow_counter += 1
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

    def _emit_flow_from_match(self, source: dict, sink_kind, sink_match, sink_file, sink_line, path, sanitizers):
        """fast 模式用:从正则 match 构造 flow"""
        self._flow_counter += 1
        self.flows.append(TaintFlow(
            flow_id=f"F{self._flow_counter:03d}",
            source_kind=source["kind"].value,
            source_function=source["fn"],
            source_file=source["file"],
            source_line=source["line"],
            sink_kind=sink_kind.value,
            sink_call=sink_match[:80],
            sink_file=sink_file,
            sink_line=sink_line,
            path_functions=path,
            sanitizers=sanitizers,
            blocked=bool(sanitizers),
            exploitable=not bool(sanitizers),
            severity=self._severity_for(source["kind"], sink_kind),
            description=f"{source['fn']} -> {sink_kind.value}",
        ))

    def _severity_for(self, kind: TaintKind, sink: SinkKind) -> str:
        """
        严重度评估（合并 full + fast 的提升）:
        - FILE_CONTENT 入高危源（fast 提升，合理:文件内容污染同样高危）
        - URL_FETCH 入高危 sink（fast 提升，合理:数据外带）
        """
        critical = {SinkKind.SHELL_CMD, SinkKind.MEMORY_WRITE, SinkKind.EXTERNAL_OUTPUT}
        if sink in critical:
            return "critical"
        if kind in {TaintKind.WEB_FETCH, TaintKind.RAG_CONTEXT, TaintKind.MCP_RESPONSE, TaintKind.FILE_CONTENT}:
            if sink in {SinkKind.TOOL_CALL, SinkKind.PROMPT_CONSTRUCT, SinkKind.MCP_REQUEST, SinkKind.URL_FETCH}:
                return "high"
        if sink == SinkKind.PROMPT_CONSTRUCT:
            return "high"
        return "medium"

    def to_json(self) -> str:
        return json.dumps([asdict(f) for f in self.flows], indent=2, ensure_ascii=False)


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser(description="AgentStalker Rust Taint Tracker")
    ap.add_argument("--source", required=True, help="Rust 项目根目录")
    ap.add_argument("--agent-model", help="agent_model.json 路径（可选）")
    ap.add_argument("--output", default="taint_flows.json")
    ap.add_argument("--fast", action="store_true",
                    help="快速模式:仅看 source body + ≤5 直接 caller（跳过完整 BFS callgraph）")
    args = ap.parse_args()

    am = {}
    if args.agent_model and Path(args.agent_model).exists():
        am = json.loads(Path(args.agent_model).read_text(encoding="utf-8"))

    tracker = RustTaintTracker(args.source, am, fast=args.fast)
    flows = tracker.track()
    Path(args.output).write_text(tracker.to_json(), encoding="utf-8")

    exploitable = sum(1 for f in flows if f.exploitable)
    critical = sum(1 for f in flows if f.severity == "critical" and f.exploitable)
    print(f"[+] Mode: {'fast' if args.fast else 'full'}")
    print(f"[+] Total flows: {len(flows)}")
    print(f"[+] Exploitable (no sanitizer): {exploitable}")
    print(f"[+] Critical & exploitable: {critical}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()
