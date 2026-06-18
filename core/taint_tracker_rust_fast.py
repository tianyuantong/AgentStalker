"""
AgentStalker Rust Taint Tracker - Fast Version
================================================
针对中型 Rust Agent（数百 .rs 文件 / 数千行）的轻量污点推断。

不做完整 BFS callgraph（太慢），改做 **in-file 同 scope + 跨文件已知 call chain** 的污点推断。

设计:
- Source: 用户输入 / 文件内容 / MCP 响应 / 记忆读取 / Web fetch
- Sink: shell_cmd / file_write / memory_write / external_output / prompt_construct
- 路径: 启发式 — 同 fn 内 → 同文件直接调用 → 跨文件已知 call chain
- 净化器: execpolicy / allowlist / escape

对每个 Source 函数:
  1. 同 fn body 内找 sink → 直接污点流
  2. 同文件内找调用 Source 的 fn（caller）→ 再找 sink
  3. 跨文件用 grep 找 caller
"""
from __future__ import annotations

import json
import re
import time
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


RUST_SANITIZERS = {
    "execpolicy": re.compile(r'(?:check_approval|check_command_safety|ExecPolicyEngine|evaluate_policy|ExecPolicyCheck|exec_policy)'),
    "allowlist": re.compile(r'(?:ALLOWED|allowlist|whitelist|allowed_commands)'),
    "shell_escape": re.compile(r'shellexpand|shell_escape|escape_arg'),
    "path_norm": re.compile(r'(?:canonicalize|normalize_path|strip_prefix|sandbox_path)'),
    "url_validate": re.compile(r'(?:url::Url::parse|validate_url|is_safe_url|allowed_domains|Url::parse)'),
    "xml_escape": re.compile(r'(?:escape|sanitize|ammonia|html_escape)'),
}

# Source fn patterns (Rust agent 通用 — 典型上下文加载函数名)
SOURCE_FN_PATTERNS = [
    # USER_INPUT
    (TaintKind.USER_INPUT, re.compile(r'fn\s+(handle_user_input|read_user_input|get_user_message|process_user_input|handle_user_message|process_user_message|on_user_message|user_message_handler|input_handler|chat_handler)')),
    (TaintKind.USER_INPUT, re.compile(r'(read_stdin|stdin\(\))')),
    (TaintKind.USER_INPUT, re.compile(r'(?:args|env::args|std::env::args).*next')),

    # RAG_CONTEXT
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(retrieve|search|rag_query|retrieve_tool_result|vector_search|retrieve_context)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(grep_files|file_search|search_files)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(web_search|web_run)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(run_tests|run_verifiers|diagnostics)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(agent_open|rlm_open|tool_agent|sub_agent)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(review|read_code|analyze)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(read_file|load_file_content|read_project_file)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(list_dir|load_project|load_workspace)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(code_execution|validate_data)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(apply_patch|edit_file|write_file)')),
    (TaintKind.RAG_CONTEXT, re.compile(r'fn\s+(load_skill|render_skills|list_skills)')),

    # MCP_RESPONSE
    (TaintKind.MCP_RESPONSE, re.compile(r'fn\s+(mcp_call|call_mcp|mcp_client_call|invoke_mcp_tool|call_mcp_tool)')),
    (TaintKind.MCP_RESPONSE, re.compile(r'(McpClient|McpManager).*call_tool')),

    # MEMORY_READ
    (TaintKind.MEMORY_READ, re.compile(r'fn\s+(load_user_memory|load_memory|load_handoff_block|read_memory)')),
    (TaintKind.MEMORY_READ, re.compile(r'(?:append_entry|load_memory_block).*read')),  # file load then return

    # TOOL_RESULT
    (TaintKind.TOOL_RESULT, re.compile(r'fn\s+(execute_tool|invoke_tool|run_tool|handle_tool_call|dispatch_tool)')),
    (TaintKind.TOOL_RESULT, re.compile(r'fn\s+(retrieve_tool_result|get_tool_result)')),

    # WEB_FETCH
    (TaintKind.WEB_FETCH, re.compile(r'fn\s+(fetch_url|http_get|web_run|web_fetch|http_post|http_request)')),
    (TaintKind.WEB_FETCH, re.compile(r'reqwest::Client::new\(\)')),

    # FILE_CONTENT
    (TaintKind.FILE_CONTENT, re.compile(r'fn\s+(read_file|load_file|read_to_string|load_project_file|load_workspace_file)')),
    (TaintKind.FILE_CONTENT, re.compile(r'include_str!\s*\(')),
]

# Sink call patterns
SINK_CALL_PATTERNS = {
    SinkKind.TOOL_CALL: re.compile(r'(?:invoke_tool|execute_tool|dispatch_tool|tool_handler|handlers\.get|handlers\.insert|register_tool|tool_registry)'),
    SinkKind.SHELL_CMD: re.compile(r'(?:std::process|tokio::process)\s*::\s*Command\s*::\s*new'),
    SinkKind.SHELL_CMD: re.compile(r'Command\s*::\s*new\s*\(\s*"([^"]+)"'),
    SinkKind.FILE_PATH: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*(?:read|write|create|remove|open)\s*\('),
    SinkKind.FILE_WRITE: re.compile(r'(?:fs|std::fs|tokio::fs)\s*::\s*write\b|File::create|OpenOptions::new\(\)'),
    SinkKind.URL_FETCH: re.compile(r'reqwest\s*::\s*(?:Client|get|post)|\.send\(\)|ureq\s*::'),
    SinkKind.MEMORY_WRITE: re.compile(r'(?:append_entry|write_memory|save_to_memory|update_memory|fs::write.*?memory)'),
    SinkKind.MCP_REQUEST: re.compile(r'(?:McpClient|mcp_manager).*?(?:call_tool|send_request)'),
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


class FastRustTaintTracker:
    def __init__(self, source_dir: str | Path):
        self.source_dir = Path(source_dir)
        self.rs_files = [
            f for f in self.source_dir.rglob("*.rs")
            if not any(p in f.parts for p in {"target", "tests", "examples", "benches", ".git"})
        ]
        self.all_source: str = ""
        self.flows: list[TaintFlow] = []
        self._counter = 0
        # 按 file 缓存 source
        self.fn_bodies: dict[tuple[str, int], tuple[str, str]] = {}  # (file, line) -> (fn_name, body)
        self.fn_calls: dict[str, list[tuple[str, int, str]]] = {}  # fn_name -> [(file, line, body)]

    def track(self) -> list[TaintFlow]:
        t0 = time.time()
        # 1. 单次读取全部 .rs
        file_contents: dict[str, str] = {}
        total_lines = 0
        for path in self.rs_files:
            rel = str(path.relative_to(self.source_dir))
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                file_contents[rel] = content
                total_lines += content.count("\n")
            except Exception:
                pass
        print(f"  [i] Read {len(file_contents)} files, {total_lines} lines in {time.time()-t0:.1f}s")

        # 2. 构建 fn 索引 (file → [(fn_name, line, body)])
        t1 = time.time()
        fn_re = re.compile(
            r'((?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?(?:unsafe\s+)?fn\s+(\w+)\s*(?:<[^>]*>)?\s*\([^)]*\)\s*(?:->\s*[^{=;]+)?\s*)\{',
            re.MULTILINE
        )
        # 用 (file, fn_name, start_line) 索引
        fn_index: dict[str, list[tuple[str, int, int]]] = {}  # file -> [(fn_name, start, end)]
        for rel, content in file_contents.items():
            for m in fn_re.finditer(content):
                fn_name = m.group(2)
                brace_idx = m.end() - 1
                # 找配对的 }
                depth = 0
                i = brace_idx
                while i < len(content):
                    c = content[i]
                    if c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                        if depth == 0:
                            start_line = content[:m.start()].count("\n") + 1
                            end_line = content[:i].count("\n") + 1
                            fn_index.setdefault(rel, []).append((fn_name, start_line, end_line))
                            self.fn_calls.setdefault(fn_name, []).append((rel, start_line, content[m.start():i+1]))
                            break
                    i += 1
        print(f"  [i] Indexed {sum(len(v) for v in fn_index.values())} fn defs in {time.time()-t1:.1f}s")

        # 3. 找 source fn
        t2 = time.time()
        sources: list[dict] = []
        for rel, content in file_contents.items():
            for kind, pat in SOURCE_FN_PATTERNS:
                for m in pat.finditer(content):
                    line_no = content[:m.start()].count("\n") + 1
                    # 找所属 fn
                    owner = self._find_owner_fn(fn_index, rel, line_no)
                    if not owner:
                        continue
                    fn_name, fn_start, fn_end = owner
                    # 取 body
                    body = self._extract_body(content, fn_start, fn_end)
                    sources.append({
                        "kind": kind,
                        "fn": fn_name,
                        "file": rel,
                        "line": fn_start,
                        "body": body,
                    })
        # 去重
        seen = set()
        unique_sources = []
        for s in sources:
            key = (s["fn"], s["file"], s["line"])
            if key not in seen:
                seen.add(key)
                unique_sources.append(s)
        sources = unique_sources
        print(f"  [i] Found {len(sources)} unique source fns in {time.time()-t2:.1f}s")

        # 4. 对每个 source: body 内 + caller body 内找 sink
        t3 = time.time()
        for source in sources:
            # 4a. source body 内直接 sink
            for sink_kind, pat in SINK_CALL_PATTERNS.items():
                for m in pat.finditer(source["body"]):
                    line_no = source["line"] + source["body"][:m.start()].count("\n")
                    self._emit_flow(source, sink_kind, m.group(0), source["file"], line_no, [source["fn"]])

            # 4b. caller body 内 sink
            callers = self._find_callers_in_files(fn_index, file_contents, source["fn"], source["file"])
            for caller in callers[:5]:  # 限 5 caller 避免爆炸
                for sink_kind, pat in SINK_CALL_PATTERNS.items():
                    for m in pat.finditer(caller["body"]):
                        line_no = caller["line"] + caller["body"][:m.start()].count("\n")
                        self._emit_flow(source, sink_kind, m.group(0), caller["file"], line_no, [source["fn"], caller["fn"]])
        print(f"  [i] Traced {len(sources)} sources in {time.time()-t3:.1f}s")

        # 5. 去重 + 排序
        seen = set()
        unique_flows = []
        for f in self.flows:
            key = (f.source_kind, f.source_function, f.sink_kind, f.sink_call[:40], f.sink_file)
            if key not in seen:
                seen.add(key)
                unique_flows.append(f)
        self.flows = unique_flows

        return self.flows

    def _find_owner_fn(self, fn_index: dict, file: str, line: int) -> tuple[str, int, int] | None:
        for fn_name, start, end in fn_index.get(file, []):
            if start <= line <= end:
                return (fn_name, start, end)
        return None

    def _extract_body(self, content: str, start_line: int, end_line: int) -> str:
        lines = content.splitlines()
        if start_line <= 0 or start_line > len(lines):
            return ""
        s = start_line - 1
        e = min(end_line, len(lines))
        return "\n".join(lines[s:e])

    def _find_callers_in_files(self, fn_index, file_contents, fn_name: str, src_file: str) -> list[dict]:
        """找调用了 fn_name 的所有 fn（同 file + 跨 file）"""
        # 用 pat 加速
        pat = re.compile(rf'\b{re.escape(fn_name)}\s*\(')
        results = []
        for rel, content in file_contents.items():
            if not pat.search(content):
                continue
            for fn2_name, start, end in fn_index.get(rel, []):
                body = self._extract_body(content, start, end)
                if pat.search(body) and (fn2_name != fn_name or rel != src_file):
                    results.append({
                        "fn": fn2_name,
                        "file": rel,
                        "line": start,
                        "body": body,
                    })
        return results

    def _emit_flow(self, source, sink_kind, sink_match, sink_file, sink_line, path):
        self._counter += 1
        sanitizers = self._detect_sanitizers(source["body"])
        if len(path) > 1:
            # caller body
            # 简单: 看 source body 里的 sanitizer 数量
            pass
        self.flows.append(TaintFlow(
            flow_id=f"F{self._counter:03d}",
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
            severity=self._severity(source["kind"], sink_kind),
            description=f"{source['fn']} → {sink_kind.value}",
        ))

    def _detect_sanitizers(self, body: str) -> list[str]:
        found = []
        for sname, pat in RUST_SANITIZERS.items():
            if pat.search(body):
                found.append(sname)
        return found

    def _severity(self, kind, sink) -> str:
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


def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--output", default="taint_flows.json")
    args = ap.parse_args()

    tracker = FastRustTaintTracker(args.source)
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
