"""
AgentStalker Rust AST Extractor
================================
针对 Rust Agent 项目（Codex / Aider / Rig / AutoGen-RS / 自研 CLI）的静态安全提取器。

设计思路：
- 不用完整 Rust parser（太重），用正则 + 行级上下文分析
- 覆盖 Rust 特有抽象：trait impl / 宏 / Cargo.toml 依赖 / format! / writeln! / process::Command
- 输出与 Python 版 ast_extractor 兼容的 agent_model.json
- 重点识别：tool registry、execpolicy、prompt 层、memory、MCP

Author: AgentStalker v2.2
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ============ 数据模型 (与 Python 版兼容) ============
@dataclass
class ToolDef:
    name: str
    description: str = ""
    parameters_schema: dict = field(default_factory=dict)
    risk_level: str = "medium"
    requires_approval: bool = False
    scope: list[str] = field(default_factory=list)
    file: str = ""
    line: int = 0
    framework: str = ""  # "codex" / "aider" / "rig" / "generic"


@dataclass
class AgentModel:
    project: str
    type: str = "Custom Rust Agent"
    tools: list[ToolDef] = field(default_factory=list)
    system_prompts: list[dict] = field(default_factory=list)
    permissions: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    mcp_servers: list[dict] = field(default_factory=list)
    hitl: dict = field(default_factory=dict)
    observability: dict = field(default_factory=dict)
    dangerous_sinks: list[dict] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)
    dependencies: dict = field(default_factory=dict)
    prompt_layers: list[dict] = field(default_factory=list)
    files_scanned: int = 0


# ============ 模式识别 (Rust 特有) ============

# --- Tool 注册（Rust 通用模式）---
RUST_TOOL_PATTERNS = [
    # Rust 通用: ToolSpec / Action struct 形式的工具声明
    {
        "name": "rust_toolspec",
        "pattern": re.compile(r'(?:ToolSpec|LocalShellAction|WebSearchAction|FetchUrlAction)\s*\{\s*name:\s*["\']([\w_]+)["\']'),
        "framework": "rust-agent",
        "extract": "spec_name",
    },
    # Rust 通用: handler map 注册模式
    {
        "name": "rust_handler_register",
        "pattern": re.compile(r'handlers\.insert\(\s*["\']([\w_]+)["\']'),
        "framework": "rust-agent",
        "extract": "handler_name",
    },
    # Generic: impl Tool for X
    {
        "name": "generic_trait_impl",
        "pattern": re.compile(r'impl\s+(?:async\s+)?Tool\s+for\s+(\w+)'),
        "framework": "generic",
        "extract": "trait_impl",
    },
    # Rig: #[tool] 宏
    {
        "name": "rig_tool_macro",
        "pattern": re.compile(r'#\s*\[\s*tool\s*\]'),
        "framework": "rig",
        "extract": "tool_attr",
    },
    # 通用: tool_registry / ToolRegistry
    {
        "name": "tool_registry",
        "pattern": re.compile(r'(?:register_tool|ToolRegistry|register)\s*\(?\s*["\']?(\w+)'),
        "framework": "generic",
        "extract": "registry",
    },
]

# --- 危险 sink (Rust)---
RUST_SINKS = {
    # 命令执行
    "process_command": {
        "pattern": re.compile(r'(?:std::process|::process|tokio::process)\s*::\s*Command\s*::\s*new'),
        "sink": "command_execution",
        "severity": "critical",
        "sanitizer_hint": "execpolicy::rules?::check",
    },
    "process_spawn": {
        "pattern": re.compile(r'(?:std::process|tokio::process)\s*::\s*Command\s*::\s*(?:spawn|status|output)\s*\('),
        "sink": "command_spawn",
        "severity": "critical",
    },
    "shellexpand": {
        "pattern": re.compile(r'shellexpand::(?:full|tilde)\s*\('),
        "sink": "shell_expansion",
        "severity": "medium",
    },
    # 文件操作
    "fs_write": {
        "pattern": re.compile(r'(?:std::fs|tokio::fs)\s*::\s*(?:write|write_all|FOpenOptions::new).*\.create\(true\)'),
        "sink": "filesystem_write",
        "severity": "high",
    },
    "fs_read": {
        "pattern": re.compile(r'(?:std::fs|tokio::fs)\s*::\s*read(?:_to_string)?\s*\('),
        "sink": "filesystem_read",
        "severity": "medium",
    },
    "remove_file": {
        "pattern": re.compile(r'(?:std::fs|tokio::fs)\s*::\s*remove_(?:file|dir)\s*\('),
        "sink": "destructive_filesystem",
        "severity": "high",
    },
    # 网络
    "reqwest": {
        "pattern": re.compile(r'reqwest\s*::\s*(?:get|post|Client|ClientBuilder)|\.get\s*\(|\.post\s*\('),
        "sink": "http_request",
        "severity": "high",
    },
    "url_open": {
        "pattern": re.compile(r'url::Url::parse|Url\s*::\s*parse'),
        "sink": "url_parse",
        "severity": "low",
    },
    "ureq": {
        "pattern": re.compile(r'ureq\s*::\s*(?:get|post|request)'),
        "sink": "http_request",
        "severity": "high",
    },
    # 序列化 / 反序列化
    "serde_yaml": {
        "pattern": re.compile(r'serde_yaml\s*::\s*from_(?:str|slice|reader)\b'),
        "sink": "yaml_deserialization",
        "severity": "high",
    },
    "serde_json_userinput": {
        "pattern": re.compile(r'serde_json\s*::\s*from_(?:str|slice|value)\s*\(.*?(?:input|user|message|args|param)'),
        "sink": "json_deserialization",
        "severity": "high",
    },
    "bincode": {
        "pattern": re.compile(r'bincode\s*::\s*(?:deserialize|decode)'),
        "sink": "binary_deserialization",
        "severity": "critical",
    },
    # eval-like
    "lua_bind": {
        "pattern": re.compile(r'(?:rlua|mlua|hlua|rhai)\s*::\s*(?:Lua|Rhai)::new'),
        "sink": "script_engine",
        "severity": "critical",
    },
    # 加密 / secrets
    "keyring_access": {
        "pattern": re.compile(r'(?:keyring|secret_service)\s*::\s*(?:Entry|Entry::new)'),
        "sink": "credential_access",
        "severity": "high",
    },
    "env_secret": {
        "pattern": re.compile(r'std::env::var(?:_os)?\s*\(\s*["\']([A-Z_]+(?:KEY|TOKEN|SECRET|PASSWORD|API)[A-Z_]*)["\']'),
        "sink": "env_secret_read",
        "severity": "medium",
        "capture_group": 1,
    },
}

# --- System prompt 拼接 (Rust 风格)---
RUST_PROMPT_PATTERNS = {
    "format_into_prompt": re.compile(
        r'(?:format!|writeln!|write!|concat!|String::from)\s*[\(\s].*?(?:<|<\!)',
        re.DOTALL,
    ),
    "as_system_block": re.compile(
        r'(?:fn|pub fn|fn)\s+(?:as_system_block|load_.*?_block|render_.*?_block|build_.*?_prompt|system_prompt|build_prompt)\s*\('
    ),
    "load_markdown": re.compile(
        r'(?:fs::read_to_string|include_str!|tokio::fs::read_to_string)\s*\(\s*["\']([^"\']*\.(?:md|txt|prompt))["\']'
    ),
    "wrap_xml": re.compile(
        r'<\s*(\w+)(?:\s+source\s*=\s*["\'][^"\']+["\'])?\s*>',
    ),
    "include_str": re.compile(r'include_str!\s*\(\s*["\']([^"\']+)["\']\s*\)'),
}

# --- 权限 / 审批 (Rust agent 通用模式)---
RUST_PERMISSION_PATTERNS = {
    "ask_for_approval": re.compile(r'AskForApproval\s*::\s*(\w+)'),
    "approval_requirement": re.compile(r'ApprovalRequirement\s*::\s*(\w+)'),
    "tool_capability": re.compile(r'ToolCapability\s*::\s*(\w+)'),
    "ruleset_layer": re.compile(r'RulesetLayer\s*::\s*(\w+)'),
    "execpolicy_check": re.compile(r'(?:check_approval|check_command_safety|evaluate)\s*\('),
}

# --- 记忆 / RAG (Rust 风格)---
RUST_MEMORY_PATTERNS = {
    "append_entry": re.compile(r'(?:append_entry|append_to_memory|write_memory|save_memory)\s*\('),
    "load_memory": re.compile(r'(?:load_user_memory|load_memory|read_memory|recall)\s*\('),
    "as_system_block_mem": re.compile(r'<(?:user_memory|memory_block|session_goal|handoff_block)\b'),
    "memory_path": re.compile(r'memory\.(?:md|json|jsonl)|MEMORY_PATH'),
}

# --- MCP (Rust 风格)---
RUST_MCP_PATTERNS = {
    "mcpserverconfig": re.compile(r'McpServerConfig\s*\{'),
    "toolfilter": re.compile(r'ToolFilter\s*\{'),
    "mcp_call": re.compile(r'(?:mcp__|mcp::|McpClient|McpManager)'),
    "qualified_name": re.compile(r'mcp__\w+__\w+'),
    "stdio_transport": re.compile(r'(?:stdio|Stdio)\s*::\s*(?:Server|Client|Transport)'),
}

# --- Hooks / 反向通道 (Rust agent 通用)---
RUST_HOOK_PATTERNS = {
    "stdout_hook": re.compile(r'StdoutHookSink|JsonlHookSink|WebhookHookSink'),
    "webhook_url": re.compile(r'(?:webhook|url|endpoint)\s*:\s*["\'](https?://[^"\']+)["\']'),
    "secret_in_hook": re.compile(r'(?:key|token|secret)\s*:\s*["\']'),
}

# --- 入口点 (Rust)---
RUST_ENTRY_POINT_PATTERNS = {
    "tokio_main": re.compile(r'#\s*\[\s*(?:tokio::|async_std::)?main\s*\]'),
    "actix_route": re.compile(r'#\s*\[\s*(?:get|post|put|delete|patch|route)\s*\(\s*["\']([^"\']+)["\']'),
    "axum_route": re.compile(r'(?:\.route|\.get|\.post|\.put|\.delete)\s*\(\s*["\']([^"\']+)["\']'),
    "clap_subcommand": re.compile(r'#\s*\[\s*command\s*\(\s*(?:name\s*=\s*)?["\']([^"\']+)["\']'),
}


# ============ 提取器 ============
class RustASTExtractor:
    """Rust 项目 Agent 安全抽象提取器"""

    def __init__(self, source_dir: str | Path):
        self.source_dir = Path(source_dir)
        self.model = AgentModel(project=self.source_dir.name)
        self.rs_files: list[Path] = []
        self.cargo_toml: dict = {}
        self.all_source: str = ""

    def analyze(self) -> AgentModel:
        """主入口：扫描整个 Rust workspace"""
        # 1. 收集 .rs 文件
        self.rs_files = [
            f for f in self.source_dir.rglob("*.rs")
            if not self._is_excluded(f)
        ]
        self.model.files_scanned = len(self.rs_files)

        # 2. 解析 Cargo.toml
        self._parse_cargo_toml()

        # 3. 全文累积 (用于跨文件模式匹配)
        self.all_source = "\n".join(
            self._read_safe(f) for f in self.rs_files
        )

        # 4. 逐文件提取
        for path in self.rs_files:
            source = self._read_safe(path)
            if not source:
                continue
            self._extract_tools(source, path)
            self._extract_sinks(source, path)
            self._extract_prompts(source, path)
            self._extract_permissions(source, path)
            self._extract_memory(source, path)
            self._extract_mcp(source, path)
            self._extract_hooks(source, path)
            self._extract_entry_points(source, path)

        # 5. 提示词分层（基于累积 source）
        self._extract_prompt_layers()

        # 6. 整体评估
        self._assess_overall()

        return self.model

    def _is_excluded(self, path: Path) -> bool:
        parts = path.parts
        return any(p in parts for p in {
            "target", "node_modules", ".git", "tests", "test",
            "examples", "benches", "__pycache__",
        })

    def _read_safe(self, path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def to_json(self, indent=2) -> str:
        return json.dumps(self._model_to_dict(self.model), indent=indent, ensure_ascii=False)

    # ----- Cargo.toml -----
    def _parse_cargo_toml(self):
        """解析 workspace + 每个 crate 的 Cargo.toml"""
        toml_files = list(self.source_dir.rglob("Cargo.toml"))
        for tf in toml_files:
            if not self._is_excluded(tf):
                content = self._read_safe(tf)
                crate_name_m = re.search(r'^\s*name\s*=\s*"([^"]+)"', content, re.M)
                deps_block = re.findall(r'^\s*([\w-]+)\s*=\s*\{[^}]*\}', content, re.M)
                if crate_name_m:
                    self.cargo_toml[crate_name_m.group(1)] = {
                        "file": str(tf.relative_to(self.source_dir)),
                        "deps": deps_block[:30],
                    }
        # 关键 crates 摘要
        interesting = ["agent", "tools", "execpolicy", "mcp", "secrets",
                       "hooks", "tui", "protocol", "app-server", "core"]
        self.model.dependencies = {
            "total_crates": len(self.cargo_toml),
            "interesting": {
                k: v for k, v in self.cargo_toml.items()
                if any(i in k for i in interesting)
            }
        }

    # ----- 工具 -----
    def _extract_tools(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for pat_def in RUST_TOOL_PATTERNS:
            for m in pat_def["pattern"].finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                # 取名字
                if pat_def["extract"] == "spec_name":
                    name = m.group(1)
                elif pat_def["extract"] == "handler_name":
                    name = m.group(1)
                else:
                    name = m.group(0)[:40]
                # 风险启发
                risk = self._infer_tool_risk(name, source, line_no)
                self.model.tools.append(ToolDef(
                    name=name,
                    risk_level=risk,
                    requires_approval=self._check_approval_requirement(source, name, line_no),
                    framework=pat_def["framework"],
                    file=rel,
                    line=line_no,
                ))

    def _infer_tool_risk(self, name: str, source: str, line: int) -> str:
        text = (name + " " + self._ctx(source, line, 30)).lower()
        if any(k in text for k in ["shell", "exec", "command", "run", "spawn"]):
            return "critical"
        if any(k in text for k in ["delete", "remove", "drop", "send", "post", "publish", "transfer", "kill"]):
            return "high"
        if any(k in text for k in ["write", "update", "create", "modify", "edit", "patch", "save", "remember", "note"]):
            return "medium"
        if any(k in text for k in ["read", "search", "grep", "list", "get", "fetch", "retrieve", "view"]):
            return "low"
        return "medium"

    def _check_approval_requirement(self, source: str, name: str, line: int) -> bool:
        """检查该工具定义附近是否有 approval gate"""
        ctx = self._ctx(source, line, 50)
        return bool(re.search(
            r'(?:ApprovalRequirement::Forbidden|AskForApproval::OnFailure|requires_approval\s*=\s*true|ApprovalRequirement::(\w+))',
            ctx,
        ))

    # ----- 危险 sink -----
    def _extract_sinks(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for sink_name, defn in RUST_SINKS.items():
            for m in defn["pattern"].finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                ctx = self._ctx(source, line_no, 2)
                # 是否在 sanitizer 后
                has_sanitizer = bool(re.search(
                    defn.get("sanitizer_hint", r"$^"), ctx,
                ))
                # 是否在 fn exec_policy 之类 wrapper 内
                in_safe_wrapper = bool(re.search(
                    r'fn\s+(?:safe_.*?|check_.*?|validate_.*?)\s*\(', ctx,
                ))
                self.model.dangerous_sinks.append({
                    "sink_type": defn["sink"],
                    "pattern": sink_name,
                    "severity": defn["severity"],
                    "file": rel,
                    "line": line_no,
                    "context": ctx,
                    "has_sanitizer_nearby": has_sanitizer,
                    "in_safe_wrapper": in_safe_wrapper,
                    "match_text": m.group(0)[:80],
                })

    # ----- 提示词 -----
    def _extract_prompts(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for m in RUST_PROMPT_PATTERNS["as_system_block"].finditer(source):
            line_no = source[:m.start()].count("\n") + 1
            name_m = re.search(r'fn\s+(\w+)', m.group(0))
            name = name_m.group(1) if name_m else "?"
            # 检查 100 行内是否有 format!/writeln! 拼接用户/文件内容
            ctx = self._ctx(source, line_no, 100)
            has_user_input = bool(re.search(
                r'(?:user|input|message|args|content|file_content)\s*[:,)]', ctx
            ))
            has_file_read = bool(re.search(
                r'(?:fs::read|include_str|read_to_string)', ctx
            ))
            has_xml_wrap = "<" in ctx and ">" in ctx
            has_escape = bool(re.search(
                r'(?:escape|sanitize|html_escape|ammonia|sanitize_)', ctx,
            ))
            self.model.system_prompts.append({
                "fn": name,
                "file": rel,
                "line": line_no,
                "takes_user_input": has_user_input,
                "reads_file": has_file_read,
                "wrapped_xml": has_xml_wrap,
                "has_escape": has_escape,
                "vulnerability": (
                    "high" if (has_user_input or has_file_read) and not has_escape else "low"
                ),
            })

    # ----- 提示词分层（基于全文扫描）-----
    def _extract_prompt_layers(self):
        """识别 prompt 拼接链中的所有 layer / source"""
        # 找所有 "load_xxx" / "include_str!" 引用的 prompt 文件
        layer_patterns = [
            (r'include_str!\s*\(\s*["\']([^"\']+)["\']\s*\)', "include_str"),
            (r'fs::read_to_string\s*\(\s*["\']([^"\']+)["\']', "fs_read"),
            (r'fs::read\s*\(\s*["\']([^"\']+)["\']', "fs_read"),
        ]
        for pat, kind in layer_patterns:
            for m in re.finditer(pat, self.all_source):
                path = m.group(1)
                if any(path.endswith(ext) for ext in [".md", ".txt", ".prompt", "instructions"]):
                    self.model.prompt_layers.append({
                        "path": path,
                        "source_kind": kind,
                        "vulnerable_to_poison": True,
                        "wrap_expected": "XML",
                    })

    # ----- 权限 -----
    def _extract_permissions(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for name, pat in RUST_PERMISSION_PATTERNS.items():
            for m in pat.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                self.model.permissions.setdefault(name, []).append({
                    "file": rel,
                    "line": line_no,
                    "match": m.group(0)[:60],
                })

    # ----- 记忆 -----
    def _extract_memory(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for name, pat in RUST_MEMORY_PATTERNS.items():
            for m in pat.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                self.model.memory.setdefault("patterns_found", []).append({
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "match": m.group(0)[:60],
                })

    # ----- MCP -----
    def _extract_mcp(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for name, pat in RUST_MCP_PATTERNS.items():
            for m in pat.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                self.model.mcp_servers.append({
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "match": m.group(0)[:60],
                })

    # ----- Hooks -----
    def _extract_hooks(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for name, pat in RUST_HOOK_PATTERNS.items():
            for m in pat.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                # hooks 写入 url 如果是 webhook 且无 auth 标记
                self.model.observability.setdefault("hook_sinks", []).append({
                    "name": name,
                    "file": rel,
                    "line": line_no,
                    "match": m.group(0)[:60],
                })

    # ----- 入口点 -----
    def _extract_entry_points(self, source: str, path: Path):
        rel = str(path.relative_to(self.source_dir))
        for name, pat in RUST_ENTRY_POINT_PATTERNS.items():
            for m in pat.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                route = m.group(1) if m.lastindex else name
                self.model.entry_points.append({
                    "type": name,
                    "route": route,
                    "file": rel,
                    "line": line_no,
                })

    # ----- 整体评估 -----
    def _assess_overall(self):
        # HITL
        if "approval_requirement" in self.model.permissions or "ask_for_approval" in self.model.permissions:
            self.model.hitl = {
                "trigger": "deterministic",
                "evidence_pack": "execpolicy engine present",
                "ruleset_layers": self.model.permissions.get("ruleset_layer", []),
            }
        else:
            self.model.hitl = {"trigger": "unknown", "evidence_pack": False}

        # 可观测性
        has_otel = bool(re.search(r'opentelemetry|tracing::|trace|tracer', self.all_source))
        has_log = bool(re.search(r'#\s*\[\s*(?:tracing::)?instrument', self.all_source))
        self.model.observability.update({
            "tracing_present": has_log,
            "otel_present": has_otel,
            "audit_trail": "audit.rs" in self.all_source or "audit_log" in self.all_source,
        })

    # ----- 工具函数 -----
    def _ctx(self, source: str, line: int, span: int) -> str:
        lines = source.splitlines()
        s = max(0, line - span)
        e = min(len(lines), line + span)
        return "\n".join(lines[s:e])

    def _model_to_dict(self, model: AgentModel) -> dict:
        return {
            "project": model.project,
            "type": model.type,
            "language": "rust",
            "files_scanned": model.files_scanned,
            "tools": [asdict(t) for t in model.tools],
            "system_prompts": model.system_prompts,
            "permissions": model.permissions,
            "memory": model.memory,
            "mcp_servers": model.mcp_servers,
            "hitl": model.hitl,
            "observability": model.observability,
            "dangerous_sinks": model.dangerous_sinks,
            "entry_points": model.entry_points,
            "dependencies": model.dependencies,
            "prompt_layers": model.prompt_layers,
        }


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser(description="AgentStalker Rust AST Extractor")
    ap.add_argument("--source", required=True, help="Rust workspace 根目录")
    ap.add_argument("--output", default="agent_model.json")
    args = ap.parse_args()

    extractor = RustASTExtractor(args.source)
    model = extractor.analyze()
    Path(args.output).write_text(extractor.to_json(), encoding="utf-8")
    print(f"[+] Scanned {model.files_scanned} .rs files")
    print(f"[+] Crates: {len(extractor.cargo_toml)}")
    print(f"[+] Tools: {len(model.tools)}")
    print(f"[+] Sinks: {len(model.dangerous_sinks)}")
    print(f"[+] Prompts: {len(model.system_prompts)}")
    print(f"[+] MCP refs: {len(model.mcp_servers)}")
    print(f"[+] Hook sinks: {len(model.observability.get('hook_sinks', []))}")
    print(f"[+] Memory patterns: {len(model.memory.get('patterns_found', []))}")
    print(f"[+] Permissions: {sum(len(v) for v in model.permissions.values())}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()
