"""
AgentStalker AST Extractor
==========================
从 Agent 项目源码中静态提取安全抽象：
- 工具定义（tool / BaseTool / MCP / Function Calling）
- 系统提示词与指令边界
- 权限模型（role/permission 装饰器）
- 记忆/向量库读写接口
- MCP Server 注册
- 危险 sink（eval/exec/subprocess/...）

移植并适配自 codeaudit (Apache 2.0):
- 基于 Python `ast` 模块，无需第三方依赖
- 支持 LangChain、AutoGen、CrewAI、LlamaIndex、MCP 的常见模式
- 输出统一 agent_model.json 格式
"""
from __future__ import annotations

import ast
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ============ 数据模型 ============
@dataclass
class ToolDef:
    name: str
    description: str
    parameters_schema: dict = field(default_factory=dict)
    risk_level: str = "medium"          # low/medium/high/critical
    requires_approval: bool = False
    scope: list[str] = field(default_factory=list)
    file: str = ""
    line: int = 0


@dataclass
class AgentModel:
    project: str
    type: str                            # LangChain / AutoGen / MCP / Custom
    tools: list[ToolDef] = field(default_factory=list)
    system_prompts: list[dict] = field(default_factory=list)
    permissions: dict = field(default_factory=dict)
    memory: dict = field(default_factory=dict)
    mcp_servers: list[dict] = field(default_factory=list)
    hitl: dict = field(default_factory=dict)
    observability: dict = field(default_factory=dict)
    dangerous_sinks: list[dict] = field(default_factory=list)
    entry_points: list[dict] = field(default_factory=list)
    files_scanned: int = 0


# ============ 模式识别 ============
# LangChain
LANGCHAIN_PATTERNS = {
    "tool_decorator": re.compile(r"@tool\b"),
    "tool_class": re.compile(r"class\s+\w+\s*\(\s*BaseTool\s*\)"),
    "structured_tool": re.compile(r"StructuredTool\b"),
    "tool_call": re.compile(r"\.bind_tools\(|\.invoke\(|\.run\("),
    "agent_executor": re.compile(r"AgentExecutor\b"),
    "react_agent": re.compile(r"create_react_agent\b"),
    "openai_tools_agent": re.compile(r"create_openai_tools_agent\b"),
}

# AutoGen
AUTOGEN_PATTERNS = {
    "register_function": re.compile(r"register_function\b"),
    "user_proxy": re.compile(r"UserProxyAgent\b"),
    "assistant_agent": re.compile(r"AssistantAgent\b"),
    "group_chat": re.compile(r"GroupChat\b"),
}

# CrewAI
CREWAI_PATTERNS = {
    "crew": re.compile(r"\bCrew\b"),
    "agent_crewai": re.compile(r"class\s+\w+\s*\(\s*Agent\s*\)"),
    "task": re.compile(r"\bTask\b"),
}

# MCP
MCP_PATTERNS = {
    "server_class": re.compile(r"class\s+\w+\s*\(\s*(FastMCP|Server)\s*\)"),
    "list_tools": re.compile(r"@server\.list_tools|@list_tools"),
    "call_tool": re.compile(r"@server\.call_tool|@call_tool"),
    "stdio_transport": re.compile(r"stdio_server|stdio_client"),
    "sse_transport": re.compile(r"sse_server|sse_client"),
}

# 危险 sink
DANGEROUS_SINKS = {
    "eval": (re.compile(r"\beval\s*\("), "code_execution", "critical"),
    "exec": (re.compile(r"\bexec\s*\("), "code_execution", "critical"),
    "subprocess_shell": (re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"), "command_injection", "critical"),
    "os_system": (re.compile(r"os\.system\("), "command_injection", "critical"),
    "os_popen": (re.compile(r"os\.popen\("), "command_injection", "critical"),
    "pickle_loads": (re.compile(r"pickle\.(load|loads)\("), "deserialization", "critical"),
    "yaml_load_unsafe": (re.compile(r"yaml\.load\((?![^)]*Loader\s*=)"), "deserialization", "high"),
    "requests_no_verify": (re.compile(r"requests\.\w+\([^)]*verify\s*=\s*False"), "tls_bypass", "medium"),
    "shell_true": (re.compile(r"shell\s*=\s*True"), "command_injection", "high"),
}

# 提示词模式
PROMPT_PATTERNS = {
    "system_prompt_def": re.compile(r"^(?:SYSTEM_PROMPT|SYSTEM_MESSAGE|system_prompt|system_message)\s*=\s*['\"](.+?)['\"]", re.MULTILINE | re.DOTALL),
    "prompt_template": re.compile(r"(PromptTemplate|ChatPromptTemplate|SystemMessage)\s*\("),
    "fstring_prompt": re.compile(r"f\".*?\{(user_input|user_message|input|message).*?\}"),
    "format_prompt": re.compile(r"\.format\(.*?(user|input|message|context)"),
}

# 记忆模式
MEMORY_PATTERNS = {
    "buffer_memory": re.compile(r"ConversationBufferMemory\b"),
    "vector_memory": re.compile(r"VectorStoreRetrieverMemory\b"),
    "langgraph_memory": re.compile(r"(MemorySaver|PostgresSaver|RedisSaver)\b"),
    "llama_index_memory": re.compile(r"ChatMemoryBuffer\b"),
    "mcp_resources": re.compile(r"@server\.list_resources|@server\.read_resource"),
}

# 权限装饰器
PERMISSION_PATTERNS = {
    "requires_role": re.compile(r"@(?:requires_role|role_required|permission_required|requires_permission)\s*\("),
    "has_role": re.compile(r"\.has_role\(|has_perm\("),
    "is_admin": re.compile(r"\.is_admin\b|user\.is_superuser\b"),
    "role_tool_map": re.compile(r"(ROLE_TOOL_MAP|TOOL_PERMISSIONS|TOOL_ALLOWLIST)\s*="),
}

# API 入口点
ENTRY_POINT_PATTERNS = {
    "flask_route": re.compile(r"@(?:app|blueprint|bp)\.route\(['\"](.+?)['\"]"),
    "fastapi_route": re.compile(r"@(?:app|router)\.(get|post|put|delete|patch)\(['\"](.+?)['\"]"),
    "django_path": re.compile(r"path\(\s*['\"]([^'\"]+)['\"]"),
    "express_route": re.compile(r"(?:app|router)\.(get|post|put|delete)\(['\"]([^'\"]+)['\"]"),
}


# ============ AST 提取器 ============
class ASTExtractor:
    """从 Python 源文件提取 Agent 安全抽象"""

    def __init__(self, source_dir: str | Path):
        self.source_dir = Path(source_dir)
        self.model = AgentModel(project=source_dir.name, type="Unknown")

    def analyze(self) -> AgentModel:
        """主入口：扫描所有 .py 文件并填充 model"""
        py_files = list(self.source_dir.rglob("*.py"))
        py_files = [f for f in py_files if not self._is_excluded(f)]

        self.model.files_scanned = len(py_files)

        for path in py_files:
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # 框架识别
            self._detect_framework(source, path)
            # 工具定义
            self._extract_tools_from_source(source, path)
            # 提示词
            self._extract_prompts(source, path)
            # 权限
            self._extract_permissions(source, path)
            # 记忆
            self._extract_memory(source, path)
            # MCP
            self._extract_mcp(source, path)
            # 危险 sink
            self._extract_sinks(source, path)
            # 入口点
            self._extract_entry_points(source, path)

        # 评估整体风险
        self._assess_overall()
        return self.model

    def to_json(self, indent=2) -> str:
        return json.dumps(self._model_to_dict(self.model), indent=indent, ensure_ascii=False)

    def _is_excluded(self, path: Path) -> bool:
        parts = path.parts
        return any(p in parts for p in {"__pycache__", ".git", "node_modules", "venv", ".venv", "test", "tests"})

    # ----- 框架检测 -----
    def _detect_framework(self, source: str, path: Path):
        scores = {
            "LangChain": sum(1 for p in LANGCHAIN_PATTERNS.values() if p.search(source)),
            "AutoGen": sum(1 for p in AUTOGEN_PATTERNS.values() if p.search(source)),
            "CrewAI": sum(1 for p in CREWAI_PATTERNS.values() if p.search(source)),
            "MCP": sum(1 for p in MCP_PATTERNS.values() if p.search(source)),
        }
        # 取最高分
        if max(scores.values()) > 0:
            detected = max(scores, key=scores.get)
            if detected != "Unknown":
                self.model.type = detected

    # ----- 工具定义 -----
    def _extract_tools_from_source(self, source: str, path: Path):
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return

        for node in ast.walk(tree):
            # @tool 装饰器
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(self._is_tool_decorator(d) for d in node.decorator_list):
                    doc = ast.get_docstring(node) or ""
                    # 提取参数 schema（粗略）
                    args = [a.arg for a in node.args.args]
                    tool = ToolDef(
                        name=node.name,
                        description=doc.strip()[:500],
                        parameters_schema={"params": args},
                        risk_level=self._infer_risk_from_name(node.name, doc),
                        file=str(path.relative_to(self.source_dir)),
                        line=node.lineno,
                    )
                    self.model.tools.append(tool)

            # BaseTool 子类
            elif isinstance(node, ast.ClassDef):
                bases = [b.id if isinstance(b, ast.Name) else getattr(b, "attr", "") for b in node.bases]
                if "BaseTool" in bases or "StructuredTool" in bases:
                    doc = ast.get_docstring(node) or ""
                    tool = ToolDef(
                        name=node.name,
                        description=doc.strip()[:500],
                        risk_level=self._infer_risk_from_name(node.name, doc),
                        file=str(path.relative_to(self.source_dir)),
                        line=node.lineno,
                    )
                    self.model.tools.append(tool)

    def _is_tool_decorator(self, dec: ast.expr) -> bool:
        """判断装饰器是否为 @tool / @something.tool"""
        if isinstance(dec, ast.Call):
            func = dec.func
            if isinstance(func, ast.Name) and func.id == "tool":
                return True
            if isinstance(func, ast.Attribute) and func.attr == "tool":
                return True
        elif isinstance(dec, ast.Name) and dec.id == "tool":
            return True
        return False

    def _infer_risk_from_name(self, name: str, doc: str) -> str:
        """基于工具名/描述启发式推断风险等级"""
        text = (name + " " + doc).lower()
        if any(k in text for k in ["shell", "exec", "command", "code", "eval"]):
            return "critical"
        if any(k in text for k in ["delete", "remove", "drop", "refund", "send_email", "publish", "transfer", "payment"]):
            return "high"
        if any(k in text for k in ["write", "update", "create", "post", "put", "modify", "save"]):
            return "medium"
        return "low"

    # ----- 提示词 -----
    def _extract_prompts(self, source: str, path: Path):
        for m in PROMPT_PATTERNS["system_prompt_def"].finditer(source):
            prompt_text = m.group(1)
            line_no = source[:m.start()].count("\n") + 1

            # 划分指令/数据区（启发式）
            instruction_keywords = ["you must", "you should", "never", "always", "do not", "禁止", "必须"]
            data_placeholders = re.findall(r"\{(\w+)\}", prompt_text)

            has_fstring = bool(PROMPT_PATTERNS["fstring_prompt"].search(source))
            has_format = bool(PROMPT_PATTERNS["format_prompt"].search(source))

            self.model.system_prompts.append({
                "file": str(path.relative_to(self.source_dir)),
                "line": line_no,
                "raw_preview": prompt_text[:300] + "..." if len(prompt_text) > 300 else prompt_text,
                "instruction_keywords_found": [k for k in instruction_keywords if k in prompt_text.lower()],
                "data_placeholders": data_placeholders,
                "uses_fstring": has_fstring,
                "uses_format": has_format,
                "risk": "high" if (has_fstring or has_format) and data_placeholders else "low"
            })

    # ----- 权限 -----
    def _extract_permissions(self, source: str, path: Path):
        for name, pattern in PERMISSION_PATTERNS.items():
            for m in pattern.finditer(source):
                if name not in self.model.permissions:
                    self.model.permissions[name] = []
                self.model.permissions[name].append({
                    "file": str(path.relative_to(self.source_dir)),
                    "line": source[:m.start()].count("\n") + 1,
                    "match": m.group(0)
                })

    # ----- 记忆 -----
    def _extract_memory(self, source: str, path: Path):
        for name, pattern in MEMORY_PATTERNS.items():
            if pattern.search(source):
                if "type" not in self.model.memory:
                    self.model.memory["type"] = name
                self.model.memory.setdefault("occurrences", []).append({
                    "file": str(path.relative_to(self.source_dir)),
                    "line": source[:pattern.search(source).start()].count("\n") + 1,
                })

    # ----- MCP -----
    def _extract_mcp(self, source: str, path: Path):
        for m in MCP_PATTERNS["list_tools"].finditer(source):
            # 找临近的 @server.list_tools() 上方的注释作为 server 名称
            line_no = source[:m.start()].count("\n") + 1
            self.model.mcp_servers.append({
                "file": str(path.relative_to(self.source_dir)),
                "line": line_no,
                "trust": "unknown",  # 静态无法判断
                "tools_declared": True
            })

    # ----- 危险 sink -----
    def _extract_sinks(self, source: str, path: Path):
        for name, (pattern, sink_type, severity) in DANGEROUS_SINKS.items():
            for m in pattern.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                # 提取上下文（前后 2 行）
                lines = source.splitlines()
                ctx_start = max(0, line_no - 2)
                ctx_end = min(len(lines), line_no + 2)
                self.model.dangerous_sinks.append({
                    "sink_type": sink_type,
                    "pattern": name,
                    "severity": severity,
                    "file": str(path.relative_to(self.source_dir)),
                    "line": line_no,
                    "context": "\n".join(lines[ctx_start:ctx_end])
                })

    # ----- 入口点 -----
    def _extract_entry_points(self, source: str, path: Path):
        for name, pattern in ENTRY_POINT_PATTERNS.items():
            for m in pattern.finditer(source):
                line_no = source[:m.start()].count("\n") + 1
                self.model.entry_points.append({
                    "type": name,
                    "route": m.group(1) if m.lastindex else m.group(0),
                    "file": str(path.relative_to(self.source_dir)),
                    "line": line_no
                })

    # ----- 整体评估 -----
    def _assess_overall(self):
        """基于收集的信息评估整体安全态势"""
        # HITL 启发式判断
        if not self.model.permissions:
            self.model.hitl = {"trigger": "unknown", "evidence_pack": False}
        else:
            self.model.hitl = {"trigger": "deterministic_partial", "evidence_pack": False}

        # 可观测性启发式
        has_observability = False
        for f in self.source_dir.rglob("*.py"):
            try:
                s = f.read_text(errors="ignore")
                if any(k in s for k in ["trace_id", "tracer", "langfuse", "opentelemetry", "arize"]):
                    has_observability = True
                    break
            except Exception:
                continue
        self.model.observability = {
            "trace": has_observability,
            "evals": (self.source_dir / "evals").exists()
        }

    def _model_to_dict(self, model: AgentModel) -> dict:
        """转换为可序列化字典"""
        return {
            "project": model.project,
            "type": model.type,
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
        }


# ============ 语言检测 + Dispatch ============
def detect_language(source_dir: Path) -> str:
    """检测 Agent 项目主要语言 (Python / Rust / Node / Go)

    启发式优先级:
    1. Cargo.toml    → rust
    2. package.json  → node
    3. go.mod        → go
    4. pyproject.toml / requirements.txt / setup.py → python
    5. .py 文件占多数 → python (fallback)
    """
    source_dir = Path(source_dir)
    if not source_dir.exists():
        return "unknown"

    # 显式 manifest 优先
    if (source_dir / "Cargo.toml").exists():
        return "rust"
    if (source_dir / "go.mod").exists():
        return "go"
    if (source_dir / "package.json").exists():
        return "node"
    if any((source_dir / name).exists() for name in
           ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"]):
        return "python"

    # 文件扩展名 fallback
    counts = {"py": 0, "rs": 0, "js": 0, "ts": 0, "go": 0}
    for p in source_dir.rglob("*"):
        if not p.is_file():
            continue
        if any(x in p.parts for x in {"node_modules", ".git", "target", "dist", "build", "__pycache__", "venv", ".venv"}):
            continue
        ext = p.suffix.lstrip(".")
        if ext in counts:
            counts[ext] += 1

    detected = max(counts, key=counts.get)
    return detected if counts[detected] > 0 else "unknown"


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser(
        description="AgentStalker AST Extractor (auto-detect Python / Rust / Node / Go)"
    )
    ap.add_argument("--source", required=True, help="Agent 项目源码目录")
    ap.add_argument("--output", default="agent_model.json", help="输出文件")
    ap.add_argument("--language", default=None,
                    choices=["python", "rust", "node", "go", "auto"],
                    help="强制指定语言 (默认: auto-detect)")
    ap.add_argument("--multi", action="store_true",
                    help="多语言项目: 扫描所有语言并合并结果")
    args = ap.parse_args()

    source = Path(args.source)
    language = args.language if args.language and args.language != "auto" else detect_language(source)
    print(f"[*] Detected language: {language}")

    # 多语言模式: 扫描所有启用的 extractor 并合并
    if args.multi:
        all_models = []
        if (source.rglob("*.py") and any(True for _ in source.rglob("*.py"))):
            print(f"[+] Scanning Python files...")
            m = ASTExtractor(source).analyze()
            all_models.append(("python", m))
        if (source / "Cargo.toml").exists():
            print(f"[+] Scanning Rust files...")
            try:
                from core.ast_extractor_rust import RustASTExtractor
                m = RustASTExtractor(source).analyze()
                all_models.append(("rust", m))
            except ImportError as e:
                print(f"[!] Rust extractor unavailable: {e}")
        if (source / "package.json").exists():
            print(f"[!] Node/TS extractor not yet implemented (skipping)")
        # 合并: 简单追加所有 tools / sinks / prompts
        merged = _merge_models(all_models)
        Path(args.output).write_text(json.dumps(merged, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[+] Merged {len(all_models)} language models → {args.output}")
        return

    # 单语言模式: dispatch
    if language == "rust":
        # 当 skill 目录不在 sys.path 时, 用 importlib + 临时 sys.path 注入加载
        import sys
        import importlib.util
        rust_path = Path(__file__).parent / "ast_extractor_rust.py"
        if "core.ast_extractor_rust" not in sys.modules:
            spec = importlib.util.spec_from_file_location("core.ast_extractor_rust", rust_path)
            mod = importlib.util.module_from_spec(spec)
            sys.modules["core.ast_extractor_rust"] = mod
            spec.loader.exec_module(mod)
        RustASTExtractor = sys.modules["core.ast_extractor_rust"].RustASTExtractor

        extractor = RustASTExtractor(source)
        model = extractor.analyze()
        Path(args.output).write_text(extractor.to_json(), encoding="utf-8")
        print(f"[+] Scanned {model.files_scanned} .rs files")
        print(f"[+] Crates: {len(extractor.cargo_toml)}")
        print(f"[+] Tools: {len(model.tools)}")
        print(f"[+] Sinks: {len(model.dangerous_sinks)}")
        print(f"[+] Prompts: {len(model.system_prompts)}")
        print(f"[+] MCP refs: {len(model.mcp_servers)}")
        print(f"[+] Memory patterns: {len(model.memory.get('patterns_found', []))}")
        print(f"[+] Output: {args.output}")
    else:
        # Python (默认路径)
        extractor = ASTExtractor(source)
        model = extractor.analyze()
        Path(args.output).write_text(extractor.to_json(), encoding="utf-8")
        print(f"[+] Scanned {model.files_scanned} files")
        print(f"[+] Detected framework: {model.type}")
        print(f"[+] Found {len(model.tools)} tools")
        print(f"[+] Found {len(model.dangerous_sinks)} dangerous sinks")
        print(f"[+] Found {len(model.entry_points)} entry points")
        print(f"[+] Output: {args.output}")


def _merge_models(language_models: list) -> dict:
    """合并多语言 extractor 的输出 (去重 by file:line)"""
    merged = {
        "project": "",
        "languages": [],
        "type": "Multi-Language",
        "files_scanned": 0,
        "tools": [],
        "system_prompts": [],
        "permissions": {},
        "memory": {},
        "mcp_servers": [],
        "hitl": {"trigger": "unknown", "evidence_pack": False},
        "observability": {},
        "dangerous_sinks": [],
        "entry_points": [],
    }
    for lang, m in language_models:
        merged["languages"].append(lang)
        if not merged["project"]:
            merged["project"] = m.project
        merged["files_scanned"] += m.files_scanned
        # 去重 by (file, line, name)
        seen_tools = {(t.get("file", ""), t.get("line", 0), t.get("name", "")) for t in merged["tools"]}
        for t in m.tools:
            tdict = t if isinstance(t, dict) else t.__dict__
            key = (tdict.get("file", ""), tdict.get("line", 0), tdict.get("name", ""))
            if key not in seen_tools:
                merged["tools"].append(tdict)
                seen_tools.add(key)
        # 同样方式处理 sinks / prompts (省略以节省空间)
        merged["dangerous_sinks"].extend(s for s in m.dangerous_sinks if s not in merged["dangerous_sinks"])
        merged["system_prompts"].extend(p for p in m.system_prompts if p not in merged["system_prompts"])
        merged["mcp_servers"].extend(s for s in m.mcp_servers if s not in merged["mcp_servers"])
    return merged


if __name__ == "__main__":
    main()
