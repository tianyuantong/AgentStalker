"""
AgentStalker Sandbox Discovery
==============================
自动发现 Agent 类型与运行入口，用于沙箱适配器选择

输入：源码目录 + agent_model.json（可选）
输出：AgentProfile — 框架、入口点、暴露接口、运行时
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Literal


@dataclass
class AgentProfile:
    """Agent 运行时画像"""
    framework: str = "Unknown"        # LangChain / AutoGen / CrewAI / MCP / Custom / CodeWhale / Codex / Aider / Rig
    language: str = "Unknown"         # python / javascript / go / rust
    entry_points: list[str] = field(default_factory=list)
    exposed_endpoints: list[str] = field(default_factory=list)
    tools: list[dict] = field(default_factory=list)
    has_mcp_server: bool = False
    has_a2a_protocol: bool = False
    has_long_running: bool = False
    docker_runtime: str = "python"    # python | node | rust | custom
    startup_command: str = ""
    health_check: str = ""
    config_files: list[str] = field(default_factory=list)
    env_vars_required: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)
    recommended_adapter: str = "generic_api"
    recommended_executor: str = "api_executor"
    recommended_monitoring: list[str] = field(default_factory=list)
    # Rust-specific
    rust_binaries: list[str] = field(default_factory=list)
    rust_required_libs: list[str] = field(default_factory=list)  # e.g. libdbus-1, libssl3


# ============ 检测器 ============
class AgentDiscovery:
    def __init__(self, source_dir: str | Path):
        self.source_dir = Path(source_dir)
        self.profile = AgentProfile()

    def discover(self) -> AgentProfile:
        """主入口"""
        self._detect_language()
        self._detect_framework()
        self._detect_entry_points()
        self._detect_exposed_endpoints()
        self._detect_tools()
        self._detect_mcp_and_a2a()
        self._detect_config_and_env()
        self._detect_dependencies()
        self._recommend()
        return self.profile

    # ----- 语言 -----
    def _detect_language(self):
        py_files = list(self.source_dir.rglob("*.py"))
        js_files = list(self.source_dir.rglob("*.js")) + list(self.source_dir.rglob("*.ts"))
        go_files = list(self.source_dir.rglob("*.go"))
        rs_files = list(self.source_dir.rglob("*.rs"))

        # 显式 manifest 优先
        if (self.source_dir / "Cargo.toml").exists():
            self.profile.language = "rust"
            return
        if (self.source_dir / "go.mod").exists():
            self.profile.language = "go"
            return
        if (self.source_dir / "package.json").exists():
            self.profile.language = "javascript"
            return
        if any((self.source_dir / n).exists() for n in
               ["pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"]):
            self.profile.language = "python"
            return

        # 文件扩展名 fallback
        counts = {"python": len(py_files), "javascript": len(js_files), "go": len(go_files), "rust": len(rs_files)}
        self.profile.language = max(counts, key=counts.get) if max(counts.values()) > 0 else "unknown"

    # ----- 框架 -----
    def _detect_framework(self):
        scores = {"LangChain": 0, "AutoGen": 0, "CrewAI": 0, "MCP": 0, "LlamaIndex": 0, "LangGraph": 0, "OpenAI": 0,
                  "CodeWhale": 0, "Codex": 0, "Aider": 0, "Rig": 0, "AutoGen-RS": 0}

        # Python 文件
        for f in self.source_dir.rglob("*.py"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if re.search(r"from\s+langchain|import\s+langchain", content):
                scores["LangChain"] += 3
            if re.search(r"autogen|UserProxyAgent", content):
                scores["AutoGen"] += 3
            if re.search(r"crewai|from\s+crew\s+import|Crew\(", content):
                scores["CrewAI"] += 3
            if re.search(r"mcp\s+server|FastMCP|@server\.list_tools", content):
                scores["MCP"] += 3
            if re.search(r"llama_index|LlamaIndex|VectorStoreIndex", content):
                scores["LlamaIndex"] += 3
            if re.search(r"langgraph|StateGraph", content):
                scores["LangGraph"] += 3
            if re.search(r"openai|ChatOpenAI|Anthropic\s*\(", content):
                scores["OpenAI"] += 1

        # Rust 文件 — 框架指纹
        rust_patterns = {
            "CodeWhale": [r"CodeWhale|codewhale-tui", r"codewhale-cli", r"DEEPSEEK_TUI_BIN|deepseek-tui"],
            "Codex": [r"Codex|codex-rs|codex-cli"],
            "Aider": [r"aider-chat|\baider\b"],
            "Rig": [r"rig-core|use\s+rig::"],
            "AutoGen-RS": [r"autogen-rs|auto_gen_rs"],
        }
        for f in self.source_dir.rglob("*.rs"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for framework, pats in rust_patterns.items():
                for pat in pats:
                    if re.search(pat, content):
                        scores[framework] += 3

        # 也检查 Cargo.toml 的 [package] name
        for cargo in self.source_dir.rglob("Cargo.toml"):
            try:
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                if re.search(r'name\s*=\s*"codewhale', content):
                    scores["CodeWhale"] += 5
                if re.search(r'name\s*=\s*"codex', content):
                    scores["Codex"] += 5
                if re.search(r'name\s*=\s*"rig', content):
                    scores["Rig"] += 5
            except Exception:
                continue

        # 取最高分
        best = max(scores, key=scores.get)
        if scores[best] > 0:
            self.profile.framework = best

    # ----- 入口点 -----
    def _detect_entry_points(self):
        candidates = [
            "main.py", "app.py", "agent.py", "server.py",
            "run.py", "start.py", "main.js", "index.js", "server.js",
        ]
        for name in candidates:
            for f in self.source_dir.rglob(name):
                rel = str(f.relative_to(self.source_dir))
                if "__pycache__" in rel or "node_modules" in rel or "test" in rel:
                    continue
                self.profile.entry_points.append(rel)
                if not self.profile.startup_command:
                    if name.endswith(".py"):
                        self.profile.startup_command = f"python {rel}"
                    elif name.endswith(".js"):
                        self.profile.startup_command = f"node {rel}"

        # Rust 入口点: Cargo.toml 的 [[bin]] 段
        for cargo in self.source_dir.rglob("Cargo.toml"):
            try:
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                # Find [[bin]] sections
                for m in re.finditer(r'\[\[bin\]\]\s*name\s*=\s*"([^"]+)"\s*path\s*=\s*"([^"]+)"', content):
                    bin_name, bin_path = m.group(1), m.group(2)
                    self.profile.entry_points.append(f"{bin_name} (rust bin @ {bin_path})")
                    self.profile.rust_binaries.append(bin_name)
                # 简化形式 [[bin]] 只有 name
                for m in re.finditer(r'\[\[bin\]\]\s*name\s*=\s*"([^"]+)"', content):
                    if m.group(1) not in self.profile.rust_binaries:
                        self.profile.rust_binaries.append(m.group(1))
                        self.profile.entry_points.append(f"{m.group(1)} (rust bin)")
            except Exception:
                continue

        # Rust 必需的运行时库 (基于依赖推断 + 常见 lib 探测)
        for cargo in self.source_dir.rglob("Cargo.toml"):
            try:
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                # 直接依赖
                if re.search(r'\bdbus\s*=', content) or re.search(r'libdbus', content):
                    self.profile.rust_required_libs.append("libdbus-1-3")
                if re.search(r'openssl\s*=\s*"', content) or re.search(r'openssl-sys', content):
                    self.profile.rust_required_libs.append("libssl3")
                if re.search(r'\bgtk3?\b|gtk\s*=\s*"', content):
                    self.profile.rust_required_libs.append("libgtk-3-0")
                # 常见 Rust Agent 默认依赖
                if re.search(r'\bkeyring\s*=\s*"', content):
                    # keyring 在 Linux 上会拉 secret-service / dbus
                    self.profile.rust_required_libs.append("libdbus-1-3")
                if re.search(r'cfg\(target_os\s*=\s*"linux"\)', content):
                    # Linux-specific target deps 通常需要 dbus / openssl
                    self.profile.rust_required_libs.append("libdbus-1-3")
                if re.search(r'\bwebpki\b|rustls\b', content):
                    self.profile.rust_required_libs.append("ca-certificates")
                # workspace.dependencies 引用
                if re.search(r'keyring', content):
                    self.profile.rust_required_libs.append("libdbus-1-3")
            except Exception:
                continue

        # 读取 workspace root Cargo.toml 的 [workspace.dependencies] 段
        for cargo in [self.source_dir / "Cargo.toml"] + list(self.source_dir.rglob("Cargo.toml")):
            if not cargo.exists():
                continue
            try:
                content = cargo.read_text(encoding="utf-8", errors="ignore")
                if re.search(r'^\[workspace\.dependencies\]', content, re.MULTILINE):
                    if re.search(r'^\s*keyring\s*=', content, re.MULTILINE):
                        self.profile.rust_required_libs.append("libdbus-1-3")
                    if re.search(r'^\s*openssl(-sys)?\s*=', content, re.MULTILINE):
                        self.profile.rust_required_libs.append("libssl3")
            except Exception:
                continue

        # 默认加 ca-certificates (几乎所有 agent 都需要 HTTPS)
        if self.profile.rust_required_libs and "ca-certificates" not in self.profile.rust_required_libs:
            self.profile.rust_required_libs.append("ca-certificates")
        # 去重
        self.profile.rust_required_libs = list(set(self.profile.rust_required_libs))

        # Rust 启动命令
        if self.profile.language == "rust" and self.profile.rust_binaries:
            primary = self.profile.rust_binaries[0]
            self.profile.startup_command = f"./{primary}"

    # ----- HTTP 端点 -----
    def _detect_exposed_endpoints(self):
        patterns = [
            (r"@(?:app|router|api)\.(?:get|post|put|delete|patch)\(['\"]([^'\"]+)", "endpoint"),
            (r"@app\.route\(['\"]([^'\"]+)", "endpoint"),
        ]
        for f in self.source_dir.rglob("*.py"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            for pat, _ in patterns:
                for m in re.finditer(pat, content):
                    path = m.group(1)
                    if path not in self.profile.exposed_endpoints:
                        self.profile.exposed_endpoints.append(path)

    # ----- 工具定义 -----
    def _detect_tools(self):
        for f in self.source_dir.rglob("*.py"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue

            # @tool 装饰器
            for m in re.finditer(r"@tool\s*(?:\([^)]*\))?\s*(?:\n\s*)*(?:async\s+)?def\s+(\w+)", content):
                self.profile.tools.append({
                    "name": m.group(1),
                    "type": "function_tool",
                    "file": str(f.relative_to(self.source_dir)),
                })
            # BaseTool 子类
            for m in re.finditer(r"class\s+(\w+)\s*\(\s*BaseTool\s*\)", content):
                self.profile.tools.append({
                    "name": m.group(1),
                    "type": "base_tool",
                    "file": str(f.relative_to(self.source_dir)),
                })
            # MCP 工具
            for m in re.finditer(r"@(?:server|app)\.(?:list_tools|tool|call_tool)\s*\(", content):
                self.profile.has_mcp_server = True

    # ----- MCP / A2A -----
    def _detect_mcp_and_a2a(self):
        for f in self.source_dir.rglob("*"):
            try:
                content = f.read_text(encoding="utf-8", errors="ignore") if f.is_file() else ""
            except Exception:
                continue
            if re.search(r"@server\.list_tools|@server\.call_tool|FastMCP", content):
                self.profile.has_mcp_server = True
            if re.search(r"a2a\s+protocol|@agent2agent|google_a2a", content, re.IGNORECASE):
                self.profile.has_a2a_protocol = True
            if re.search(r"asyncio\.run|while\s+True:|@app\.on_event|websocket|polling", content):
                self.profile.has_long_running = True

    # ----- 配置 + 环境变量 -----
    def _detect_config_and_env(self):
        for name in [".env", ".env.example", "config.yaml", "config.yml", "config.json", "settings.py"]:
            if (self.source_dir / name).exists():
                self.profile.config_files.append(name)
        # 提取 .env 中的 key
        for env_file in self.source_dir.glob(".env*"):
            try:
                content = env_file.read_text(encoding="utf-8", errors="ignore")
                for m in re.finditer(r"^([A-Z][A-Z_0-9]+)\s*=", content, re.MULTILINE):
                    self.profile.env_vars_required.append(m.group(1))
            except Exception:
                continue

    # ----- 依赖 -----
    def _detect_dependencies(self):
        for req_file in ["requirements.txt", "pyproject.toml", "package.json", "go.mod"]:
            f = self.source_dir / req_file
            if f.exists():
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")
                    self.profile.dependencies = [
                        line.strip().split("==")[0].split(">=")[0].split("[")[0]
                        for line in content.splitlines()
                        if line.strip() and not line.startswith("#") and "=" not in line.split(" ")[0]
                    ][:50]
                except Exception:
                    pass

    # ----- 建议 -----
    def _recommend(self):
        # 适配器选择
        if self.profile.framework == "LangChain" and self.profile.language == "python":
            self.profile.recommended_adapter = "python_langchain"
            self.profile.recommended_executor = "api_executor"
        elif self.profile.framework == "AutoGen":
            self.profile.recommended_adapter = "python_autogen"
            self.profile.recommended_executor = "api_executor"
        elif self.profile.framework == "CrewAI":
            self.profile.recommended_adapter = "python_crewai"
            self.profile.recommended_executor = "api_executor"
        elif self.profile.framework == "MCP":
            self.profile.recommended_adapter = "python_mcp"
            self.profile.recommended_executor = "mcp_executor"
        elif self.profile.framework == "LangGraph":
            self.profile.recommended_adapter = "python_langgraph"
            self.profile.recommended_executor = "api_executor"
        # Rust 框架 — 全部走 cli_executor (二进制 stdin/stdout)
        elif self.profile.language == "rust":
            self.profile.docker_runtime = "rust"
            self.profile.recommended_adapter = "generic_api"
            self.profile.recommended_executor = "cli_executor"
            if self.profile.framework in ("CodeWhale", "Codex", "Aider", "Rig", "AutoGen-RS"):
                # 这些都是 stdio-based CLI agent, 用 cli_executor
                pass
        else:
            self.profile.recommended_adapter = "generic_api"
            self.profile.recommended_executor = self.profile.exposed_endpoints and "api_executor" or "cli_executor"

        # 监控建议
        self.profile.recommended_monitoring = ["network", "filesystem", "process"]
        if any("sql" in str(t).lower() for t in self.profile.tools):
            self.profile.recommended_monitoring.append("db_query")
        if any("shell" in str(t).lower() or "exec" in str(t).lower() for t in self.profile.tools):
            self.profile.recommended_monitoring.append("syscall")
        if any("email" in str(t).lower() or "send" in str(t).lower() for t in self.profile.tools):
            self.profile.recommended_monitoring.append("smtp")
        if self.profile.has_mcp_server:
            self.profile.recommended_monitoring.append("mcp_io")

        # 健康检查
        if self.profile.exposed_endpoints:
            self.profile.health_check = self.profile.exposed_endpoints[0]


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True)
    ap.add_argument("--output", default="agent_profile.json")
    args = ap.parse_args()

    discovery = AgentDiscovery(args.source)
    profile = discovery.discover()
    Path(args.output).write_text(json.dumps(asdict(profile), indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Framework: {profile.framework}")
    print(f"[+] Language: {profile.language}")
    print(f"[+] Entry: {profile.entry_points}")
    print(f"[+] Endpoints: {profile.exposed_endpoints[:5]}...")
    print(f"[+] Tools: {len(profile.tools)}")
    print(f"[+] Recommended adapter: {profile.recommended_adapter}")
    print(f"[+] Recommended executor: {profile.recommended_executor}")
    print(f"[+] Recommended monitoring: {profile.recommended_monitoring}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()