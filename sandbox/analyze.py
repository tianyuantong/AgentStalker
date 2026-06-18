"""
AgentStalker Project Analyzer
=============================
扫描被测 Agent 源码，输出结构化 JSON。
Claude Code 据此决定：使用哪个 Dockerfile 模板 / 端口 / LLM key 注入策略。

⚠️ 此模块**只做静态分析**——不生成文件、不启动容器、不发请求。
   文件生成由 Claude Code 调用 jinja2 模板完成。
   容器启动由 Claude Code 调用 docker compose 完成。
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class ProjectAnalysis:
    language: str = "unknown"
    framework: str = "unknown"
    entry_point: str = ""
    package_manager: str = ""
    deps_file: str = ""
    port: int = 8000
    health_path: str = "/health"
    env_vars_required: list[str] = field(default_factory=list)
    has_dockerfile: bool = False
    has_compose: bool = False
    install_command: str = ""
    run_command: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def analyze(source_dir: str | Path) -> ProjectAnalysis:
    """扫描源码目录，输出分析结果

    Claude Code 调用方式:
        python -m sandbox.analyze --source ./my-agent
    """
    src = Path(source_dir)
    a = ProjectAnalysis()
    a.notes = []

    # ---- 1. 语言与包管理 ----
    if (src / "pyproject.toml").exists() or (src / "requirements.txt").exists() or (src / "setup.py").exists():
        a.language = "python"
        if (src / "requirements.txt").exists():
            a.deps_file = "requirements.txt"
            a.package_manager = "pip"
            a.install_command = "pip install --no-cache-dir -r requirements.txt"
        elif (src / "pyproject.toml").exists():
            a.deps_file = "pyproject.toml"
            content = (src / "pyproject.toml").read_text(errors="ignore")
            if "[tool.poetry]" in content:
                a.package_manager = "poetry"
                a.install_command = "poetry install --no-interaction --no-ansi"
            elif "[tool.uv]" in content or (src / "uv.lock").exists():
                a.package_manager = "uv"
                a.install_command = "uv pip install --system -r requirements.txt"
            else:
                a.package_manager = "pip"
                a.install_command = "pip install -e ."
    elif (src / "package.json").exists():
        a.language = "node"
        a.deps_file = "package.json"
        if (src / "pnpm-lock.yaml").exists():
            a.package_manager = "pnpm"
        elif (src / "yarn.lock").exists():
            a.package_manager = "yarn"
        else:
            a.package_manager = "npm"
        a.install_command = f"{a.package_manager} install --no-audit --no-fund"
    elif (src / "go.mod").exists():
        a.language = "go"
        a.deps_file = "go.mod"
        a.install_command = "go mod download"
    elif (src / "Cargo.toml").exists():
        a.language = "rust"
        a.deps_file = "Cargo.toml"
        a.notes.append("Rust 项目需自定义 Dockerfile，模板未覆盖")
    elif (src / "pom.xml").exists() or (src / "build.gradle").exists():
        a.language = "java"
        a.deps_file = "pom.xml" if (src / "pom.xml").exists() else "build.gradle"
        a.notes.append("Java 项目需自定义 Dockerfile，模板未覆盖")

    # ---- 2. 框架识别 ----
    deps_content = ""
    if a.deps_file and (src / a.deps_file).exists():
        deps_content = (src / a.deps_file).read_text(errors="ignore").lower()
    if "langchain" in deps_content:
        a.framework = "langchain"
    elif "crewai" in deps_content:
        a.framework = "crewai"
    elif "autogen" in deps_content:
        a.framework = "autogen"
    elif "llama-index" in deps_content or "llama_index" in deps_content:
        a.framework = "llamaindex"
    elif "fastapi" in deps_content or "flask" in deps_content or "django" in deps_content:
        a.framework = "custom-api"

    # ---- 3. 入口点 ----
    for candidate in ["main.py", "app.py", "server.py", "agent.py", "src/main.py", "src/app.py", "index.js", "index.ts", "cmd/main.go"]:
        if (src / candidate).exists():
            a.entry_point = candidate
            break
    if not a.entry_point and a.language == "python":
        py_files = list(src.glob("*.py"))
        if py_files:
            a.entry_point = py_files[0].name
            a.notes.append(f"未找到常见入口，回退到第一个 .py: {a.entry_point}")

    # ---- 4. 端口推断 ----
    port_pat = re.compile(r"(?:port|listen)\s*[=:]\s*(\d{4,5})", re.IGNORECASE)
    for f in src.rglob("*.py"):
        try:
            for m in port_pat.finditer(f.read_text(errors="ignore")):
                p = int(m.group(1))
                if 1024 < p < 65535:
                    a.port = p
                    break
            if a.port != 8000:
                break
        except Exception:
            continue
    if a.port == 8000 and a.language == "node":
        a.port = 3000

    # ---- 5. 健康检查路径 ----
    for f in src.rglob("*.py"):
        try:
            text = f.read_text(errors="ignore")
            if any(p in text for p in ['@app.get("/health"', 'path="/health"', "GET /health"]):
                a.health_path = "/health"
                break
        except Exception:
            continue

    # ---- 6. 必需环境变量 ----
    env_needed: set[str] = set()
    for f in src.rglob("*.py"):
        try:
            text = f.read_text(errors="ignore")
            for m in re.finditer(r"os\.environ\.get\(\s*['\"](\w+)['\"]", text):
                env_needed.add(m.group(1))
            for m in re.finditer(r"os\.environ\[\s*['\"](\w+)['\"]", text):
                env_needed.add(m.group(1))
        except Exception:
            continue
    # 排除常见不需要注入的
    env_needed -= {"PATH", "HOME", "USER", "LANG", "SHELL", "PWD"}
    a.env_vars_required = sorted(env_needed)

    # ---- 7. 已有 Docker 配置 ----
    a.has_dockerfile = (src / "Dockerfile").exists()
    a.has_compose = any((src / f).exists() for f in ["docker-compose.yml", "docker-compose.yaml", "compose.yml"])

    # ---- 8. 默认运行命令 ----
    if a.language == "python" and a.entry_point:
        mod = a.entry_point.replace(".py", "").replace("/", ".").replace("\\\\", ".")
        a.run_command = f"uvicorn {mod}:app --host 0.0.0.0 --port {a.port}"
    elif a.language == "node":
        a.run_command = f"{a.package_manager} start"

    return a


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser(description="AgentStalker 项目分析（只读）")
    ap.add_argument("--source", required=True)
    ap.add_argument("--output", help="输出 JSON 路径（默认 stdout）")
    args = ap.parse_args()

    result = analyze(args.source)
    text = json.dumps(result.to_dict(), indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"[+] Written to {args.output}")
    else:
        print(text)


if __name__ == "__main__":
    main()
