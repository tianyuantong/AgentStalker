"""
AgentStalker Heal Diagnose — 错误诊断辅助
=========================================
只做一件事：把错误文本与 sandbox/data/heal_signatures.yaml 匹配，输出建议。
⚠️ **不执行任何修复动作**——Claude Code 用 Bash 工具自己决定是否执行。

Claude Code 调用模式:
    # 1. 部署失败时
    err=$(docker compose up 2>&1)
    python -m sandbox.heal_diagnose --error-text "$err" --json

    # 2. Claude Code 收到 JSON 输出
    #    {matched: true, signature: {category, suggested_action, action_param, max_retries, requires_user}, hint: "..."}
    # 3. Claude Code 自行判断:
    #    - requires_user=true → 用 AskUserQuestion 问用户
    #    - requires_user=false → 用 Bash 工具执行对应修复命令
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any


@dataclass
class HealSignature:
    category: str
    description: str
    pattern: str
    suggested_action: str
    action_param: str = ""
    max_retries: int = 3
    requires_user: bool = False


@dataclass
class DiagnoseResult:
    matched: bool
    category: str = ""
    description: str = ""
    suggested_action: str = ""
    action_param: str = ""
    max_retries: int = 0
    requires_user: bool = False
    hint: str = ""
    extracted_vars: dict = field(default_factory=dict)


def load_kb(path: str | Path = None) -> list[HealSignature]:
    """从 YAML 加载错误签名库"""
    try:
        import yaml
    except ImportError:
        return []
    if path is None:
        path = Path(__file__).parent / "data" / "heal_signatures.yaml"
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    sigs = []
    for s in data.get("signatures", []):
        sigs.append(HealSignature(
            category=s["category"],
            description=s["description"],
            pattern=s["pattern"],
            suggested_action=s["suggested_action"],
            action_param=s.get("action_param", ""),
            max_retries=s.get("max_retries", 3),
            requires_user=s.get("requires_user", False),
        ))
    return sigs


def diagnose(error_text: str, kb: list[HealSignature] | None = None) -> DiagnoseResult:
    """诊断错误文本，匹配第一个命中的签名

    Args:
        error_text: 错误日志（来自 docker compose / docker run / curl 等）
        kb: 签名库（默认从 YAML 加载）

    Returns:
        DiagnoseResult；未匹配时 matched=False
    """
    if kb is None:
        kb = load_kb()

    for sig in kb:
        m = re.search(sig.pattern, error_text, re.IGNORECASE | re.MULTILINE)
        if m:
            # 提取捕获组（如缺失的模块名）
            extracted = {f"group_{i+1}": g for i, g in enumerate(m.groups()) if g}

            hint = ""
            try:
                import yaml
                data = yaml.safe_load((Path(__file__).parent / "data" / "heal_signatures.yaml").read_text(encoding="utf-8"))
                if sig.requires_user:
                    hints = data.get("hard_boundaries", {}).get("user_prompt_hints", {})
                    hint = hints.get(sig.action_param, f"需要用户介入: {sig.action_param}")
                else:
                    # 优先用签名自身的 hint, 否则用 defaults
                    sig_raw = next((s for s in data.get("signatures", []) if s.get("pattern") == sig.pattern), {})
                    hint = sig_raw.get("hint", "")
            except Exception:
                hint = f"⚠️ 硬边界: {sig.action_param} 需要用户确认" if sig.requires_user else ""

            return DiagnoseResult(
                matched=True,
                category=sig.category,
                description=sig.description,
                suggested_action=sig.suggested_action,
                action_param=sig.action_param,
                max_retries=sig.max_retries,
                requires_user=sig.requires_user,
                hint=hint,
                extracted_vars=extracted,
            )

    return DiagnoseResult(matched=False)


# ============ 建议的修复命令（仅文字描述，由 Claude Code 自行执行）============
SUGGESTED_COMMANDS = {
    "edit_dockerfile": "Claude Code 用 Read+Edit 工具修改 ./output/agent.Dockerfile",
    "edit_compose": "Claude Code 用 Read+Edit 工具修改 ./output/docker-compose.override.yml",
    "edit_requirements": "Claude Code 修改 ./agent/requirements.txt（或对应路径）",
    "add_dependency": "Claude Code 在 requirements.txt 添加 {package} 并重建",
    "add_privileged": "Claude Code 在 compose.override.yml 加 privileged: true 到 ebpf-monitor",
    "restart_container": "docker restart {container}",
    "increase_timeout": "Claude Code 修改 healthcheck start-period 至 30s；或 curl 加 -m 60",
    "recreate_network": "docker network create agent-net && 重启容器",
    "clean_volumes": "docker system prune -f && docker volume prune -f",
    "prompt_user": "⚠️ Claude Code 必须用 AskUserQuestion 询问用户",
    "abort": "停止并报告 — Claude Code 向用户呈现错误",
}


# ============ CLI ============
def main():
    ap = argparse.ArgumentParser(description="AgentStalker 错误诊断（只读，不执行）")
    ap.add_argument("--error-text", help="错误文本")
    ap.add_argument("--error-file", help="从文件读取错误")
    ap.add_argument("--json", action="store_true", help="输出 JSON 格式")
    ap.add_argument("--verbose", action="store_true", help="显示建议的修复命令")
    args = ap.parse_args()

    if args.error_file:
        text = Path(args.error_file).read_text(errors="ignore")
    elif args.error_text:
        text = args.error_text
    elif not sys.stdin.isatty():
        import sys
        text = sys.stdin.read()
    else:
        print("请提供 --error-text / --error-file / 通过 stdin 输入", file=sys.stderr)
        return 1

    result = diagnose(text)

    if args.json:
        output = asdict(result)
        if args.verbose and result.suggested_action:
            output["suggested_command"] = SUGGESTED_COMMANDS.get(
                result.suggested_action, "(unknown action)"
            )
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        if result.matched:
            print(f"[✓] 匹配: {result.category} - {result.description}")
            print(f"    建议动作: {result.suggested_action} (param: {result.action_param})")
            print(f"    最多重试: {result.max_retries} 次")
            print(f"    需用户确认: {result.requires_user}")
            if result.hint:
                print(f"    提示: {result.hint}")
            if args.verbose:
                print(f"    建议命令: {SUGGESTED_COMMANDS.get(result.suggested_action, '?')}")
        else:
            print("[!] 未匹配已知错误，需人工分析")
            print(f"    原始错误前 500 字符: {text[:500]}")

    # 退出码：未匹配 = 1，匹配但需用户 = 2，匹配自动修复 = 0
    if not result.matched:
        return 1
    if result.requires_user:
        return 2
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
