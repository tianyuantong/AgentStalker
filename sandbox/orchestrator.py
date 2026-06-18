"""
AgentStalker Sandbox State Tracker
==================================
⚠️ 此模块**只跟踪状态**——不启动容器、不生成文件、不发请求。
   所有动作由 Claude Code 用 Bash 工具执行，事后调用此模块更新状态。

Claude Code 工作流:
    1. analyze.py              → 获得 project_info
    2. jinja2 模板渲染 Dockerfile + compose.override
    3. docker compose up -d    (Bash)
    4. docker inspect / curl   (Bash, 5 要素检查)
    5. 出错时 heal_diagnose.py → Claude Code 自行决定修复
    6. send_attack.py / curl   (注入攻击)
    7. correlation/            (研判)
    8. orchestrator.py record  → 更新本模块的 state
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class SandboxState:
    session_id: str = ""
    started_at: float = 0.0
    stopped_at: float = 0.0
    status: str = "idle"   # idle | starting | running | stopping | stopped | error
    agent_container: str = ""
    compose_file: str = ""
    evidence_dir: str = ""
    deployment_checks: dict = field(default_factory=dict)  # 5 要素结果
    test_cases: list[dict] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def new_session(output_dir: str | Path) -> SandboxState:
    """创建新会话（Claude Code 在 Bash 中调用）"""
    state = SandboxState(
        session_id=f"ast-{uuid.uuid4().hex[:8]}",
        started_at=time.time(),
        status="starting",
        evidence_dir=str(Path(output_dir) / "evidence"),
    )
    Path(state.evidence_dir).mkdir(parents=True, exist_ok=True)
    return state


def record(state: SandboxState, **kwargs) -> SandboxState:
    """更新状态字段（任意关键字参数）"""
    for k, v in kwargs.items():
        if hasattr(state, k):
            setattr(state, k, v)
    return state


def add_finding(state: SandboxState, case_id: str, verdict: str,
                severity: str, evidence: dict, **extras) -> SandboxState:
    """添加一条 finding"""
    state.findings.append({
        "case_id": case_id,
        "verdict": verdict,
        "severity": severity,
        "evidence": evidence,
        **extras,
    })
    return state


def add_note(state: SandboxState, note: str) -> SandboxState:
    """追加一条 note（Claude Code 用于记录操作）"""
    state.notes.append(f"[{time.strftime('%H:%M:%S')}] {note}")
    return state


def save_state(state: SandboxState, path: str | Path):
    """保存状态到 JSON（Claude Code 在 stop 时调用）"""
    state.stopped_at = time.time()
    if state.status != "error":
        state.status = "stopped"
    Path(path).write_text(
        json.dumps(asdict(state), indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )


def load_state(path: str | Path) -> SandboxState:
    """从 JSON 恢复状态"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return SandboxState(**data)


# ============ 摘要 ============
def summary(state: SandboxState) -> dict:
    """生成可打印摘要"""
    by_severity: dict[str, int] = {}
    for f in state.findings:
        sev = f.get("severity", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return {
        "session_id": state.session_id,
        "status": state.status,
        "duration_s": round(state.stopped_at - state.started_at, 1) if state.stopped_at else None,
        "deployment_passed": state.deployment_checks.get("all_passed"),
        "findings_total": len(state.findings),
        "by_severity": by_severity,
        "notes_count": len(state.notes),
    }


# ============ CLI ============
def main():
    import argparse
    ap = argparse.ArgumentParser(description="AgentStalker 状态跟踪器")
    sub = ap.add_subparsers(dest="cmd", required=True)

    new_p = sub.add_parser("new", help="创建新会话")
    new_p.add_argument("--output", default="./output")

    save_p = sub.add_parser("save", help="保存状态")
    save_p.add_argument("--state-file", required=True)

    sum_p = sub.add_parser("summary", help="打印摘要")
    sum_p.add_argument("--state-file", required=True)

    args = ap.parse_args()

    if args.cmd == "new":
        s = new_session(args.output)
        save_state(s, Path(args.output) / "sandbox_state.json")
        print(json.dumps(asdict(s), indent=2, ensure_ascii=False, default=str))
    elif args.cmd == "save":
        s = load_state(args.state_file)
        save_state(s, args.state_file)
        print(f"[+] saved to {args.state_file}")
    elif args.cmd == "summary":
        s = load_state(args.state_file)
        print(json.dumps(summary(s), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
