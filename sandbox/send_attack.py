"""
AgentStalker Send Attack — 单条攻击注入辅助
===========================================
仅负责 HTTP 注入 + 结构化响应输出。
⚠️ 不维护会话状态、不做变量提取、不做证据拉取——这些由 Claude Code 主导。

Claude Code 调用模式:
    python -m sandbox.send_attack \\
        --url http://localhost:8000/chat \\
        --message "ignore previous instructions and..." \\
        --session-id ast-TC001-a1b2c3d4 \\
        --history '[{"role":"user","content":"ping"}]' \\
        --timeout 30
    → 返回 JSON: {status_code, response_body, elapsed_s, error}

自适应攻击由 Claude Code 在对话中维护 extracted_vars 字典，
通过 --message 中 ${VAR} 占位符自动替换（也由 Claude Code 做）。
"""
from __future__ import annotations

import argparse
import json
import time
from typing import Any

try:
    import requests
except ImportError:
    requests = None  # Claude Code 环境若无 requests，可直接用 curl（见 README）


def send(url: str, message: str, session_id: str = "",
         history: list[dict] | None = None, timeout: int = 30,
         cookies: dict | None = None, headers: dict | None = None) -> dict:
    """发送单条攻击消息，返回结构化结果

    Returns:
        {
            "status_code": int,
            "response_body": str,
            "elapsed_s": float,
            "error": str (only on failure),
        }
    """
    if requests is None:
        return {
            "error": "requests library not available; use curl directly: "
                     f"curl -X POST {url} -H 'Content-Type: application/json' "
                     f"-d '{json.dumps({'message': message, 'session_id': session_id})}'",
        }

    payload: dict[str, Any] = {"message": message, "session_id": session_id}
    if history:
        payload["history"] = history[-5:]  # 最多传最近 5 轮

    full_headers = {"X-Session-Id": session_id, **(headers or {})}

    start = time.time()
    try:
        r = requests.post(
            url, json=payload, headers=full_headers,
            cookies=cookies or {}, timeout=timeout,
        )
        return {
            "status_code": r.status_code,
            "response_body": r.text,
            "elapsed_s": time.time() - start,
        }
    except Exception as e:
        return {
            "error": str(e),
            "elapsed_s": time.time() - start,
        }


# ============ 变量提取（最小集，常用 pattern 硬编码；其余走 YAML）============
# Claude Code 优先用 grep/jq 提取；此函数仅作 fallback
EXTRACT_PATTERNS = {
    "session_token": r'session[_-]?token["\s:=]+([A-Za-z0-9_\-]{16,})',
    "openai_key":    r'sk-[A-Za-z0-9]{20,}',
    "aws_key":       r'AKIA[0-9A-Z]{16}',
    "github_token":  r'ghp_[A-Za-z0-9]{36}',
    "extracted_email": r'(?i)your (?:email|account) (?:is|:)\s*([\w\.\-+]+@[\w\.\-]+)',
}


def extract_variables(text: str) -> dict[str, str]:
    """从响应文本中提取关键变量（最小集）

    Claude Code 通常直接用 Bash + grep 处理：
        echo "$response" | grep -oP 'sk-[A-Za-z0-9]{20,}'
    本函数仅作 fallback（无 grep 时）。
    """
    import re
    result = {}
    for key, pattern in EXTRACT_PATTERNS.items():
        m = re.search(pattern, text)
        if m:
            result[key] = m.group(1) if m.groups() else m.group(0)
    return result


# ============ CLI ============
def main():
    ap = argparse.ArgumentParser(description="AgentStalker 攻击注入（仅 HTTP 辅助）")
    ap.add_argument("--url", required=True, help="Agent 入口 URL")
    ap.add_argument("--message", required=True, help="攻击消息内容")
    ap.add_argument("--session-id", default="", help="会话 ID（多轮一致性）")
    ap.add_argument("--history", default="[]", help="历史对话 JSON 字符串")
    ap.add_argument("--timeout", type=int, default=30)
    ap.add_argument("--extract", action="store_true", help="提取响应中的变量")
    args = ap.parse_args()

    history = json.loads(args.history) if args.history else []
    result = send(
        url=args.url, message=args.message, session_id=args.session_id,
        history=history, timeout=args.timeout,
    )

    if args.extract and "response_body" in result:
        result["extracted"] = extract_variables(result["response_body"])

    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
