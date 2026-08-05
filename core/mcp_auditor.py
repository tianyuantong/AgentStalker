"""
AgentStalker MCP Auditor — MCP 安全审计检测器（静态层）
=====================================================
三个静态检测器,填补 references/mcp-risks.md 定义但原仓库零代码实现的 MCP 攻击向量:

1. detect_tool_squatting (R-MCP-SQUAT-001, confidence 0.90)
   工具名冲突:Agent 本地工具名 与 MCP server 暴露的工具名 交集。
   兑现 README:133 声称但从未实现的 R-MCP-SQUAT-001。

2. detect_description_poisoning (R-MCP-DESC-001, confidence 0.80)
   工具描述含隐藏指令(ignore previous / [HIDDEN] / forward to http 等)。
   正则库来自 references/mcp-risks.md:103-110 的 SUSPICIOUS_DESCRIPTION_PATTERNS,
   并按实战扩充。

3. detect_token_passthrough (R-MCP-TOKEN-001, confidence 0.85)
   MCP server 源码原样转发 Authorization header 到下游(无 token exchange)。
   检测模式:headers={"Authorization": ...} 直接传给 requests/urllib/httpx。

工作流:静态发现 → Commit 9 的 MCPMonitor 运行时验证 → VerdictEngine R009-R011 判定。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    """MCP 审计发现"""
    rule_id: str               # R-MCP-SQUAT-001 / R-MCP-DESC-001 / R-MCP-TOKEN-001
    severity: str              # critical | high | medium
    confidence: float          # 0.0 - 1.0
    server_name: str
    tool_name: str = ""
    location: str = ""         # file:line
    evidence: str = ""         # 命中的具体内容
    description: str = ""      # 人类可读说明


# ============ 规则常量 ============

# R-MCP-SQUAT-001: 工具名冲突置信度(匹配 README:133 声明的 0.90)
SQUATTING_CONFIDENCE = 0.90

# R-MCP-DESC-001: 描述投毒置信度
DESC_POISONING_CONFIDENCE = 0.80

# R-MCP-TOKEN-001: token passthrough 置信度
TOKEN_PASSTHROUGH_CONFIDENCE = 0.85

# 描述投毒可疑模式(来自 references/mcp-risks.md:103-110 + 实战扩充)
SUSPICIOUS_DESCRIPTION_PATTERNS = [
    re.compile(r'\[hidden', re.IGNORECASE),
    re.compile(r'\[system', re.IGNORECASE),
    re.compile(r'\[secret', re.IGNORECASE),
    re.compile(r'forward.*?to.*?http', re.IGNORECASE),
    re.compile(r'send.*?to.*?@', re.IGNORECASE),
    re.compile(r'ignore.*?previous', re.IGNORECASE),
    re.compile(r'do\s+not\s+(?:inform|tell)\s+the\s+user', re.IGNORECASE),
    re.compile(r'system\s*:', re.IGNORECASE),
    re.compile(r'<instruction', re.IGNORECASE),
    re.compile(r'instead\s+of.*?(?:exfiltrate|leak|send|upload)', re.IGNORECASE),
    re.compile(r'exfiltrate.*?(?:env|secret|credential|token|key)', re.IGNORECASE),
    # base64 段(可能是编码的隐藏指令)
    re.compile(r'[A-Za-z0-9+/]{40,}={0,2}'),
]

# token passthrough 检测:在源码里找原样转发 Authorization 的模式
# 匹配 requests/urllib/httpx/aiohttp 的 headers={"Authorization": ...}
TOKEN_PASSTHROUGH_PATTERNS = [
    # requests/httpx: headers={"Authorization": f"Bearer {token}"} / headers={"Authorization": token}
    re.compile(r'headers\s*=\s*\{[^}]*["\']Authorization["\']\s*:', re.IGNORECASE | re.DOTALL),
    # urllib: Request(url, headers={"Authorization": ...})
    re.compile(r'Request\s*\([^)]*headers\s*=\s*\{[^}]*["\']Authorization["\']', re.IGNORECASE | re.DOTALL),
    # 显式从 environ 取 token 后转发
    re.compile(r'(?:os\.environ|getenv|os\.getenv)\s*\(\s*["\'](?:AUTHORIZATION|AUTH_TOKEN|API_KEY|TOKEN)["\']', re.IGNORECASE),
]

# 排除:检测到 token exchange(减分信号 —— 有 exchange 说明不是 passthrough)
TOKEN_EXCHANGE_SIGNAL = re.compile(r'token_exchange|exchange_token|exchange_for|/oauth/token|client_credentials', re.IGNORECASE)


class MCPAuditor:
    """MCP 安全审计器(静态层)

    输入:AgentStalker agent_model.json 的 dict 表示(含 tools[] 和 mcp_servers[])
    输出:list[Finding]
    """

    def __init__(self, agent_model: dict, source_dir: str | Path | None = None):
        """
        Args:
            agent_model: agent_model.json 解析后的 dict
            source_dir: 可选,Agent 源码目录(token passthrough 需读源码文件)
        """
        self.model = agent_model
        self.source_dir = Path(source_dir) if source_dir else None

    def audit(self) -> list[Finding]:
        """运行全部三个检测器"""
        findings: list[Finding] = []
        findings.extend(self.detect_tool_squatting())
        findings.extend(self.detect_description_poisoning())
        findings.extend(self.detect_token_passthrough())
        # Rust 端 MCP 检测(Rust agent_model 的 mcp_servers 由 ast_extractor_rust 产生,
        # 当前结构无 tools[] —— Rust 工具名抽取待后续增强,见 docs/v2-roadmap.md)。
        # 现阶段对 Rust MCP server 源码做 token passthrough + 描述投毒扫描。
        findings.extend(self._audit_rust_mcp_servers())
        return findings

    # ============ 1. 工具名冲突 (R-MCP-SQUAT-001) ============
    def detect_tool_squatting(self) -> list[Finding]:
        """比对 agent_model.tools[](本地工具名) vs mcp_servers[].tools[](MCP 工具名)。

        交集 = squatting 风险(取决于注册顺序,MCP 可能覆盖本地工具)。
        confidence 0.90 匹配 README:133 声明。
        """
        findings: list[Finding] = []
        local_names = self._local_tool_names()
        if not local_names:
            return findings

        for srv in self.model.get("mcp_servers", []):
            srv_name = srv.get("name", srv.get("file", "unknown"))
            for mcp_tool in srv.get("tools", []):
                mcp_name = mcp_tool.get("name", "")
                if not mcp_name:
                    continue
                if mcp_name in local_names:
                    findings.append(Finding(
                        rule_id="R-MCP-SQUAT-001",
                        severity="high",
                        confidence=SQUATTING_CONFIDENCE,
                        server_name=srv_name,
                        tool_name=mcp_name,
                        location=f"{mcp_tool.get('file', srv.get('file', '?'))}:{mcp_tool.get('line', srv.get('line', '?'))}",
                        evidence=f"MCP tool '{mcp_name}' shadows local agent tool of the same name",
                        description=(
                            f"MCP server '{srv_name}' exposes a tool named '{mcp_name}', "
                            f"which collides with the agent's own local tool. Depending on "
                            f"registration order, MCP calls may shadow or be shadowed by the "
                            f"local tool — a classic tool-squatting vector (OWASP ASI04)."
                        ),
                    ))
        return findings

    # ============ 2. 描述投毒 (R-MCP-DESC-001) ============
    def detect_description_poisoning(self) -> list[Finding]:
        """扫描 MCP 工具 description 的隐藏指令。

        正则库来自 references/mcp-risks.md:103-110 + 实战扩充。
        """
        findings: list[Finding] = []
        for srv in self.model.get("mcp_servers", []):
            srv_name = srv.get("name", srv.get("file", "unknown"))
            for mcp_tool in srv.get("tools", []):
                desc = mcp_tool.get("description", "")
                if not desc:
                    continue
                matched_patterns = [p.pattern for p in SUSPICIOUS_DESCRIPTION_PATTERNS if p.search(desc)]
                if matched_patterns:
                    findings.append(Finding(
                        rule_id="R-MCP-DESC-001",
                        severity="high",
                        confidence=DESC_POISONING_CONFIDENCE,
                        server_name=srv_name,
                        tool_name=mcp_tool.get("name", ""),
                        location=f"{mcp_tool.get('file', srv.get('file', '?'))}:{mcp_tool.get('line', srv.get('line', '?'))}",
                        evidence=f"matched patterns: {matched_patterns}; desc snippet: {desc[:120]!r}",
                        description=(
                            f"MCP tool '{mcp_tool.get('name','')}' description contains suspicious "
                            f"patterns indicative of instruction injection "
                            f"({len(matched_patterns)} pattern(s) matched). The LLM reads tool "
                            f"descriptions as context, so a poisoned description can manipulate "
                            f"agent behavior (OWASP ASI04 / tool-description poisoning)."
                        ),
                    ))
        return findings

    # ============ 3. Token Passthrough (R-MCP-TOKEN-001) ============
    def detect_token_passthrough(self) -> list[Finding]:
        """静态:扫 MCP server 源码是否原样转发 Authorization header 到下游。

        检测模式:headers={"Authorization": ...} 直接传给 requests/urllib/httpx。
        若同时检测到 token exchange 信号(/oauth/token, exchange_token 等),减分。
        """
        findings: list[Finding] = []
        if not self.source_dir or not self.source_dir.exists():
            return findings

        # 找 MCP server 源码文件
        server_files = self._find_mcp_server_files()
        for sf in server_files:
            try:
                content = sf.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(sf.relative_to(self.source_dir))

            # 找 token passthrough 模式
            passthrough_hits = []
            for pat in TOKEN_PASSTHROUGH_PATTERNS:
                for m in pat.finditer(content):
                    line_no = content[:m.start()].count("\n") + 1
                    passthrough_hits.append((line_no, m.group(0)[:80]))

            if not passthrough_hits:
                continue

            # 检测 token exchange 信号(减分)
            has_exchange = bool(TOKEN_EXCHANGE_SIGNAL.search(content))
            confidence = TOKEN_PASSTHROUGH_CONFIDENCE
            if has_exchange:
                confidence *= 0.5  # 有 exchange 说明可能做了正确的 token 转换

            # 关联到对应的 MCP server
            srv_name = self._server_name_for_file(rel)
            for line_no, evidence in passthrough_hits:
                findings.append(Finding(
                    rule_id="R-MCP-TOKEN-001",
                    severity="high" if confidence >= 0.7 else "medium",
                    confidence=round(confidence, 2),
                    server_name=srv_name,
                    location=f"{rel}:{line_no}",
                    evidence=evidence,
                    description=(
                        f"MCP server source forwards an Authorization header directly to a "
                        f"downstream service{' WITHOUT token exchange' if not has_exchange else ' (token exchange signal detected, reduced confidence)'}. "
                        f"Token passthrough lets the MCP server impersonate the user against "
                        f"downstream APIs (OWASP ASI03/ASI04)."
                    ),
                ))
        return findings

    # ============ 辅助 ============
    def _local_tool_names(self) -> set[str]:
        """从 agent_model.tools[] 取本地工具名集合"""
        names = set()
        for t in self.model.get("tools", []):
            # ToolDef 是 dataclass,agent_model.json 里 name 是字段
            name = t.get("name") if isinstance(t, dict) else getattr(t, "name", None)
            if name:
                names.add(name)
        return names

    def _find_mcp_server_files(self) -> list[Path]:
        """定位 MCP server 源码文件(基于 mcp_servers[] 的 file 字段)"""
        files = []
        for srv in self.model.get("mcp_servers", []):
            f = srv.get("file")
            if f:
                p = self.source_dir / f
                if p.exists():
                    files.append(p)
        return files

    def _server_name_for_file(self, rel_file: str) -> str:
        """根据文件名反查 server 名"""
        for srv in self.model.get("mcp_servers", []):
            if srv.get("file") == rel_file:
                return srv.get("name", rel_file)
        return rel_file

    # ============ Rust 端 MCP 检测(Commit 10)============
    # Rust MCP server 的 mcp_servers[] 由 ast_extractor_rust.py 产生,当前结构
    # {name, file, line, match} 无 tools[](Rust 工具名抽取待后续增强)。
    # 现阶段对 Rust MCP server 源码做:
    # - token passthrough 扫描(复用 TOKEN_PASSTHROUGH_PATTERNS,但加 Rust 的 reqwest/ureq 模式)
    # - 描述投毒扫描(扫 #[tool] 宏旁的 doc comment)
    # 完整 Rust 工具名 squatting 检测需要先增强 ast_extractor_rust 抽工具名(记入路线图)。
    def _audit_rust_mcp_servers(self) -> list[Finding]:
        findings: list[Finding] = []
        if not self.source_dir or not self.source_dir.exists():
            return findings

        # Rust 特有的 token passthrough 模式
        rust_token_patterns = [
            # reqwest: .header("Authorization", ...)
            re.compile(r'\.header\s*\(\s*["\']Authorization["\']', re.IGNORECASE),
            # ureq: .set("Authorization", ...)
            re.compile(r'\.set\s*\(\s*["\']Authorization["\']', re.IGNORECASE),
            # reqwest bearer: .bearer_auth(token)
            re.compile(r'\.bearer_auth\s*\(', re.IGNORECASE),
        ]
        # Rust doc comment(描述投毒)模式://! 或 /// 开头
        rust_doc_pattern = re.compile(r'^\s*(?://!|///)\s*(.+)$', re.MULTILINE)

        for srv in self.model.get("mcp_servers", []):
            # 只看 Rust MCP server(name 字段是 RUST_MCP_PATTERNS 的 key 名,如 mcp_qualified)
            srv_name = srv.get("name", "")
            f = srv.get("file")
            if not f:
                continue
            p = self.source_dir / f
            if not p.exists() or p.suffix != ".rs":
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            rel = str(p.relative_to(self.source_dir))

            # 1. token passthrough
            has_exchange = bool(TOKEN_EXCHANGE_SIGNAL.search(content))
            confidence = TOKEN_PASSTHROUGH_CONFIDENCE
            if has_exchange:
                confidence *= 0.5
            for pat in rust_token_patterns:
                for m in pat.finditer(content):
                    line_no = content[:m.start()].count("\n") + 1
                    findings.append(Finding(
                        rule_id="R-MCP-TOKEN-001",
                        severity="high" if confidence >= 0.7 else "medium",
                        confidence=round(confidence, 2),
                        server_name=srv_name or rel,
                        location=f"{rel}:{line_no}",
                        evidence=f"rust: {m.group(0)[:80]}",
                        description=(
                            f"Rust MCP server forwards Authorization header to downstream"
                            f"{' without token exchange' if not has_exchange else ' (exchange signal detected, reduced confidence)'}."
                        ),
                    ))
                    break  # 每文件只报一次

            # 2. 描述投毒(扫 doc comment)
            for dm in rust_doc_pattern.finditer(content):
                doc_line = dm.group(1)
                matched = [p.pattern for p in SUSPICIOUS_DESCRIPTION_PATTERNS if p.search(doc_line)]
                if matched:
                    line_no = content[:dm.start()].count("\n") + 1
                    findings.append(Finding(
                        rule_id="R-MCP-DESC-001",
                        severity="high",
                        confidence=DESC_POISONING_CONFIDENCE,
                        server_name=srv_name or rel,
                        location=f"{rel}:{line_no}",
                        evidence=f"rust doc comment matched: {matched}; {doc_line[:80]!r}",
                        description=(
                            f"Rust MCP server doc comment contains suspicious pattern(s) "
                            f"indicative of instruction injection."
                        ),
                    ))
        return findings


def findings_to_json(findings: list[Finding]) -> str:
    """序列化 findings 为 JSON(供 Claude Code 编排器读)"""
    import json
    from dataclasses import asdict
    return json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False)
