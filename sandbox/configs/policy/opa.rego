# AgentStalker OPA Policy
# 部署到 Envoy/Istio/自研代理层
# 用于在 L4/L7 层强制 Agent 工具调用的合规性

package agentstalker.policy

# ============ Tool Allowlist ============
# 只有白名单内的工具可被调用
allowed_tools := {
    "search_web",
    "read_file",
    "send_email",
    "get_calendar",
    "query_db",
    "list_users",
}

# ============ Dangerous Tool Blocklist ============
# 阻断危险工具（如未经显式授权）
blocked_tools := {
    "execute_shell",
    "exec_command",
    "run_script",
    "delete_file",
    "modify_audit_log",
    "send_money",
    "transfer_funds",
}

# ============ Sender Restrictions ============
# 邮件/转账目标白名单
allowed_email_domains := {
    "corp.com",
    "test.com",
    "internal.local",
}

# ============ Resource Limits ============
max_request_size := 65536       # 64KB
max_response_size := 1048576    # 1MB
max_tool_calls_per_request := 20

# ============ Rules ============

# Rule 1: 阻断危险工具
deny[msg] {
    input.tool_call.name == blocked_tools[_]
    msg := sprintf("Tool '%v' is in blocklist (ASI03 Excessive Agency)", [input.tool_call.name])
}

# Rule 2: 邮件外发阻断（ASI05 Improper Output Handling）
deny[msg] {
    input.tool_call.name == "send_email"
    recipient := input.tool_call.arguments.to
    not allowed_email_domains[split(recipient, "@")[1]]
    msg := sprintf("Email to '%v' targets external domain (ASI05)", [recipient])
}

# Rule 3: 阻断审计日志修改（ASI06 Excessive Autonomy）
deny[msg] {
    input.tool_call.name == "modify_audit_log"
    msg := "Modification of audit log is forbidden (ASI06)"
}

# Rule 4: 请求体大小限制
deny[msg] {
    input.request_size > max_request_size
    msg := sprintf("Request size %v exceeds %v bytes (DoS prevention)", [input.request_size, max_request_size])
}

# Rule 5: 单请求工具调用数量限制
deny[msg] {
    count(input.tool_calls) > max_tool_calls_per_request
    msg := sprintf("Tool call count %v exceeds limit %v", [count(input.tool_calls), max_tool_calls_per_request])
}

# Rule 6: 阻断指向 metadata 服务（ASI04 / SSRF）
deny[msg] {
    url := input.tool_call.arguments.url
    contains(url, "169.254.169.254")
    msg := sprintf("SSRF to cloud metadata blocked: %v", [url])
}

deny[msg] {
    url := input.tool_call.arguments.url
    contains(url, "metadata.google.internal")
    msg := sprintf("SSRF to GCP metadata blocked: %v", [url])
}

deny[msg] {
    url := input.tool_call.arguments.url
    contains(url, "metadata.azure.com")
    msg := sprintf("SSRF to Azure metadata blocked: %v", [url])
}

# Rule 7: 阻断内网回环（除 mock 服务）
deny[msg] {
    url := input.tool_call.arguments.url
    startswith(url, "http://localhost") ; startswith(url, "http://127.")
    not contains(url, "mock-")
    msg := sprintf("SSRF to localhost blocked: %v", [url])
}

# Rule 8: 高风险组合 — 读凭据 + 外联
warn[msg] {
    input.tool_call.name == "read_file"
    contains(input.tool_call.arguments.path, "/etc/shadow")
    msg := "Reading /etc/shadow detected (potential credential theft)"
}

warn[msg] {
    input.tool_call.name == "read_file"
    contains(input.tool_call.arguments.path, ".ssh/id_rsa")
    msg := "Reading SSH private key detected"
}
