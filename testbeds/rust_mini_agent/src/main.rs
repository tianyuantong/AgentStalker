// Test fixture: a Rust agent exercising the taint-tracker regression cases.
//
// C3 (SHELL_CMD dynamic detection):
//   - run_shell_dynamic uses Command::new(user_cmd) (dynamically-constructed command)
//   - run_shell_literal uses Command::new("ls") (literal command)
//     Both must be flagged as SHELL_CMD sinks.
//
// C5 (sanitizer on caller path):
//   - handle_user_input is a USER_INPUT source that calls run_shell_dynamic.
//   - handle_user_input_sanitized calls check_approval() before run_shell_dynamic,
//     so the flow through it must carry a sanitizer (not be silently exploitable).
//
// fast/full consistency:
//   - The fixture is small enough that fast and full should both find the
//     critical SHELL_CMD sinks; full additionally resolves longer hops.
//
// NOTE: function names are chosen to match SOURCE_FN_PATTERNS so the tracker
// recognizes them as sources (read_user_input, handle_user_input).

use std::process::Command;

// USER_INPUT source — name matches SOURCE_FN_PATTERNS[USER_INPUT].
fn read_user_input() -> String {
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(1)
}

// USER_INPUT source that reaches a dynamic SHELL_CMD sink directly (no sanitizer),
// and also reaches a literal-command sink in the same body.
fn handle_user_input() {
    let user_cmd = read_user_input();
    // directly run a dynamically-built command — no sanitizer in this fn body
    let _out = Command::new(&user_cmd).output();
    // literal command in the same source fn body
    let _listing = Command::new("ls").output();
}

// USER_INPUT source that reaches the same sink but THROUGH a sanitizer.
fn handle_user_input_sanitized() {
    let user_cmd = read_user_input();
    check_approval(&user_cmd);
    let _out = Command::new(&user_cmd).output();
}

// Sanitizer stub — name matches RUST_SANITIZERS[execpolicy] (check_approval).
fn check_approval(cmd: &str) -> bool {
    cmd.is_empty()
}

// Standalone literal SHELL_CMD sink — reachable from a USER_INPUT source via main.
fn run_shell_literal() {
    let _out = Command::new("ls").output();
}

fn main() {
    handle_user_input();
    handle_user_input_sanitized();
    run_shell_literal();
}
