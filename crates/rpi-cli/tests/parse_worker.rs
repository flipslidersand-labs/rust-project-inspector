//! Hidden `parse-worker` subcommand: spawn the real binary and check replies.

use std::io::Write;
use std::process::{Command, Stdio};

fn run_worker(stdin: &[u8]) -> (String, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rpi"))
        .arg("parse-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (String::from_utf8(out.stdout).unwrap(), out.status.success())
}

#[test]
fn replies_ok_and_err_per_line() {
    let dir = std::env::temp_dir().join(format!("rpi-pw-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let good = dir.join("good.rs");
    let bad = dir.join("bad.rs");
    let deep = dir.join("deep.rs");
    std::fs::write(&good, "fn main() {}\n").unwrap();
    std::fs::write(&bad, "fn main( {\n").unwrap();
    std::fs::write(
        &deep,
        format!("fn f() {{ {}{} }}", "(".repeat(600), ")".repeat(600)),
    )
    .unwrap();
    let input = format!(
        "{}\n{}\n{}\n{}\n",
        good.display(),
        bad.display(),
        deep.display(),
        dir.join("missing\u{1b}[31m.rs").display()
    );
    let (out, ok) = run_worker(input.as_bytes());
    std::fs::remove_dir_all(&dir).ok();
    assert!(ok);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(lines[0], "ok");
    assert!(lines[1].starts_with("err "), "{out}");
    assert!(
        lines[2].starts_with("err ") && lines[2].contains("nesting too deep"),
        "{out}"
    );
    assert!(lines[3].starts_with("err "), "{out}");
    assert!(!out.contains('\u{1b}'), "control chars must be escaped");
}

#[test]
fn invalid_utf8_path_is_an_err_line() {
    let (out, ok) = run_worker(b"\xff\xfe\n");
    assert!(ok);
    assert_eq!(out, "err path is not valid UTF-8\n");
}

#[test]
fn hidden_from_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_rpi"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("parse-worker"));
}
