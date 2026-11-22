//! Parent-side client against the real `rpi parse-worker`: abnormal files are
//! skipped, the worker restarts, and the test process never aborts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rpi_collect::{ParseWorker, WorkerError};

fn rpi() -> &'static str {
    env!("CARGO_BIN_EXE_rpi")
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rpi-pc-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Bracket-free deep shape that aborts `syn` in debug builds.
fn attack(dir: &Path) -> PathBuf {
    let p = dir.join("attack.rs");
    std::fs::write(&p, format!("type T = {};", "Vec<".repeat(20000))).unwrap();
    p
}

fn good(dir: &Path) -> PathBuf {
    let p = dir.join("good.rs");
    std::fs::write(&p, "fn main() {}\n").unwrap();
    p
}

#[test]
fn ok_and_err_without_restart() {
    let dir = tmp("basic");
    let bad = dir.join("bad.rs");
    std::fs::write(&bad, "fn main( {\n").unwrap();
    let mut w = ParseWorker::new(rpi());
    assert!(w.verdict(&good(&dir)).is_ok());
    assert!(matches!(w.verdict(&bad), Err(WorkerError::Parse(_))));
    assert!(w.verdict(&good(&dir)).is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn attack_input_is_skipped_and_worker_restarts() {
    let dir = tmp("attack");
    let mut w = ParseWorker::new(rpi());
    assert!(w.verdict(&good(&dir)).is_ok());
    let r = w.verdict(&attack(&dir));
    // In debug the child aborts (Crashed); in release it may reject it as too
    // deep. Either way the parent survives and does not accept the file.
    assert!(
        matches!(r, Err(WorkerError::Crashed(_) | WorkerError::Parse(_))),
        "{r:?}"
    );
    assert!(w.verdict(&good(&dir)).is_ok(), "worker must restart");
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn small_stack_child_still_cannot_take_down_parent() {
    let dir = tmp("smallstack");
    // Cap address space (via the worker's own limit, not an environment
    // `ulimit`) so the 1 GiB / 256 MiB stack reservations fail and the worker
    // falls back to a small stack.
    let mut w = ParseWorker::new(rpi());
    w.set_memory_limit(Some(300 * 1024 * 1024));
    let r = w.verdict(&attack(&dir));
    assert!(r.is_err(), "{r:?}");
    assert!(w.verdict(&good(&dir)).is_ok(), "worker must restart");
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn tiny_memory_limit_skips_file_instead_of_aborting_parent() {
    let dir = tmp("tinymem");
    let mut w = ParseWorker::new(rpi());
    w.set_memory_limit(Some(8 * 1024 * 1024)); // too small for the child to run
    let r = w.verdict(&good(&dir));
    assert!(
        matches!(r, Err(WorkerError::Crashed(_) | WorkerError::BadReply(_))),
        "{r:?}"
    );
    w.set_memory_limit(None);
    assert!(w.verdict(&good(&dir)).is_ok(), "unlimited child must work");
    std::fs::remove_dir_all(&dir).ok();
}

#[cfg(unix)]
#[test]
fn fifo_blocks_child_and_times_out() {
    let dir = tmp("fifo");
    let fifo = dir.join("pipe.rs");
    assert!(std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .unwrap()
        .success());
    let mut w = ParseWorker::new(rpi());
    assert!(w.verdict(&good(&dir)).is_ok()); // warm up with the default timeout
    w.set_timeout(Duration::from_secs(1));
    assert!(matches!(w.verdict(&fifo), Err(WorkerError::Timeout)));
    w.set_timeout(Duration::from_secs(30));
    assert!(w.verdict(&good(&dir)).is_ok(), "worker must restart");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn invalid_reply_is_reported_and_skipped() {
    // `echo` ignores stdin and prints a non-protocol line.
    let mut w = ParseWorker::new("/bin/echo");
    let r = w.verdict(Path::new("x.rs"));
    assert!(matches!(r, Err(WorkerError::BadReply(_))), "{r:?}");
}

#[test]
fn exit_without_reply_is_crashed() {
    let mut w = ParseWorker::new("/bin/false");
    let r = w.verdict(Path::new("x.rs"));
    assert!(matches!(r, Err(WorkerError::Crashed(_))), "{r:?}");
}

#[test]
fn collect_isolated_skips_attack_file_and_keeps_others() {
    let dir = tmp("collect");
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(
        dir.join("Cargo.toml"),
        "[package]\nname = \"iso\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(dir.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    std::fs::write(
        dir.join("src/evil.rs"),
        format!("type T = {};", "Vec<".repeat(20000)),
    )
    .unwrap();
    let ctx = rpi_collect::collect_isolated(
        &dir,
        rpi_collect::CollectOptions::default(),
        Path::new(rpi()),
    )
    .unwrap();
    let names: Vec<String> = ctx.crates[0]
        .files
        .iter()
        .map(|f| f.path.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["lib.rs".to_string()]);
    std::fs::remove_dir_all(&dir).ok();
}
