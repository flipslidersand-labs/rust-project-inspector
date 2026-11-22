//! Parent-side client for the hidden `rpi parse-worker` child process (#119).
//!
//! `syn` can abort the whole process (stack overflow) on hostile input, which no
//! in-process guard can catch. The worker judges each file in a child; when the
//! child dies, hangs or answers garbage, the parent skips that one file, kills
//! and reaps the child, and starts a fresh one for the next file.

use std::fmt;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::Duration;

/// Longest path (bytes) the parent sends; longer ones are skipped. The worker
/// enforces its own line cap derived from this, so it never buffers unbounded input.
pub const MAX_WORKER_PATH_BYTES: usize = 4096;

/// Cap on one reply line read from the child (replies are short; this bounds memory).
const MAX_REPLY_BYTES: usize = 64 * 1024;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a file was not accepted by the worker.
#[derive(Debug)]
pub enum WorkerError {
    /// The child judged the file bad (`err <reason>`); the worker is still healthy.
    Parse(String),
    /// The path cannot be sent (newline, non-UTF-8, too long). Nothing was spawned.
    PathRejected(String),
    /// The child exited or was killed by a signal (e.g. abort) before replying.
    Crashed(String),
    /// No reply within the timeout (e.g. blocked on a FIFO); the child was killed.
    Timeout,
    /// The child replied with something that is not `ok` / `err ...`.
    BadReply(String),
    /// The child could not be started.
    Spawn(String),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(m) => write!(f, "{m}"),
            Self::PathRejected(m) => write!(f, "path rejected: {m}"),
            Self::Crashed(m) => write!(f, "parser process crashed: {m}"),
            Self::Timeout => write!(f, "parser process timed out"),
            Self::BadReply(m) => write!(f, "parser process gave an invalid reply: {m}"),
            Self::Spawn(m) => write!(f, "cannot start parser process: {m}"),
        }
    }
}

struct Live {
    child: Child,
    stdin: ChildStdin,
    replies: Receiver<Vec<u8>>,
}

/// A lazily started, restart-on-failure `parse-worker` child.
pub struct ParseWorker {
    exe: PathBuf,
    timeout: Duration,
    live: Option<Live>,
}

impl ParseWorker {
    /// Use `exe` (an `rpi` binary) as the worker, invoked as `exe parse-worker`.
    pub fn new(exe: impl Into<PathBuf>) -> Self {
        Self {
            exe: exe.into(),
            timeout: DEFAULT_TIMEOUT,
            live: None,
        }
    }

    /// Use the running executable itself (only valid when it is `rpi`).
    pub fn from_current_exe() -> std::io::Result<Self> {
        std::env::current_exe().map(Self::new)
    }

    /// Per-file reply timeout (default 30 s).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// Ask the child whether `path` parses. After any error other than
    /// [`WorkerError::Parse`] / [`WorkerError::PathRejected`] the child has been
    /// killed and reaped; the next call starts a new one.
    pub fn verdict(&mut self, path: &Path) -> Result<(), WorkerError> {
        let p = path
            .to_str()
            .ok_or_else(|| WorkerError::PathRejected("not valid UTF-8".into()))?;
        if p.contains(['\n', '\r']) {
            return Err(WorkerError::PathRejected("contains a line break".into()));
        }
        if p.len() > MAX_WORKER_PATH_BYTES {
            return Err(WorkerError::PathRejected(format!(
                "longer than {MAX_WORKER_PATH_BYTES} bytes"
            )));
        }
        if self.live.is_none() {
            self.live = Some(self.spawn()?);
        }
        let live = self.live.as_mut().expect("just ensured");
        let sent = writeln!(live.stdin, "{p}").and_then(|()| live.stdin.flush());
        let got = match sent {
            // A failed write usually means the child is already gone; the
            // closed reply channel below tells us how it ended.
            Err(_) => live.replies.recv_timeout(self.timeout),
            Ok(()) => live.replies.recv_timeout(self.timeout),
        };
        let line = match got {
            Ok(l) => l,
            Err(RecvTimeoutError::Timeout) => {
                self.discard();
                return Err(WorkerError::Timeout);
            }
            Err(RecvTimeoutError::Disconnected) => {
                let status = self.discard();
                return Err(WorkerError::Crashed(status));
            }
        };
        let text = String::from_utf8_lossy(&line).into_owned();
        if text == "ok" && sent.is_ok() {
            Ok(())
        } else if let Some(reason) = text.strip_prefix("err ") {
            Err(WorkerError::Parse(reason.to_string()))
        } else {
            self.discard();
            let shown: String = text.chars().take(80).collect();
            Err(WorkerError::BadReply(shown))
        }
    }

    fn spawn(&self) -> Result<Live, WorkerError> {
        let mut child = Command::new(&self.exe)
            .arg("parse-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| WorkerError::Spawn(e.to_string()))?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let stdout = child.stdout.take().expect("stdout was piped");
        let (tx, replies) = mpsc::channel();
        thread::spawn(move || {
            let mut r = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                let n = (&mut r)
                    .take(MAX_REPLY_BYTES as u64 + 1)
                    .read_until(b'\n', &mut line);
                if !matches!(n, Ok(n) if n > 0) {
                    return; // EOF/error: dropping `tx` signals the parent.
                }
                if line.last() == Some(&b'\n') {
                    line.pop();
                } else if line.len() > MAX_REPLY_BYTES {
                    line.truncate(MAX_REPLY_BYTES);
                    line.extend_from_slice(b"<too long>");
                }
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
        Ok(Live {
            child,
            stdin,
            replies,
        })
    }

    /// Kill and reap the child; describe how it ended.
    fn discard(&mut self) -> String {
        let Some(mut live) = self.live.take() else {
            return "no worker".into();
        };
        let _ = live.child.kill();
        match live.child.wait() {
            Ok(st) => describe(st),
            Err(e) => format!("wait failed: {e}"),
        }
    }
}

impl Drop for ParseWorker {
    fn drop(&mut self) {
        self.discard();
    }
}

fn describe(st: ExitStatus) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(sig) = st.signal() {
            return format!("killed by signal {sig}");
        }
    }
    format!("{st}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsendable_paths_without_spawning() {
        let mut w = ParseWorker::new("/nonexistent/rpi");
        for p in ["a\nb.rs", "a\rb.rs"] {
            assert!(matches!(
                w.verdict(Path::new(p)),
                Err(WorkerError::PathRejected(_))
            ));
        }
        let long = "x".repeat(MAX_WORKER_PATH_BYTES + 1);
        assert!(matches!(
            w.verdict(Path::new(&long)),
            Err(WorkerError::PathRejected(_))
        ));
        assert!(matches!(
            w.verdict(Path::new("ok.rs")),
            Err(WorkerError::Spawn(_))
        ));
    }
}
