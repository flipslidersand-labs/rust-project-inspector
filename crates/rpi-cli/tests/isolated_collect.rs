//! `collect_isolated` must give the same result as `collect` on ordinary input,
//! and honour `rpi.toml` (`parse_isolation`).

use std::path::{Path, PathBuf};

use rpi_collect::{collect, collect_isolated, CollectOptions};

fn rpi() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rpi"))
}

fn fixture(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rpi-iso-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(d.join("src")).unwrap();
    std::fs::write(
        d.join("Cargo.toml"),
        "[package]\nname = \"fx\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .unwrap();
    std::fs::write(d.join("src/lib.rs"), "pub mod a;\npub fn f() -> u8 { 1 }\n").unwrap();
    std::fs::write(d.join("src/a.rs"), "pub fn g() {\n    if true {}\n}\n").unwrap();
    std::fs::write(d.join("src/broken.rs"), "fn main( {\n").unwrap();
    d
}

type Summary = Vec<(String, Vec<(String, usize, usize)>)>;

/// (crate name, [(relative path, loc, item count)]) for every crate.
fn summary(root: &Path, c: &rpi_core::Context) -> Summary {
    c.crates
        .iter()
        .map(|k| {
            let mut files: Vec<_> = k
                .files
                .iter()
                .map(|f| {
                    let rel = f.path.strip_prefix(root).unwrap_or(&f.path);
                    (rel.display().to_string(), f.loc, f.ast.items.len())
                })
                .collect();
            files.sort();
            (k.name.clone(), files)
        })
        .collect()
}

#[test]
fn isolated_matches_in_process_collect() {
    let d = fixture("same");
    let a = collect(&d, CollectOptions::default()).unwrap();
    let b = collect_isolated(&d, CollectOptions::default(), &rpi()).unwrap();
    let (sa, sb) = (summary(&d, &a), summary(&d, &b));
    assert_eq!(sa, sb);
    assert_eq!(sa[0].1.len(), 2, "broken.rs must be skipped: {sa:?}");
    assert_eq!(a.config.complexity_warn, b.config.complexity_warn);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn parse_isolation_false_parses_in_process() {
    let d = fixture("off");
    std::fs::write(d.join("rpi.toml"), "parse_isolation = false\n").unwrap();
    // A worker that cannot start would skip every file if it were used.
    let r = collect_isolated(&d, CollectOptions::default(), Path::new("/nonexistent/rpi")).unwrap();
    assert!(!r.crates[0].files.is_empty());
    std::fs::remove_dir_all(&d).ok();
}

#[cfg(unix)]
#[test]
fn non_utf8_path_is_skipped_only_when_isolated() {
    use std::os::unix::ffi::OsStrExt as _;
    let d = fixture("nonutf8");
    let name = std::ffi::OsStr::from_bytes(b"bad\xff.rs");
    std::fs::write(d.join("src").join(name), "fn h() {}\n").unwrap();
    let a = collect(&d, CollectOptions::default()).unwrap();
    let b = collect_isolated(&d, CollectOptions::default(), &rpi()).unwrap();
    let n = |c: &rpi_core::Context| c.crates[0].files.len();
    assert_eq!(n(&a), n(&b) + 1, "documented difference: isolated skips it");
    std::fs::remove_dir_all(&d).ok();
}
