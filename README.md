# rust-project-inspector (`rpi`)

> **Spot structural drift across your entire Rust workspace — one command, one view.**

`clippy` sees lines. `cargo-audit` sees dependencies. Both focus on a single crate.
`rpi` diagnoses the **workspace as a whole**: it answers not "which line to fix" but **"which crate to tackle first."**

## What it does

`rpi inspect <workspace>` scans the workspace and ranks crates by risk score.

| Inspection | Detects |
|---|---|
| `workspace-graph` | Cyclic dependencies (Tarjan SCC) · orphan crates |
| `module-size` | Oversized files (LOC threshold) |
| `unsafe-surface` | `unsafe` count and density (per kLOC) per crate |
| `pub-surface` | Public API surface area per crate |
| `test-gap` | Crates with no tests |

## Usage

```bash
cargo build --release -p rpi-cli

rpi inspect .                      # text output for current workspace
rpi inspect /path/to/ws            # separate workspace
rpi inspect . --format json        # machine-readable
rpi inspect . --format sarif       # GitHub Code Scanning upload
rpi inspect . --fail-on warn       # exit 1 on warn+ (CI gate)
```

Sample output:

```
  crate risk (score = 100·err + 10·warn + 1·info):
    score  err warn info  crate
       42    0    4    2  fluxion-core
       42    0    4    2  fluxion-host
       31    0    3    1  fluxion-cli
```

## Configuration (`rpi.toml`)

Place in workspace root to override thresholds (unset keys use defaults).

```toml
module_size_loc = 300       # LOC warning threshold per file
pub_surface_warn = 50       # public items warning threshold per crate
unsafe_density_warn = 5.0   # unsafe/kLOC warning threshold
```

## CI Integration

[`.github/workflows/inspect.yml`](.github/workflows/inspect.yml) uploads SARIF results to GitHub Code Scanning.
Use `--fail-on warn` to gate PRs on structural quality.

## Design

See [`DESIGN.md`](DESIGN.md). 4-crate workspace: `rpi-core` / `rpi-collect` / `rpi-inspections` / `rpi-cli`.
Parses AST once with `syn` and shares it across all inspections — no nightly toolchain required, works on any Rust project.

## Status

MVP operational. Roadmap tracked in [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1).

## License

MIT

