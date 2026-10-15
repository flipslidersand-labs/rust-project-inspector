# rust-project-inspector (`rpi`)

> **Spot structural drift across your entire Rust workspace — one command, one view.**
>
> **crate をまたいだ構造の歪みを、1コマンドで1枚にする。**

`clippy` sees lines. `cargo-audit` sees dependencies. Both focus on a single crate.
`rpi` diagnoses the **workspace as a whole**: it answers not "which line to fix" but **"which crate to tackle first."**

clippy は行を、cargo-audit は依存を見る。どれも単一 crate・単一関心。
`rpi` は **Rust workspace 全体を1つの生き物として診る**構造インスペクタで、
答えるのは「どの行を直すか」ではなく **「どの crate から手を付けるべきか」**。

## What it does / できること

`rpi inspect <workspace>` scans the workspace and ranks crates by risk score.  
`rpi inspect <workspace>` が workspace を走査し、crate をリスクスコア順にランキングする。

| Inspection | Detects / 検出 |
|---|---|
| `workspace-graph` | Cyclic dependencies (Tarjan SCC) · orphan crates / crate 間の循環依存・孤立 crate |
| `module-size` | Oversized files (LOC threshold) / 肥大ファイル（LOC 閾値超） |
| `unsafe-surface` | `unsafe` count and density (per kLOC) / crate 別 unsafe 件数と密度 |
| `pub-surface` | Public API surface area per crate / crate 別の公開 API 表面積 |
| `test-gap` | Crates with no tests / テストを持たない crate |

## Usage / 使い方

```bash
cargo build --release -p rpi-cli

rpi inspect .                      # text output / カレント workspace を text 出力
rpi inspect /path/to/ws            # separate workspace / 別 workspace
rpi inspect . --format json        # machine-readable / 機械可読
rpi inspect . --format sarif       # GitHub Code Scanning upload / Code Scanning 用
rpi inspect . --fail-on warn       # exit 1 on warn+ (CI gate) / warn 以上があれば exit 1
```

Sample output / 出力例:

```
  crate risk (score = 100·err + 10·warn + 1·info):
    score  err warn info  crate
       42    0    4    2  fluxion-core
       42    0    4    2  fluxion-host
       31    0    3    1  fluxion-cli
```

## Configuration / 設定 (`rpi.toml`)

Place in workspace root to override thresholds.  
workspace ルートに置くと閾値を上書きできる（未指定キーは既定値）。

```toml
module_size_loc = 300       # LOC warning threshold / ファイル LOC 警告閾値
pub_surface_warn = 50       # public items warning threshold / pub item 警告閾値
unsafe_density_warn = 5.0   # unsafe/kLOC warning threshold / 警告閾値
```

## CI Integration / CI 連携

[`.github/workflows/inspect.yml`](.github/workflows/inspect.yml) uploads SARIF to GitHub Code Scanning.
Use `--fail-on warn` to gate PRs.

`rpi inspect . --format sarif` の結果を GitHub Code Scanning にアップロードする。PR ゲートにするなら `--fail-on warn` を使う。

## Design / 設計

See [`DESIGN.md`](DESIGN.md). 4-crate workspace: `rpi-core` / `rpi-collect` / `rpi-inspections` / `rpi-cli`.
Parses AST once with `syn` and shares it across all inspections — no nightly toolchain required.

詳細は [`DESIGN.md`](DESIGN.md)。syn で AST を1回だけパースし全 inspection で共有。型解決が要る分析は近似（nightly 不要）。

## Status / ステータス

MVP operational. Roadmap: [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1).  
MVP 稼働中。ロードマップは [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1)。

## License

MIT
