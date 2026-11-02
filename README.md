# rust-project-inspector (`rpi`)

> **Spot structural drift across your entire Rust workspace — one command, one view.**
>
> **crate をまたいだ構造の歪みを、1コマンドで1枚にする。**

`clippy` sees lines. `cargo-audit` sees dependencies. Both focus on a single crate.
`rpi` diagnoses the **workspace as a whole**: it answers not "which line to fix" but **"which crate to tackle first."**

clippy は行を、cargo-audit は依存を見る。どれも単一 crate・単一関心。
`rpi` は **Rust workspace 全体を1つの生き物として診る**構造インスペクタで、
答えるのは「どの行を直すか」ではなく **「どの crate から手を付けるべきか」**。

## Install / インストール

Build from source and put the binary on your `PATH` (the binary is `target/release/rpi`).  
ソースからビルドし、バイナリを `PATH` に通す（バイナリは `target/release/rpi`）。

```bash
cargo build --release -p rpi-cli
export PATH="$PATH:$(pwd)/target/release"   # bash/zsh
```

## What it does / できること

`rpi inspect <workspace>` scans the workspace and ranks crates by risk score.  
`rpi inspect <workspace>` が workspace を走査し、crate をリスクスコア順にランキングする。

| Inspection | Detects / 検出 | Severity |
|---|---|---|
| `workspace-graph` | Cyclic dependencies (Tarjan SCC) · orphan crates / crate 間の循環依存・孤立 crate | Error (cycle / 循環) · Info (orphan / 孤立) |
| `module-size` | Oversized files (LOC threshold) / 肥大ファイル（LOC 閾値超） | Warn |
| `unsafe-surface` | `unsafe` count and density (per kLOC) / crate 別 unsafe 件数と密度 | Warn (over threshold / 閾値超) · Info (otherwise / 閾値以下) |
| `pub-surface` | Public API surface area per crate / crate 別の公開 API 表面積 | Warn (over threshold / 閾値超) · Info (otherwise / 閾値以下) |
| `test-gap` | Crates with no tests / テストを持たない crate | Warn |
| `dep-hygiene` | Declared-but-unused dependencies (approximate) · one crate resolved to multiple versions / 未使用の宣言依存（近似）・同一 crate の複数バージョン解決 | Warn |
| `coupling` | Files importing many distinct crate roots ("God module") / 依存先 crate 数が多いファイル（高結合 "God module"） | Warn |
| `audit-bridge` | RustSec advisories from `cargo audit` (needs `--audit`) / `cargo audit` の RustSec アドバイザリ（`--audit` 必須） | Error |
| `complexity` | Functions with high cyclomatic complexity (AST approximation) / 循環的複雑度が高い関数（AST 近似） | Warn |
| `churn-hotspot` | Files that are both frequently changed in git and complex / git 変更回数が多く、かつ複雑なファイル | Warn |

## Usage / 使い方

```bash
rpi inspect .                        # text output / カレント workspace を text 出力
rpi inspect /path/to/ws              # separate workspace / 別 workspace
rpi inspect . --format json          # machine-readable / 機械可読
rpi inspect . --format sarif         # GitHub Code Scanning upload / Code Scanning 用
rpi inspect . --fail-on warn         # exit 1 on warn+ (CI gate) / warn 以上があれば exit 1
rpi inspect . --fail-on error        # exit 1 on error only / error があるときだけ exit 1
rpi inspect . --audit                # run cargo-audit, enable audit-bridge / cargo-audit を実行し audit-bridge を有効化
rpi inspect . --baseline prior.json  # compare with a saved JSON report, print trend to stderr / 保存済み JSON と比較し trend を stderr に出力
```

`--audit` requires [`cargo-audit`](https://crates.io/crates/cargo-audit): `cargo install cargo-audit`. Without it, `audit-bridge` reports nothing (no error is raised).  
`--audit` には [`cargo-audit`](https://crates.io/crates/cargo-audit) が必要: `cargo install cargo-audit`。未インストールの場合、`audit-bridge` は何も報告しない（エラーにもならない）。

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

| Key / キー | Default / 既定値 | Used by / 使用先 | Meaning / 意味 |
|---|---|---|---|
| `module_size_loc` | `300` | `module-size` | File LOC above this is flagged / ファイル LOC がこれを超えると警告 |
| `pub_surface_warn` | `50` | `pub-surface` | Public items per crate above this is flagged / crate あたり pub item 数がこれを超えると警告 |
| `unsafe_density_warn` | `5.0` | `unsafe-surface` | `unsafe` items per kLOC above this is flagged / unsafe 件数 / kLOC がこれを超えると警告 |
| `coupling_warn` | `20` | `coupling` | Distinct crate roots imported by one file above this is flagged / 1ファイルが import する crate 数がこれを超えると警告 |
| `complexity_warn` | `10` | `complexity`, `churn-hotspot` | Function cyclomatic complexity above this is flagged; `churn-hotspot` also requires file total complexity above this / 関数の循環的複雑度がこれを超えると警告。`churn-hotspot` ではファイル合計複雑度にも適用 |
| `churn_warn` | `5` | `churn-hotspot` | Git change count at or above this (and complexity above `complexity_warn`) is flagged / git 変更回数がこれ以上（かつ複雑度が `complexity_warn` 超）で警告 |
| `churn_git_timeout_secs` | `30` | `churn-hotspot` | Max seconds for `git log`; `churn-hotspot` is skipped on timeout / `git log` の最大実行秒数（超過時は `churn-hotspot` をスキップ） |

```toml
module_size_loc = 300       # LOC warning threshold / ファイル LOC 警告閾値
pub_surface_warn = 50       # public items warning threshold / pub item 警告閾値
unsafe_density_warn = 5.0   # unsafe/kLOC warning threshold / 警告閾値
coupling_warn = 20          # imported crate roots per file / ファイルあたり import crate 数
complexity_warn = 10        # cyclomatic complexity per function / 関数の循環的複雑度
churn_warn = 5              # git changes per file / ファイルの git 変更回数
churn_git_timeout_secs = 30 # max seconds for git log; churn-hotspot skipped on timeout / git log の最大実行秒数（超過時は churn-hotspot をスキップ）
```

## CI Integration / CI 連携

[`.github/workflows/inspect.yml`](.github/workflows/inspect.yml) uploads SARIF to GitHub Code Scanning.
Use `--fail-on warn` to gate PRs.

`rpi inspect . --format sarif` の結果を GitHub Code Scanning にアップロードする。PR ゲートにするなら `--fail-on warn` を使う。

### Trend monitoring / trend 監視 (`--baseline`)

Save a JSON report, then compare the next run against it. The regression / improvement summary goes to stderr, so JSON/SARIF on stdout stays clean.  
JSON レポートを保存しておき、次回の実行と比較する。regression / improvement の要約は stderr に出るので、stdout の JSON/SARIF は汚れない。

```bash
rpi inspect . --format json > prior.json    # save a baseline / ベースライン保存
rpi inspect . --baseline prior.json         # compare / 比較
```

## Design / 設計

See [`DESIGN.md`](DESIGN.md). 4-crate workspace: `rpi-core` / `rpi-collect` / `rpi-inspections` / `rpi-cli`.
Parses AST once with `syn` and shares it across all inspections — no nightly toolchain required.

詳細は [`DESIGN.md`](DESIGN.md)。syn で AST を1回だけパースし全 inspection で共有。型解決が要る分析は近似（nightly 不要）。

## Status / ステータス

All 10 inspections are implemented. Roadmap: [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1).  
全 10 inspection 実装済み。ロードマップは [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1)。

## License

MIT
