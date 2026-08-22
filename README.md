# rust-project-inspector (`rpi`)

> **crate をまたいだ構造の歪みを、1コマンドで1枚にする。**

clippy は行を、cargo-audit は依存を見る。どれも単一 crate・単一関心。
`rpi` は **Rust workspace 全体を1つの生き物として診る**構造インスペクタで、
答えるのは「どの行を直すか」ではなく **「どの crate から手を付けるべきか」**。

## できること

`rpi inspect <workspace>` が workspace を走査し、crate をリスクスコア順にランキングする。

| inspection | 検出 |
|---|---|
| `workspace-graph` | crate 間の循環依存（Tarjan SCC）・孤立 crate |
| `module-size` | 肥大ファイル（LOC 閾値超） |
| `unsafe-surface` | crate 別 unsafe 件数と密度（/kLOC） |
| `pub-surface` | crate 別の公開 API 表面積 |
| `test-gap` | テストを持たない crate |

## 使い方

```bash
cargo build --release -p rpi-cli

rpi inspect .                      # カレント workspace を text 出力
rpi inspect /path/to/ws            # 別 workspace
rpi inspect . --format json        # 機械可読
rpi inspect . --format sarif       # GitHub Code Scanning 用
rpi inspect . --fail-on warn       # warn 以上があれば exit 1（CI ゲート）
```

出力例（抜粋）:

```
  crate risk (score = 100·err + 10·warn + 1·info):
    score  err warn info  crate
       42    0    4    2  fluxion-core
       42    0    4    2  fluxion-host
       31    0    3    1  fluxion-cli
```

## 設定（`rpi.toml`）

workspace ルートに置くと閾値を上書きできる（未指定キーは既定値）。

```toml
module_size_loc = 300       # ファイル LOC 警告閾値
pub_surface_warn = 50       # crate あたり pub item 警告閾値
unsafe_density_warn = 5.0   # unsafe 件数 / kLOC の警告閾値
```

## CI 連携

[`.github/workflows/inspect.yml`](.github/workflows/inspect.yml) が `rpi inspect . --format sarif`
の結果を GitHub Code Scanning にアップロードする。PR ゲートにするなら `--fail-on warn` を使う。

## 設計

詳細は [`DESIGN.md`](DESIGN.md)。4-crate workspace（`rpi-core` / `rpi-collect` /
`rpi-inspections` / `rpi-cli`）。syn で AST を1回だけパースし全 inspection で共有。
型解決が要る分析は syn 表層解析による**近似**（nightly 不要・どの Rust プロジェクトにも即座に効く）。

## ステータス

MVP 稼働中。ロードマップは [epic #1](https://github.com/flipslidersand/rust-project-inspector/issues/1)。

## License

MIT
