# rust-project-inspector (`rpi`)

> **crate をまたいだ構造の歪みを、1コマンドで1枚にする。**

clippy は行を、cargo-audit は依存を見る。どれも単一 crate・単一関心。
`rpi` は **Rust workspace 全体を1つの生き物として診る**構造インスペクタで、
答えるのは「どの行を直すか」ではなく **「どの crate から手を付けるべきか」**。

## インストール

```bash
# ソースからビルド
cargo build --release -p rpi-cli
# PATH に追加（bash/zsh）
export PATH="$PATH:$(pwd)/target/release"
```

## できること

`rpi inspect <workspace>` が workspace を走査し、crate をリスクスコア順にランキングする。

| inspection | 検出 | severity |
|---|---|---|
| `workspace-graph` | crate 間の循環依存（Tarjan SCC）・孤立 crate | Error / Info |
| `module-size` | 肥大ファイル（LOC 閾値超） | Warn |
| `unsafe-surface` | crate 別 unsafe 件数と密度（/kLOC） | Warn |
| `pub-surface` | crate 別の公開 API 表面積 | Warn |
| `test-gap` | テストを持たない crate | Warn |
| `dep-hygiene` | 未使用依存の近似検出・同一 crate の複数バージョン解決 | Warn |
| `coupling` | ファイル単位の依存先 crate 数（高結合 "God module" 検出） | Warn |
| `audit-bridge` | RustSec アドバイザリとの照合（`--audit` 必須） | Error |
| `complexity` | 関数の循環的複雑度（AST 近似） | Warn |
| `churn-hotspot` | git 変更頻度 × 複雑度が高いファイル | Warn |

## 使い方

```bash
rpi inspect .                        # カレント workspace を text 出力
rpi inspect /path/to/ws              # 別 workspace を指定
rpi inspect . --format json          # 機械可読 JSON
rpi inspect . --format sarif         # GitHub Code Scanning 用 SARIF 2.1.0
rpi inspect . --fail-on warn         # warn 以上があれば exit 1（CI ゲート）
rpi inspect . --fail-on error        # error のみで exit 1
rpi inspect . --audit                # cargo-audit を実行して audit-bridge を有効化
rpi inspect . --baseline prior.json  # 前回レポートと比較して trend を表示（stderr）
```

> **`--audit` には `cargo-audit` が必要です**: `cargo install cargo-audit`

出力例（抜粋）:

```
  crate risk (score = 100·err + 10·warn + 1·info):
    score  err warn info  crate
       42    0    4    2  fluxion-core
       42    0    4    2  fluxion-host
       31    0    3    1  fluxion-cli
```

## 設定（`rpi.toml`）

workspace ルートに置くと閾値を上書きできる（未指定キーはすべて既定値のまま）。

```toml
module_size_loc     = 300   # ファイル LOC 警告閾値
pub_surface_warn    = 50    # crate あたり pub item 警告閾値
unsafe_density_warn = 5.0   # unsafe 件数 / kLOC の警告閾値
coupling_warn       = 20    # ファイルあたりの依存 crate 数警告閾値
complexity_warn     = 10    # 関数の循環的複雑度警告閾値
churn_warn          = 5     # git 変更回数の警告閾値（complexity_warn も超えた場合に発火）
```

## CI 連携

[`.github/workflows/inspect.yml`](.github/workflows/inspect.yml) が `rpi inspect . --format sarif`
の結果を GitHub Code Scanning にアップロードする。PR ゲートにするなら `--fail-on warn` を使う。

### trend 監視（`--baseline`）

```bash
# 前回の JSON レポートを保存しておき、次回と比較する
rpi inspect . --format json > current.json
rpi inspect . --baseline prior.json   # regression / improvement を stderr に出力
```

## 設計

詳細は [`DESIGN.md`](DESIGN.md)。4-crate workspace（`rpi-core` / `rpi-collect` /
`rpi-inspections` / `rpi-cli`）。syn で AST を1回だけパースし全 inspection で共有。
型解決が要る分析は syn 表層解析による**近似**（nightly 不要・どの Rust プロジェクトにも即座に効く）。

## ステータス

全 10 inspection 実装済み・テスト緑。

## License

MIT
