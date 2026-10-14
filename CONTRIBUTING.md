# Contributing to rust-project-inspector

## 開発環境セットアップ

```bash
git clone https://github.com/flipslidersand/rust-project-inspector.git
cd rust-project-inspector

# ビルド確認
cargo build --all

# テスト実行
cargo test --all

# CLI ビルド
cargo build --release -p rpi-cli
./target/release/rpi inspect .
```

必須ツール:

| ツール | 用途 | インストール |
|---|---|---|
| Rust stable | ビルド | `rustup toolchain install stable` |
| rustfmt | フォーマット | `rustup component add rustfmt` |
| clippy | Lint | `rustup component add clippy` |
| cargo-audit | セキュリティ | `cargo install cargo-audit` |

## テスト

```bash
cargo test --all                          # 全スイート
cargo test --package rpi-cli --test acceptance   # acceptance テストのみ
cargo test --package rpi-inspections      # inspection ユニットテストのみ
cargo fmt --all -- --check                # フォーマットチェック
cargo clippy --all-targets --all-features -- -D warnings  # Lint
```

### フィクスチャ

`tests/fixtures/` に小規模なワークスペースを置いて acceptance テストで使う。

| fixture | 用途 |
|---|---|
| `multi/` | 2-crate workspace。各 inspection の positive/negative を網羅 |
| `sample/` | 単一 crate。collect の基本動作テスト用 |
| `large-module/` | 300 LOC 超ファイルを持つ crate。`module-size` のデフォルト閾値テスト |
| `empty/` | メンバー 0 の workspace 宣言（`cargo metadata` は空を返さないので Context レベルで検証） |

## PR プロセス

1. Issue を立ててから実装する
2. ブランチ名: `feat/issue-{N}-{description}` または `fix/issue-{N}-{description}`
3. 1 PR = 1 Issue を原則とする
4. `cargo fmt` / `cargo clippy` / `cargo test` をすべて通してから PR を出す
5. CI（check ジョブ + audit ジョブ）が緑になってからマージ

## 新しい inspection を追加する

`rpi` の inspection は `rpi-inspections` crate に実装し、`all()` に登録します。
以下のステップで追加できます。

### Step 1 — `rpi-inspections` にモジュールを追加

```
crates/rpi-inspections/src/
└── my_inspection.rs   ← 新規作成
```

`Inspection` trait を実装します:

```rust
// crates/rpi-inspections/src/my_inspection.rs

use rpi_core::{Context, Finding, Inspection, Location, Severity};

pub struct MyInspection;

impl MyInspection {
    pub const NAME: &'static str = "my-inspection";
}

impl Inspection for MyInspection {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn run(&self, ctx: &Context) -> Vec<Finding> {
        let mut findings = Vec::new();
        for krate in &ctx.crates {
            // ctx.config.* で rpi.toml の閾値を参照できる
            if /* 条件 */ false {
                findings.push(Finding {
                    inspection: Self::NAME,
                    severity: Severity::Warn,
                    location: Location {
                        krate: Some(krate.name.clone()),
                        ..Default::default()
                    },
                    message: format!("{} has ...", krate.name),
                    metric: None,
                });
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rpi_core::CrateData;
    use std::path::PathBuf;

    fn krate(name: &str) -> CrateData {
        CrateData {
            name: name.to_string(),
            manifest_path: PathBuf::from(format!("/w/{name}/Cargo.toml")),
            root_dir: PathBuf::from(format!("/w/{name}")),
            workspace_deps: vec![],
            external_deps: vec![],
            files: vec![],
        }
    }

    #[test]
    fn flags_when_condition_met() {
        let ctx = rpi_core::Context {
            crates: vec![krate("example")],
            ..Default::default()
        };
        let findings = MyInspection.run(&ctx);
        // assert expected findings
        let _ = findings;
    }
}
```

### Step 2 — `lib.rs` にモジュールを追加して `all()` に登録

```rust
// crates/rpi-inspections/src/lib.rs

mod my_inspection;  // 追加
use my_inspection::MyInspection;

pub fn all() -> Vec<Box<dyn rpi_core::Inspection>> {
    vec![
        // ... 既存 ...
        Box::new(MyInspection),  // 追加
    ]
}
```

### Step 3 — テストを追加

- ユニットテスト: `src/my_inspection.rs` 内の `#[cfg(test)]` に追加（境界値・異常系）
- acceptance テスト: `tests/fixtures/multi/` の既存ファイルで発火するなら `crates/rpi-cli/tests/acceptance.rs` にも追加

### Step 4 — README の inspection 一覧を更新

`README.md` の inspection テーブルに1行追加します:

```markdown
| `my-inspection` | 検出する内容 | Warn |
```

### Step 5 — 閾値が必要な場合は `Config` に追加

`rpi.toml` で上書きできる閾値が必要な場合:

```rust
// crates/rpi-core/src/lib.rs の Config struct に追加
pub my_inspection_warn: usize,

// Default impl にも追加
my_inspection_warn: 10,
```

inspection 内では `ctx.config.my_inspection_warn` で参照します。

## inspection 設計の注意点

- **副作用なし**: `Inspection::run()` は読み取り専用。ファイル書き込み・ネットワークアクセス禁止
- **Context を再パースしない**: AST は `ctx.crates[*].files[*].ast` から取得する（再 parse 禁止）
- **syn 表層解析に限定**: rustc 内部 API は使わない。型解決が必要な分析は「近似」と明記
- **マクロ展開は見えない**: `macro_rules!` / proc-macro 生成コードは AST に現れないため免責をコメントに書く
- **`unwrap()` を本番コードに書かない**: `Option` / `Result` は適切に処理する

## ディレクトリ構成

```
rust-project-inspector/
├── Cargo.toml                  # workspace 定義
├── audit.toml                  # cargo audit の ignore リスト
├── rpi.toml                    # rpi 自身の閾値設定（self-dogfood）
├── crates/
│   ├── rpi-core/               # Finding / Report / Inspection trait / Config
│   ├── rpi-collect/            # cargo_metadata + syn パース + git churn
│   ├── rpi-inspections/        # 各 inspection 実装
│   └── rpi-cli/                # clap エントリポイント + レンダラ
└── tests/
    └── fixtures/               # テスト用の小規模ワークスペース
```
