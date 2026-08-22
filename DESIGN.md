# rust-project-inspector 詳細設計

> Static analysis tool for Rust projects
> **作成:** 2026-08-17 / **状態:** 設計フェーズ（scaffold → 設計確定）

---

## 1. ポジショニング / 特徴

### エレベーターピッチ
> **「crate をまたいだ構造の歪みを、1コマンドで1枚にする」**
> clippy は行を、cargo-audit は依存を見る。どれも単一 crate・単一関心。
> rust-project-inspector は **workspace 全体を1つの生き物として診る唯一のツール。**
> 答えるのは「どの行を直すか」ではなく **「どの crate から手を付けるべきか」**。

### 決定的な特徴（他ツールが持たない4点）
| # | 特徴 | なぜ他ツールに出せないか |
|---|---|---|
| 1 | **crate 間の構造**を見る（循環依存・God module・結合度） | clippy/geiger は1ファイル/1関数で閉じ、crate 境界を越えない |
| 2 | **複数関心を1レポートに束ねる**（unsafe+test空白+依存衛生+API表面積） | 既存は「1ツール1関心」。横断は人手で繋いでいる |
| 3 | **lint を1つも出さない** | 「良くない行」でなく「良くない構造」だけ。clippy と競合しない割り切り |
| 4 | **時系列で劣化を検知**（baseline 比較） | 単発スキャンは「今」しか見ない。構造の**悪化速度**を出せる |

### 既存ツールとの棲み分け
| ツール | 粒度 | 見るもの | 本ツールとの関係 |
|---|---|---|---|
| clippy | 関数/式ローカル | イディオム・バグパターン | **重複回避**。lint はやらない |
| cargo-audit | 依存 | RustSec 脆弱性 | 結果を取り込む（呼ぶ） |
| cargo-udeps | 依存 | 未使用依存 | 概念を内包（nightly 不要な近似で） |
| cargo-geiger | unsafe | unsafe 使用量 | 概念を内包 |
| **rust-project-inspector** | **workspace/crate/module** | **プロジェクト構造の健全性** | ↑を束ねた俯瞰レポート |

### 同じ repo に各ツールが返すもの（差が一目でわかる例）
```
clippy      → "src/foo.rs:42  この match は if let にできる"        （行）
cargo-audit → "tokio 1.2 に RUSTSEC-XXXX の脆弱性"                  （依存）
─────────────────────────────────────────────────────────────
rpi         → "fluxion-core ⇄ fluxion-host に循環依存。
               fluxion-host はテスト0・pub item 87・unsafe 12。
               この crate が workspace の構造リスク最上位。"        （構造）
```

**性格:** syn 表層解析に限定（rustc 内部API不採用）＝型解決の精度を捨てる代わりに、**どんな Rust プロジェクトにも nightly なしで即座に効く**。精度より**俯瞰と手軽さ**に全振り。

---

## 2. 分析ディメンション（Inspections）

各 inspection は独立モジュール。`Finding` を吐く共通トレイトに従う。

### MVP（Phase 1）
1. **workspace-graph** — crate 依存グラフ。循環依存検出、深さ、孤立 crate。
2. **module-size** — モジュール/ファイルの LOC・item 数分布。肥大モジュール（閾値超）を警告。
3. **unsafe-surface** — `unsafe` ブロック/fn/trait/impl を集計。crate 別 unsafe 密度。
4. **pub-surface** — 公開 API 表面積（`pub` item 数）。crate の外部露出が過大な箇所。
5. **test-gap** — `#[test]`/`#[cfg(test)]` の有無を crate/module 単位で集計。テスト 0 の crate を列挙。

### Phase 2
6. **dep-hygiene** — 未使用依存の近似検出（`Cargo.toml` の deps vs `use` 解析）、version 重複（同一 crate 複数版）。
7. **coupling** — module 間 `use` 参照から結合度（fan-in/fan-out）を算出。God module 検出。
8. **audit-bridge** — `cargo audit --json` を呼び結果統合。
9. **doc-coverage** — `pub` item のうち doc comment 欠落率。

### Phase 3
10. **complexity** — 関数の循環的複雑度（AST から近似）。
11. **churn×complexity** — `git log` の変更頻度 × 複雑度でリスクホットスポット。
12. **trend** — 過去実行結果を保存し、メトリクスの時系列推移（劣化検知）。

---

## 3. アーキテクチャ

```
                 ┌──────────────────────────────────────────┐
   cargo project │   rpi (CLI, clap)                         │
   ─────────────>│                                           │
                 │  1. collect    cargo_metadata → Workspace │
                 │  2. parse      syn → per-file AST          │
                 │  3. inspect    Vec<dyn Inspection>         │
                 │  4. aggregate  Findings → Report           │
                 │  5. render     text / json / sarif / md    │
                 └──────────────────────────────────────────┘
```

### crate 構成（workspace 自身も dogfooding 対象にする）
```
rust-project-inspector/
├─ Cargo.toml               # [workspace]
├─ crates/
│  ├─ rpi-core/             # データ型・trait・Report。依存最小（syn, serde）
│  ├─ rpi-collect/          # cargo_metadata ラッパ、ファイル収集、AST パース
│  ├─ rpi-inspections/      # 各 inspection 実装（feature ごとに分割可）
│  └─ rpi-cli/              # clap エントリ、レンダラ、設定読み込み
└─ tests/fixtures/          # 小さな Rust プロジェクトを固定入力に
```

分割理由: `rpi-core` を薄く保てば、将来 inspection を外部 crate としてプラグイン化できる。CLI とロジックを分けて統合テストを CLI 非依存で書く。

---

## 4. データモデル（rpi-core）

```rust
pub struct Report {
    pub workspace: WorkspaceInfo,
    pub findings: Vec<Finding>,
    pub metrics: Metrics,          // 集計値（unsafe 数, テスト crate 率 等）
    pub generated_at: String,      // 呼び出し側が注入（時刻取得を core に持たせない）
}

pub struct Finding {
    pub inspection: &'static str,  // "module-size"
    pub severity: Severity,        // Info | Warn | Error
    pub location: Location,        // crate / file / span(optional)
    pub message: String,
    pub metric: Option<f64>,       // 閾値超過の実測値
}

pub trait Inspection {
    fn name(&self) -> &'static str;
    fn run(&self, ctx: &Context) -> Vec<Finding>;
}
```

`Context` に workspace メタ + パース済み AST マップを渡す。各 inspection は AST を再パースしない（1回パース → 共有）。

---

## 5. CLI / 出力

```bash
rpi inspect [PATH]                 # 既定: カレント workspace
rpi inspect --format json|sarif|md|text
rpi inspect --only unsafe-surface,test-gap
rpi inspect --fail-on warn          # CI 用: 閾値超過で非0終了
rpi inspect --baseline .rpi.json    # 前回比較（trend）
```

- **text**: 人間向けサマリ（crate ランキング表 + top findings）。
- **sarif**: GitHub Code Scanning にそのまま食わせられる（既存 CI 資産と接続）。
- **設定**: `rpi.toml` で閾値上書き（module-size 上限、unsafe 密度許容 等）。

---

## 6. 技術選定

| 用途 | crate | 理由 |
|---|---|---|
| workspace メタ | `cargo_metadata` | 公式。crate グラフ・target・feature を取得 |
| AST パース | `syn` (full) | デファクト。span 情報付き |
| 依存グラフ | `guppy` or 自前(petgraph) | 循環検出は petgraph の `tarjan_scc` で十分 |
| CLI | `clap` v4 (derive) | 既存 Rust repo と統一 |
| 直列化 | `serde` + `serde_json` | json/sarif 出力 |
| git churn | `git2` or `git log` 呼出 | Phase 3。まずは外部コマンドで十分 |

**非採用:** rustc 内部 API（`rustc_driver`）は nightly 固定・保守コスト過大 → **不採用**。syn ベースの表層解析に限定し、型解決が要る inspection は「近似」と明記する（正確さより俯瞰を優先）。

---

## 7. dogfooding 計画

自分の Rust 資産を固定ベンチにする。

| repo | 規模 | 検証する inspection |
|---|---|---|
| **fluxion** | multi-crate workspace / 34 rs | workspace-graph・coupling・test-gap（本命）|
| **wasm-runtime** | 単一 crate / 5 rs | module-size・unsafe-surface（wasm デコードで unsafe 出やすい）|
| rpi 自身 | — | セルフ適用（`rpi inspect` を CI に）|

受け入れ基準: fluxion に対して「循環依存 0 / 各 crate のテスト有無 / 最大モジュール LOC」が正しく出ること。

---

## 8. ロードマップと工数見積り

feedback[[feedback_issue_estimate]] に従い自分/市場工数を併記。

| Phase | 内容 | 自分見積 | 市場見積 |
|---|---|---|---|
| P0 | workspace 初期化・rpi-core 型・CLI 骨組み・fixtures | 0.5d | 1.5d |
| P1 | inspection 1–5 + text/json 出力 + fluxion 検証 | 2.5d | 6d |
| P2 | dep-hygiene/coupling/audit-bridge/doc + sarif + CI 統合 | 3d | 8d |
| P3 | complexity/churn/trend + baseline 比較 | 3d | 8d |

**MVP = P0+P1**（3d）。ここまでで「fluxion を食わせて1枚レポート」が動く。

---

## 9. Issue 分解案（着手時に new-issue 化）

- #1 P0: workspace scaffold + rpi-core (`Report`/`Finding`/`Inspection`) + clap 骨組み
- #2 P1: `rpi-collect`（cargo_metadata + syn パース + Context 構築）
- #3 P1: inspection `workspace-graph`（循環検出）
- #4 P1: inspection `module-size` / `unsafe-surface` / `pub-surface` / `test-gap`
- #5 P1: text/json レンダラ + fluxion/wasm-runtime 受け入れテスト
- #6 P2: sarif 出力 + GitHub Code Scanning 連携 + `--fail-on`
- #7 P2: `dep-hygiene` / `coupling` / `audit-bridge`
- #8 P3: `complexity` / churn ホットスポット / `--baseline` trend

---

## 10. リスク / 未決事項

- **syn 表層解析の限界**: `use` エイリアス・re-export・マクロ展開後のコードは追えない。→ 「近似」と明示し、複雑度/結合度は目安値として提示。
- **マクロ**: `macro_rules!`/proc-macro 生成コードは AST に現れない。unsafe-surface 等で漏れ得る → ドキュメントで免責。
- **既存 clippy との差別化を保てるか**: lint 追加要望が来ても core に入れない。あくまで「プロジェクト俯瞰」に閉じる。
- **命名**: バイナリ名 `rpi` は Raspberry Pi と衝突しやすい。crates.io 公開時は要再考（`cargo-inspect` サブコマンド化も選択肢）。
