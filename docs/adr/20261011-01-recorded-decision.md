# workspace の収集と inspection と描画を分離する

- Status: Draft
- 記録日: 2026-10-11
- 対象: `rust-project-inspector`
- 元判断の決定日・承認者: NEEDS_CONFIRMATION（元資料で確認できない項目は確定しない）

## 背景

README は単一行の修正より crate 単位の優先順位を示すことを目的とし、Cargo workspace は役割別 crate を定義している。

## 記録する判断

rpi-core・rpi-collect・rpi-inspections・rpi-cli に分け、workspace 全体の構造を収集・評価して text / JSON / SARIF に出力する。

この ADR は既存資料・コードの判断を整理した遡及記録であり、今回の整備で新しい設計を承認・実装したものではない。設計資料にある将来案の実装完了は断定しない。

## 代替案と判断の根拠

上記の根拠資料に残る理由を記録する。比較した代替案・却下理由が資料にない場合は NEEDS_CONFIRMATION とし、後から選定経緯を作らない。

## 影響と制約

収集した事実、スコアの意味、出力形式の契約を維持する必要がある。構造の指標だけでコードの正しさを判断しない。

## 再検討する条件

inspection・スコア・出力契約・対応 workspace 構成の変更。

## 確認事項

- NEEDS_CONFIRMATION: 決定当時の承認者・日付と、記録した範囲での正式な採用状況。
- NEEDS_CONFIRMATION: 元資料にない代替案・却下理由。確認できた内容だけを追記する。

## 根拠・関連資料

- [README.md](../../README.md)
- [Cargo.toml](../../Cargo.toml)
- [crates/rpi-core/src/lib.rs](../../crates/rpi-core/src/lib.rs)
