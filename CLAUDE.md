# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## このリポジトリは何か

**wtfi2**（What The F\*ck Internet）。Wi-Fi から internet までの経路を並列に probe し、topology 図と「どこで切れてるか + 直し方」の 1 行 verdict を出す Rust 製ネットワーク診断 CLI/TUI。ローカルディレクトリは `~/wtfi` だが **GitHub は `kanywst/wtfi2`、crate 名も `wtfi2`、インストールされるバイナリ名は `wtfi`**（旧 `kanywst/wtfi` は archived）。macOS ファースト、Linux も対応。

## 構成（big picture）

- `engine.rs` — 経路の骨格（`CHAIN`: Host → Link → Gateway → WAN → DNS → Captive）を作り、全 probe を並列に走らせて結果を mpsc channel に流す。`-w` の dashboard は届いた順に埋め、one-shot は同じ channel を drain するだけ。`Uplink` hop は WAN が壊れてるときだけ後から差し込まれる（TTL sweep は健康時に払わない）。
- `probe/` — hop ごとの計測。`diagnose.rs` — 完成した `Path` から **最初の break** を見つけて verdict + fix + confidence にする（下流は巻き添え扱い）。break が無ければ loss/jitter で品質判定。
- `platform/` — OS 依存は `Platform` trait の裏に閉じ込める。macOS は CoreWLAN (`objc2-core-wlan`) + `route` / `scutil`、Linux は `ip -j` / `iw` / `resolv.conf` と `/proc` fallback。それ以外の OS は `unsupported.rs` で exit 3。
- `ui/`（ratatui dashboard）と `render.rs`（one-shot report）、`json.rs`（`--json`）。
- 記録系: `recorder.rs` / `history.rs`（`--record` / `--history` / `--every`）、`bundle.rs`（`--bundle` で AI 向け Markdown）、`mcp.rs`（`--mcp` で stdio MCP server）。
- `demo.rs` は `demo` feature 限定。README の GIF / PNG は `docs/*.tape` を vhs で `--demo` 再生して撮る（実ネットワークを載せないため。RFC 5737 アドレス）。

## 診断ロジックの不変条件（git log の fix が繰り返し直してきたもの）

- **「測れなかった」を「壊れている」と言わない**。probe の timeout・コマンド失敗・読めなかった値は `Warn` / `Fault::Unobserved` / unknown に落とし、`Fail` や packet loss にしない。ICMP を落とす router や probe を filter する gateway を「dead」と判定しない。
- **すべての probe は `PROBE_DEADLINE`、sweep 全体は `SWEEP_DEADLINE` で必ず有界**。新しい probe を足すときも同じ時計に乗せる（1 つ詰まると channel が閉じず CLI がハングする）。
- **OS 差は判定ロジックではなく platform / probe 側で吸収**。ping / traceroute のフラグは OS ごとに組み立てる（iputils の `-t` は TTL、Linux の traceroute は `-I`）。verdict 文言も "Mac" 決め打ちにしない。
- **外部契約は exit code（0-4）と `--json` の形だけ**。`tests/cli.rs` が実バイナリでこれを pin している。変えるなら README の表とテストも同時に。exit 4 は「何も測れなかった」で 2（Broken）とは別物。
- テストで本物の probe を走らせない（#64 で踏んだ）。

## よく使うコマンド

CI（`.github/workflows/ci.yml`）は `RUSTFLAGS=-D warnings` で macOS と ubuntu の 2 leg。ローカルでも同じ組み合わせで通す。

```bash
cargo fmt --all -- --check
RUSTFLAGS="-D warnings" cargo clippy --all-targets --all-features
cargo test --all-features
RUSTFLAGS="-D warnings" cargo build --release
cargo publish --dry-run --locked          # CI の Linux leg と同じ packaging チェック

# 実ネットワークで動作確認
./target/release/wtfi -v --no-color
./target/release/wtfi --json --timeout 1

# README 用の録画（vhs 必須、demo feature でビルド）
cargo build --release --features demo && vhs docs/report.tape

# workflow の静的チェック / dist の release 計画
actionlint .github/workflows/*.yml
dist plan
```

Linux leg（`platform/linux.rs`）は macOS ローカルではコンパイルされないので、Linux 側を触ったら CI の `linux build · package` の結果まで見る。

## 変更の出し方

- **main に直コミットしない。必ず feature branch → PR**。PR が CI + review bot の動作確認を兼ねる。
- PR の title / body は英語、conventional commit の 1 行 title + 数行の事実（何を変えた・reviewer が知るべき注意・どう確認した）。"Why" セクションの講釈は書かない。
- コードコメントは 1 行まで。設計の理由は PR body へ（古いコードの長文コメントは真似しない）。
- PR に付く check: `CI`、`CodeRabbit`、`Claude Review`、`plan`（dist dry-run）。**CodeRabbit の green は「レビューしてない」の意味**（star < 10 で skip しても pass を返す）。必要なら comment の "Trigger review" を手で押す。`Claude Review` は dependabot PR では意図的に skip。

## stacked PR の落とし穴（実際に PR を失った）

- `ci.yml` は `pull_request: branches: [main]` なので **base が feature branch の PR には CI が走らない**。stack の green は CI pass を意味しない。下から順に main へ retarget して merge するか、ローカルで検証する。
- merge 手順は「子を `gh pr edit N --base main` で retarget → 親を merge → 親 branch を削除」の順。**子が残っているのに `--delete-branch` すると子 PR が close され、二度と reopen できない**（#35 を失い #46 で出し直した）。
- retarget だけでは CI は起きない（`edited` は trigger 外）。retarget してから rebase & push する。push 済みなら `gh pr close` → `gh pr reopen`。
- 親を squash merge したら `git rebase --update-refs --onto origin/main <merged-branch> <top-branch>` で restack。
- Claude Review は stack の全 PR に thread を付ける。merge 対象だけでなく open な全 PR の未返信 thread を毎回確認する。

## リリース

- `chore(release): X.Y.Z` で `Cargo.toml` と `Cargo.lock` の version だけ上げる PR を merge し、`vX.Y.Z` tag を push。
- tag は **2 つの独立 workflow** を起動する: `release.yml`（cargo-dist → GitHub Release、macOS/Linux バイナリ、attestation、CycloneDX SBOM、`kanywst/homebrew-tap` の formula、secret `HOMEBREW_TAP_TOKEN`）と `publish-crate.yml`（crates.io、secret `CARGO_REGISTRY_TOKEN`）。**crates.io は不可逆**（yank はできても同じ version は二度と使えない）。tag 前に両方を明言し、version が空いているか確認する: `curl -s https://crates.io/api/v1/crates/wtfi2/versions`。
- `release.yml` は dist 生成物に **手パッチ**が当たっている（formula commit の冪等化、`cargo-cyclonedx` output 名の typo 修正）。`dist generate` で再生成したら手パッチが消えるので差分を確認して戻す。`dist-workspace.toml` の `allow-dirty = ["ci"]` はそのため。
- tap の secret 名 `HOMEBREW_TAP_TOKEN` は他リポ（`HOMEBREW_TAP_GITHUB_TOKEN`）と違うが、dist がハードコードしているので **揃えない**。
- crates.io 公開物から `.github/` / `docs/` / `dist-workspace.toml` は `exclude` 済み。
