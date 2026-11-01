# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

**wtfi2** (What The F\*ck Internet). A network diagnostics CLI/TUI in Rust that probes the path from Wi-Fi to the internet in parallel and prints a topology diagram plus a one-line verdict on "where it breaks + how to fix it". The local directory is `~/wtfi`, but **the GitHub repo is `kanywst/wtfi2`, the crate name is also `wtfi2`, and the installed binary is `wtfi`** (the old `kanywst/wtfi` is archived). macOS first, Linux also supported.

## Layout (big picture)

- `engine.rs`: builds the skeleton of the path (`CHAIN`: Host → Link → Gateway → WAN → DNS → Captive), runs every probe in parallel and streams results into an mpsc channel. The `-w` dashboard fills in as results arrive; one-shot just drains the same channel. The `Uplink` hop is inserted afterwards only when WAN is broken (the TTL sweep is not paid when healthy).
- `probe/`: per-hop measurement. `diagnose.rs`: finds the **first break** in the completed `Path` and turns it into verdict + fix + confidence (everything downstream is treated as collateral). With no break, it judges quality from loss/jitter.
- `platform/`: OS-specific code is kept behind the `Platform` trait. macOS uses CoreWLAN (`objc2-core-wlan`) + `route` / `scutil`; Linux uses `ip -j` / `iw` / `resolv.conf` with a `/proc` fallback. Any other OS exits 3 via `unsupported.rs`.
- `ui/` (ratatui dashboard), `render.rs` (one-shot report), `json.rs` (`--json`).
- Recording: `recorder.rs` / `history.rs` (`--record` / `--history` / `--every`), `bundle.rs` (`--bundle`, Markdown for AI), `mcp.rs` (`--mcp`, stdio MCP server).
- `demo.rs` is behind the `demo` feature. The README GIFs / PNGs are captured by replaying `--demo` through `docs/*.tape` with vhs (to keep the real network out of them; RFC 5737 addresses).

## Diagnosis invariants (what fixes in git log have repeatedly restored)

- **Do not report "could not measure" as "broken".** Probe timeouts, command failures and unreadable values go to `Warn` / `Fault::Unobserved` / unknown, not `Fail` or packet loss. Do not judge a router that drops ICMP, or a gateway that filters probes, as "dead".
- **Every probe is bounded by `PROBE_DEADLINE`.** One-shot runs (`run_once` / `run_once_within`, also used by `--mcp`'s `diagnose_now`) are additionally capped by `SWEEP_DEADLINE`. The live dashboard (`-w`) calls `engine::spawn()` directly, so the initial `platform::route()` lookup sits outside the sweep timer. New probes go on the same per-probe clock (if one gets stuck, the channel never closes and the CLI hangs).
- **OS differences are absorbed in platform / probe, not in the diagnosis logic.** ping / traceroute flags are built per OS (iputils `-t` is TTL, Linux traceroute uses `-I`). Do not hardcode "Mac" in verdict text either.
- **External contracts: the exit code (0-4), the shape of `--json`, and the `--mcp` stdio JSON-RPC server with its named tools** (`list_episodes`, `get_timeline`, `get_sweeps`, `get_os_log`, `get_bundle`, `diagnose_now`). `tests/cli.rs` pins the CLI side against the real binary. If you change any of them, update the README and the tests together. Exit 4 means "nothing could be measured" and is distinct from 2 (Broken).
- Default unit tests must not run real probes (hit in #64). Two exceptions exist: `tests/cli.rs` runs the real binary against the real network with `--timeout 8` and asserts structure and invariants, not network health; and live probe tests in `src/probe/net.rs` are `#[ignore]` and run manually with `--ignored`.

## Common commands

CI (`.github/workflows/ci.yml`) has two legs, macOS and ubuntu, with `RUSTFLAGS: -D warnings` set for the whole workflow. Export it so every local command matches.

```bash
export RUSTFLAGS="-D warnings"
cargo fmt --all -- --check
cargo clippy --all-targets --all-features
cargo test --all-features
cargo build --release
cargo publish --dry-run --locked          # same packaging check as the CI Linux leg

# Check behaviour on the real network
./target/release/wtfi -v --no-color
./target/release/wtfi --json --timeout 1

# Recording for the README (requires vhs, build with the demo feature)
cargo build --release --features demo && vhs docs/report.tape

# Static check of workflows / dist release plan
actionlint .github/workflows/*.yml
dist plan
```

The Linux leg (`platform/linux.rs`) is not compiled locally on macOS, so if you touch the Linux side, check the result of CI's `linux build · package` too.

## How to ship changes

- **Do not commit directly to main. Always feature branch → PR.** The PR doubles as the check that CI and the review bots work.
- PR title / body in English: a one-line conventional commit title plus a few lines of facts (what changed, caveats the reviewer should know, how it was verified). No "Why" section lecturing.
- Code comments are one line at most. Design reasoning goes in the PR body (do not imitate the long comments in older code).
- Checks on PRs: `CI`, `CodeRabbit`, `Claude Review`, `plan` (dist dry-run). **A green CodeRabbit means "did not review"** (it returns pass even when it skips because stars < 10). If needed, press "Trigger review" in its comment by hand. `Claude Review` is intentionally skipped on dependabot PRs.

## Stacked PR pitfalls (a PR was actually lost)

- `ci.yml` uses `pull_request: branches: [main]`, so **CI does not run on PRs whose base is a feature branch**. Green in a stack does not mean CI passed. Retarget to main and merge from the bottom up, or verify locally.
- Merge order: retarget the child with `gh pr edit N --base main`, merge the parent, then delete the parent branch. **Using `--delete-branch` while a child still exists closes the child PR, and it can never be reopened** (#35 was lost and resubmitted as #46).
- Retargeting alone does not trigger CI (`edited` is not a trigger). Retarget, then rebase & push. If already pushed, `gh pr close` → `gh pr reopen`.
- After squash-merging the parent, restack with `git rebase --update-refs --onto origin/main <merged-branch> <top-branch>`.
- Claude Review posts threads on every PR in the stack. Each time, check unreplied threads on all open PRs, not just the one being merged.

## Releases

- Merge a `chore(release): X.Y.Z` PR that bumps only the version in `Cargo.toml` and `Cargo.lock`, then push the `vX.Y.Z` tag.
- The tag starts **two independent workflows**: `release.yml` (cargo-dist → GitHub Release, macOS/Linux binaries, attestation, CycloneDX SBOM, the formula in `kanywst/homebrew-tap`, secret `HOMEBREW_TAP_TOKEN`) and `publish-crate.yml` (crates.io, secret `CARGO_REGISTRY_TOKEN`). **crates.io is irreversible** (you can yank, but the same version can never be used again). Before tagging, state both explicitly and check that the version is free: `curl -s https://crates.io/api/v1/crates/wtfi2/versions`.
- `release.yml` has **hand patches** on top of the dist output (making the formula commit idempotent, fixing a typo in the `cargo-cyclonedx` output name). Regenerating with `dist generate` drops them, so check the diff and restore them. That is why `dist-workspace.toml` has `allow-dirty = ["ci"]`.
- The tap secret name `HOMEBREW_TAP_TOKEN` differs from other repos (`HOMEBREW_TAP_GITHUB_TOKEN`), but dist hardcodes it, so **do not align them**.
- `.github/` / `docs/` / `dist-workspace.toml` are already `exclude`d from the crates.io package.
