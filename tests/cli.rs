//! End-to-end tests for the CLI's published contract.
//!
//! Everything else in this crate is a unit test against a pure seam, which is
//! where the reasoning lives — but it means nothing here had ever driven the
//! actual binary. The two things `README.md` promises to scripts, the **exit
//! codes** and the **`--json` shape**, were the least covered code in the
//! project despite being the only parts users are told they can depend on.
//!
//! These run the real binary against the real network, so they assert on
//! *structure and invariants*, never on health: the machine running them might
//! be online, offline, or behind a portal, and all three have to pass.

use std::process::{Command, Output};

/// Documented in the README's exit-code table. A code outside this set means
/// either the table or the binary is wrong, and a script branching on it would
/// be silently mishandling a state it was told could not happen.
const DOCUMENTED_EXIT_CODES: [i32; 5] = [0, 1, 2, 3, 4];

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wtfi"))
        .args(args)
        // Every test bounds the sweep: an unbounded probe on a wedged network
        // would hang CI rather than fail it.
        .args(["--timeout", "8"])
        .output()
        .expect("the binary under test should run")
}

fn json(args: &[&str]) -> serde_json::Value {
    let out = run(args);
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "--json must emit parseable JSON on stdout: {e}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

#[test]
fn the_exit_code_is_one_the_readme_documents() {
    let code = run(&[])
        .status
        .code()
        .expect("should exit, not be signalled");
    assert!(
        DOCUMENTED_EXIT_CODES.contains(&code),
        "exit code {code} is not in the documented set {DOCUMENTED_EXIT_CODES:?}"
    );
}

/// The exit code and the reported status are two channels for one answer, and
/// a script that branches on the code while a human reads the text must not be
/// told different things.
#[test]
fn the_exit_code_agrees_with_the_reported_status() {
    let out = run(&["--json"]);
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    let expected = match doc["status"].as_str().expect("status is a string") {
        "ok" => 0,
        "warn" => 1,
        "skipped" => 4,
        _ => 2,
    };
    assert_eq!(
        out.status.code(),
        Some(expected),
        "status {} should exit {expected}",
        doc["status"]
    );
}

#[test]
fn json_output_carries_the_documented_shape() {
    let doc = json(&["--json"]);

    for key in ["status", "verdict", "first_break", "path"] {
        assert!(doc.get(key).is_some(), "missing top-level key `{key}`");
    }
    for key in ["headline", "cause", "fix", "confidence", "source"] {
        assert!(
            doc["verdict"].get(key).is_some(),
            "missing verdict key `{key}`"
        );
    }
    assert!(
        !doc["verdict"]["headline"]
            .as_str()
            .expect("headline is a string")
            .is_empty(),
        "a verdict with no headline says nothing"
    );

    let path = doc["path"].as_array().expect("path is an array");
    assert!(!path.is_empty(), "the path must have hops");
    for hop in path {
        for key in [
            "id", "layer", "title", "status", "fault", "summary", "evidence", "metrics",
        ] {
            assert!(hop.get(key).is_some(), "hop missing `{key}`: {hop}");
        }
        assert!(hop["metrics"].is_array(), "metrics must be an array: {hop}");
    }
}

/// Statuses are a closed set that consumers match on. A new variant reaching
/// `--json` without this test being updated would break every such match.
#[test]
fn every_status_in_json_is_a_known_variant() {
    const KNOWN: [&str; 5] = ["ok", "warn", "fail", "pending", "skipped"];
    let doc = json(&["--json"]);
    let mut seen: Vec<String> = vec![doc["status"].as_str().unwrap().to_string()];
    for hop in doc["path"].as_array().unwrap() {
        seen.push(hop["status"].as_str().unwrap().to_string());
        for metric in hop["metrics"].as_array().unwrap() {
            if let Some(s) = metric["status"].as_str() {
                seen.push(s.to_string());
            }
        }
    }
    for status in seen {
        assert!(
            KNOWN.contains(&status.as_str()),
            "unknown status `{status}`"
        );
    }
}

/// A one-shot report has finished by definition. A hop still `pending` in its
/// output means the sweep was truncated without being settled, which renders
/// as "Scanning your connection…" in a report that has stopped scanning.
#[test]
fn a_one_shot_run_leaves_no_hop_pending() {
    let doc = json(&["--json"]);
    let pending: Vec<_> = doc["path"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["status"] == "pending")
        .map(|h| h["id"].clone())
        .collect();
    assert!(pending.is_empty(), "hops left pending: {pending:?}");
    assert_ne!(doc["status"], "pending", "the verdict must have settled");
}

/// `first_break`, when present, has to name a hop that is actually in the
/// path and actually failed — otherwise a consumer following the pointer
/// lands on nothing, or on a healthy hop.
#[test]
fn first_break_points_at_a_hop_that_really_failed() {
    let doc = json(&["--json"]);
    let Some(id) = doc["first_break"].as_str() else {
        return; // Nothing broken on this machine right now; nothing to check.
    };
    let hop = doc["path"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["id"] == id)
        .unwrap_or_else(|| panic!("first_break `{id}` is not in the path"));
    assert_eq!(
        hop["status"], "fail",
        "first_break names a hop that is not failing"
    );
}

/// Likewise the verdict's source hop: the report prints that hop's evidence,
/// so a dangling pointer would silently drop the basis for the claim.
#[test]
fn the_verdict_source_names_a_hop_in_the_path() {
    let doc = json(&["--json"]);
    let Some(id) = doc["verdict"]["source"].as_str() else {
        return;
    };
    assert!(
        doc["path"]
            .as_array()
            .unwrap()
            .iter()
            .any(|h| h["id"] == id),
        "verdict.source `{id}` is not in the path"
    );
}

#[test]
fn no_color_emits_no_ansi_escapes() {
    let out = run(&["--no-color", "-v"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(!text.contains('\u{1b}'), "ANSI escape in --no-color output");
    assert!(!text.is_empty(), "the report should not be empty");
}

/// Piping already disables colour, so `--json` must be clean without the flag
/// — a consumer parsing it should never have to strip escapes.
#[test]
fn json_output_is_never_decorated() {
    let out = run(&["--json"]);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains('\u{1b}'),
        "ANSI escape in --json output"
    );
}

#[test]
fn watch_and_json_are_rejected_rather_than_silently_ranked() {
    let out = run(&["--watch", "--json"]);
    assert!(
        !out.status.success(),
        "conflicting flags must not be accepted"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("cannot be used with"),
        "the conflict should be explained on stderr"
    );
}

#[test]
fn help_and_version_answer_without_probing() {
    let help = run(&["--help"]);
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    for flag in ["--watch", "--json", "--verbose", "--no-color", "--timeout"] {
        assert!(text.contains(flag), "`{flag}` missing from --help");
    }

    let version = run(&["--version"]);
    assert!(version.status.success());
    assert!(
        String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_VERSION")),
        "--version should report the crate version"
    );
}
