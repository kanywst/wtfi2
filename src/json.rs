//! Machine-readable output for `--json` (scripting, CI, sharing).

use crate::diagnose::Verdict;
use crate::model::{Path, Status};
use serde_json::{Value, json};

fn status_str(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Pending => "pending",
        Status::Skipped => "skipped",
    }
}

pub fn to_value(path: &Path, verdict: &Verdict) -> Value {
    let hops: Vec<Value> = path
        .hops
        .iter()
        .map(|h| {
            json!({
                "id": format!("{:?}", h.id).to_lowercase(),
                "layer": h.layer.label(),
                "title": h.title,
                "subtitle": h.subtitle,
                "status": status_str(h.status),
                "summary": h.summary,
                "latency_ms": h.latency_ms,
                "metrics": h.metrics.iter().map(|m| json!({
                    "label": m.label,
                    "value": m.value,
                    "status": m.status.map(status_str),
                })).collect::<Vec<_>>(),
            })
        })
        .collect();

    json!({
        "status": status_str(verdict.status),
        "verdict": {
            "headline": verdict.headline,
            "cause": verdict.cause,
            "fix": verdict.fix,
            "confidence": format!("{:?}", verdict.confidence).to_lowercase(),
        },
        "first_break": path.first_break().map(|h| format!("{:?}", h.id).to_lowercase()),
        "path": hops,
    })
}

pub fn to_string(path: &Path, verdict: &Verdict) -> String {
    serde_json::to_string_pretty(&to_value(path, verdict)).unwrap_or_else(|_| "{}".into())
}
