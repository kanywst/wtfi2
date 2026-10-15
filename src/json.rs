//! Machine-readable output for `--json` (scripting, CI, sharing).

use crate::diagnose::Verdict;
use crate::model::{HopId, Path, Status};
use serde_json::{Value, json};

pub(crate) fn status_str(s: Status) -> &'static str {
    match s {
        Status::Ok => "ok",
        Status::Warn => "warn",
        Status::Fail => "fail",
        Status::Pending => "pending",
        Status::Skipped => "skipped",
    }
}

pub(crate) fn hop_id_str(id: HopId) -> String {
    format!("{id:?}").to_lowercase()
}

pub fn to_value(path: &Path, verdict: &Verdict) -> Value {
    let hops: Vec<Value> = path
        .hops
        .iter()
        .map(|h| {
            json!({
                "id": hop_id_str(h.id),
                "layer": h.layer.label(),
                "title": h.title,
                "subtitle": h.subtitle,
                "status": status_str(h.status),
                "fault": h.fault.map(|f| f.code()),
                "summary": h.summary,
                "evidence": h.evidence,
                "latency_ms": h.latency_ms,
                "loss_pct": h.loss_pct,
                "jitter_ms": h.jitter_ms,
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
            "source": verdict.source.map(hop_id_str),
        },
        "first_break": path.first_break().map(|h| hop_id_str(h.id)),
        "path": hops,
    })
}

pub fn to_string(path: &Path, verdict: &Verdict) -> String {
    serde_json::to_string_pretty(&to_value(path, verdict)).unwrap_or_else(|_| "{}".into())
}
