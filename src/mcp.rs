//! `wtfi --mcp`: the recorded history as an MCP server over stdio.

use crate::bundle::{self, Redactor};
use crate::history::{self, Snapshot};
use crate::platform::LogRead;
use crate::{diagnose, engine, json};
use serde_json::{Value, json};
use std::hash::RandomState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const PROTOCOLS: [&str; 4] = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
const MAX_SWEEPS: usize = 20;
const LOG_DEFAULT_SECS: u64 = 900;
const LOG_MAX_SECS: u64 = 7200;
const LOG_READ_DEADLINE: Duration = Duration::from_secs(30);

pub type SharedLog = Arc<dyn Fn(u64, u64, Duration) -> Result<LogRead, String> + Send + Sync>;

pub struct Server {
    pub history: Option<PathBuf>,
    pub log: SharedLog,
    /// Fixed clock for tests; `None` reads the system time per request.
    pub now: Option<u64>,
    /// One salt per session, so a masked SSID or MAC reads the same in every tool.
    pub salt: RandomState,
    pub sweeping: tokio::sync::Mutex<()>,
    /// OS log scans are heavy and can't be cancelled, so one at a time.
    pub reading: tokio::sync::Mutex<()>,
}

/// Requests run concurrently, so a slow tool doesn't hold up `ping`.
pub async fn serve(server: Arc<Server>) -> std::io::Result<()> {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
    let writer = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(reply) = rx.recv().await {
            stdout.write_all(format!("{reply}\n").as_bytes()).await?;
            stdout.flush().await?;
        }
        std::io::Result::Ok(())
    });
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = lines.next_line().await? {
        let (server, tx) = (server.clone(), tx.clone());
        tasks.spawn(async move {
            let reply = match serde_json::from_str::<Value>(&line) {
                Ok(req) => {
                    let id = req.get("method").and(req.get("id")).cloned();
                    match tokio::spawn(async move { server.handle(&req).await }).await {
                        Ok(reply) => reply,
                        Err(_) => id.map(|id| error(id, -32603, "internal error")),
                    }
                }
                Err(e) => Some(error(Value::Null, -32700, &e.to_string())),
            };
            if let Some(reply) = reply {
                let _ = tx.send(reply);
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    drop(tx);
    writer.await.unwrap_or(Ok(()))
}

impl Server {
    /// One JSON-RPC message in, at most one out (notifications get none).
    pub async fn handle(&self, req: &Value) -> Option<Value> {
        if !req.is_object() {
            return Some(error(
                Value::Null,
                -32600,
                "expected a single JSON-RPC object",
            ));
        }
        // Notifications and replies to our (nonexistent) requests get no answer.
        req.get("method")?;
        let id = req.get("id")?.clone();
        let params = &req["params"];
        let result = match req["method"].as_str().unwrap_or("") {
            "initialize" => {
                let asked = params["protocolVersion"].as_str().unwrap_or("");
                let version = PROTOCOLS
                    .into_iter()
                    .find(|v| *v == asked)
                    .unwrap_or(PROTOCOLS[0]);
                json!({
                    "protocolVersion": version,
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "wtfi", "version": env!("CARGO_PKG_VERSION") },
                    "instructions": "Network history recorded by `wtfi --record`. Start with list_episodes, then pull sweeps or the OS log around the one you care about. diagnose_now probes the network as it is right now.",
                })
            }
            "ping" => json!({}),
            "tools/list" => json!({ "tools": tools() }),
            "tools/call" => {
                let args = &params["arguments"];
                match self.call(params["name"].as_str().unwrap_or(""), args).await {
                    Ok(text) => json!({ "content": [{ "type": "text", "text": text }] }),
                    Err(e) => {
                        json!({ "content": [{ "type": "text", "text": e }], "isError": true })
                    }
                }
            }
            m => return Some(error(id, -32601, &format!("method not found: {m}"))),
        };
        Some(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    async fn call(&self, name: &str, args: &Value) -> Result<String, String> {
        let now = self.now.unwrap_or_else(history::now_secs);
        if name == "diagnose_now" {
            // Overlapping sweeps would load the link and skew each other's numbers.
            let Ok(_one_at_a_time) = self.sweeping.try_lock() else {
                return Err("a live sweep is already running; try again in a few seconds".into());
            };
            let path = engine::run_once_within(engine::SWEEP_DEADLINE).await;
            let mut doc = json::to_value(&path, &diagnose::diagnose(&path));
            if redacting(args) {
                let snapshot = Snapshot {
                    ts: now,
                    sweep: doc.clone(),
                };
                Redactor::new(&self.salt, &[&snapshot]).sweep(&mut doc);
            }
            return Ok(doc.to_string());
        }
        let window = since(args)?.as_secs();
        let (from, to) = range(args, window, now)?;
        let since = now.saturating_sub(window).min(from);
        // The OS log stands on its own; the recording only adds SSIDs to mask.
        let log_only = name == "get_os_log";
        let mut unreadable = None;
        let (records, sweeps) = match &self.history {
            Some(file) if !log_only => (
                history::load(file, usize::MAX).map_err(|e| e.to_string())?,
                history::load_sweeps(file, since).map_err(|e| e.to_string())?,
            ),
            Some(file) => match history::load_sweeps(file, since) {
                Ok(sweeps) => (Vec::new(), sweeps),
                Err(e) => {
                    unreadable = Some(e.to_string());
                    (Vec::new(), Vec::new())
                }
            },
            None if log_only => (Vec::new(), Vec::new()),
            None => return Err("no history file: set WTFI_HISTORY, XDG_STATE_HOME or HOME".into()),
        };
        let all: Vec<&Snapshot> = sweeps.iter().collect();
        let redactor = redacting(args).then(|| Redactor::new(&self.salt, &all));
        let text = |s: String| match &redactor {
            Some(r) => r.text(&s),
            None => s,
        };
        let windowed: Vec<_> = records.iter().filter(|r| r.ts >= since).cloned().collect();
        Ok(match name {
            "list_episodes" => {
                let mut eps = bundle::episodes(&windowed);
                if windowed.last().is_some_and(|l| bundle::stale(l, now))
                    && let Some(e) = eps.last_mut().filter(|e| e.end.is_none())
                {
                    e.cut = true;
                }
                let eps: Vec<Value> = eps
                    .iter()
                    .map(|e| {
                        json!({
                            "start": history::utc(e.start),
                            "start_ts": e.start,
                            "end": e.end.map(history::utc),
                            "end_ts": e.end,
                            "last_unhealthy_ts": e.last,
                            "recorder_stopped_before_end": e.cut,
                            "sweeps": e.sweeps,
                            "worst": e.worst,
                            "first_break": e.first_break,
                            "headline": e.headline,
                        })
                    })
                    .collect();
                let gaps: Vec<Value> = bundle::gaps(&windowed)
                    .iter()
                    .map(|(a, b)| json!({ "from": history::utc(*a), "to": history::utc(*b) }))
                    .collect();
                text(
                    json!({ "sweeps": windowed.len(), "episodes": eps, "recorder_gaps": gaps })
                        .to_string(),
                )
            }
            "get_timeline" => text(serde_json::to_string(&windowed).map_err(|e| e.to_string())?),
            "get_sweeps" => {
                let mut picked: Vec<Value> = sweeps
                    .iter()
                    .filter(|s| (from..=to).contains(&s.ts))
                    .map(|s| {
                        let mut sweep = s.sweep.clone();
                        bundle::prune(&mut sweep);
                        if let Some(r) = &redactor {
                            r.sweep(&mut sweep);
                        }
                        json!({ "at": history::utc(s.ts), "ts": s.ts, "sweep": sweep })
                    })
                    .collect();
                let skip = picked.len().saturating_sub(MAX_SWEEPS);
                let picked = picked.split_off(skip);
                json!({ "omitted_older": skip, "sweeps": picked }).to_string()
            }
            "get_os_log" => {
                let from = match (args["from_ts"].as_u64(), args["since"].is_string()) {
                    (Some(from), _) => from,
                    (None, true) => from,
                    (None, false) => to.saturating_sub(LOG_DEFAULT_SECS),
                };
                if to.saturating_sub(from) > LOG_MAX_SECS {
                    return Err(format!(
                        "ask for at most {}h of log at a time",
                        LOG_MAX_SECS / 3600
                    ));
                }
                let Ok(_one_at_a_time) = self.reading.try_lock() else {
                    return Err("an OS log read is already running; try again shortly".into());
                };
                let log = self.log.clone();
                let read = tokio::task::spawn_blocking(move || log(from, to, LOG_READ_DEADLINE))
                    .await
                    .map_err(|e| e.to_string())??;
                let block = bundle::log_block(&read, None, redactor.as_ref());
                match (&redactor, unreadable) {
                    (Some(_), Some(e)) => format!(
                        "The recording couldn't be read ({e}); only names the log labels as SSIDs or quotes are masked.\n{block}"
                    ),
                    (Some(_), None) if sweeps.is_empty() => format!(
                        "No recorded SSIDs to learn from; only names the log labels as SSIDs or quotes are masked.\n{block}"
                    ),
                    _ => block,
                }
            }
            "get_bundle" => {
                let Ok(_one_at_a_time) = self.reading.try_lock() else {
                    return Err("an OS log read is already running; try again shortly".into());
                };
                let (log, salt) = (self.log.clone(), self.salt.clone());
                let redact = redacting(args);
                tokio::task::spawn_blocking(move || {
                    let log = |from, to, deadline| log(from, to, deadline);
                    bundle::build(&records, &sweeps, since, redact.then_some(&salt), &log)
                })
                .await
                .map_err(|e| e.to_string())?
            }
            _ => return Err(format!("unknown tool: {name}")),
        })
    }
}

fn redacting(args: &Value) -> bool {
    args["redact"].as_bool().unwrap_or(true)
}

fn since(args: &Value) -> Result<Duration, String> {
    crate::cli::parse_duration(args["since"].as_str().unwrap_or("24h"))
}

/// `to_ts` defaults to now, `from_ts` to `since` before `to_ts`.
fn range(args: &Value, window: u64, now: u64) -> Result<(u64, u64), String> {
    let to = args["to_ts"].as_u64().unwrap_or(now);
    let from = args["from_ts"]
        .as_u64()
        .unwrap_or(to.saturating_sub(window));
    if from > to {
        return Err("from_ts is after to_ts".into());
    }
    Ok((from, to))
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

fn tools() -> Value {
    let since = json!({ "type": "string", "description": "How far back to look: 90s, 30m, 2h, 1d. Default 24h." });
    let redact = json!({ "type": "boolean", "description": "Mask SSIDs, public IPs and MACs. Default true." });
    let from = json!({ "type": "integer", "description": "Unix seconds. Defaults to the start of `since`." });
    let to = json!({ "type": "integer", "description": "Unix seconds. Defaults to now." });
    json!([
        {
            "name": "list_episodes",
            "description": "Outage and degradation episodes (runs of unhealthy sweeps) and spans where the recorder wasn't running.",
            "inputSchema": { "type": "object", "properties": { "since": since, "redact": redact } },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_timeline",
            "description": "Every recorded sweep as one small record: status, first broken hop, headline, gateway and internet RTT, loss, RSSI.",
            "inputSchema": { "type": "object", "properties": { "since": since, "redact": redact } },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_sweeps",
            "description": "Full per-hop sweeps kept around each change of state, newest 20 in the range.",
            "inputSchema": { "type": "object", "properties": { "since": since, "from_ts": from, "to_ts": to, "redact": redact } },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_os_log",
            "description": "Wi-Fi, DHCP, interface and DNS events from the OS log (log show on macOS, journalctl on Linux). Covers `since` (or 15 minutes) before to_ts; at most 2h per call.",
            "inputSchema": { "type": "object", "properties": { "since": since, "from_ts": from, "to_ts": to, "redact": redact } },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "get_bundle",
            "description": "The same Markdown report `wtfi --bundle` prints: episodes, gaps, latency, timeline, sweeps and OS log.",
            "inputSchema": { "type": "object", "properties": { "since": since, "redact": redact } },
            "annotations": { "readOnlyHint": true },
        },
        {
            "name": "diagnose_now",
            "description": "Probe the network right now and return the full diagnosis. Takes up to 20 seconds; one at a time.",
            "inputSchema": { "type": "object", "properties": { "redact": redact } },
            "annotations": { "readOnlyHint": true, "openWorldHint": true },
        },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::{Log, Record};
    use crate::platform::{LogLine, LogRead};

    fn log(from: u64, to: u64, _: Duration) -> Result<LogRead, String> {
        Ok(LogRead {
            lines: vec![LogLine {
                ts: 0,
                source: "configd".into(),
                message: format!(
                    "window {from}-{to} SSID 'Cafe' BSSID 00:11:22:33:44:55 via 93.184.215.14"
                ),
            }],
            ..Default::default()
        })
    }

    fn server(name: &str) -> Server {
        let dir = std::env::temp_dir().join(format!("wtfi-mcp-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let file = dir.join("history.jsonl");
        let mut l = Log::open(file.clone());
        for (ts, status) in [(1000, "ok"), (1010, "fail"), (1020, "ok")] {
            let r = Record {
                ts,
                status: status.into(),
                first_break: (status == "fail").then(|| "dns".into()),
                headline: format!("{status}!"),
                gateway_ms: None,
                wan_ms: None,
                wan_loss_pct: None,
                rssi_dbm: None,
                interval_s: None,
                partial: false,
            };
            let sweep = json!({ "path": [
                { "id": "link", "subtitle": "Cafe", "metrics": [{ "label": "BSSID", "value": "00:11:22:33:44:55" }] },
                { "id": "wan", "metrics": [{ "label": "Public IP", "value": "198.51.100.7" }] }
            ] });
            l.push(&r, sweep).unwrap();
        }
        Server {
            history: Some(file),
            log: Arc::new(log),
            now: Some(1030),
            salt: RandomState::new(),
            sweeping: Default::default(),
            reading: Default::default(),
        }
    }

    fn none_server() -> Server {
        Server {
            history: None,
            log: Arc::new(log),
            now: Some(0),
            salt: RandomState::new(),
            sweeping: Default::default(),
            reading: Default::default(),
        }
    }

    #[tokio::test]
    async fn an_unreadable_recording_is_named_not_treated_as_empty() {
        let mut s = server("unreadable");
        let file = s.history.clone().unwrap();
        let sweeps = file.with_file_name("sweeps.jsonl");
        std::fs::remove_file(&sweeps).unwrap();
        std::fs::create_dir(&sweeps).unwrap();
        s.now = Some(1030);
        let r = call(&s, "get_os_log", json!({ "from_ts": 1000, "to_ts": 1010 })).await;
        assert!(text(&r).contains("couldn't be read"), "{}", text(&r));
    }

    #[tokio::test]
    async fn a_second_log_read_is_refused_not_queued() {
        let s = none_server();
        let _held = s.reading.try_lock().unwrap();
        let r = call(&s, "get_os_log", json!({})).await;
        assert!(text(&r).contains("already running"), "{}", text(&r));
    }

    #[tokio::test]
    async fn a_second_live_sweep_is_refused_not_queued() {
        let s = none_server();
        let _held = s.sweeping.try_lock().unwrap();
        let r = call(&s, "diagnose_now", json!({})).await;
        assert_eq!(r["isError"], true);
        assert!(text(&r).contains("already running"));
    }

    async fn call(s: &Server, name: &str, args: Value) -> Value {
        let req = json!({ "jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": { "name": name, "arguments": args } });
        s.handle(&req).await.unwrap()["result"].clone()
    }

    fn text(result: &Value) -> &str {
        result["content"][0]["text"].as_str().unwrap()
    }

    #[tokio::test]
    async fn initialize_agrees_on_a_version() {
        let s = server("init");
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18" } });
        let r = s.handle(&req).await.unwrap();
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2025-06-18");
        assert!(r["result"]["capabilities"]["tools"].is_object());
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "initialize", "params": { "protocolVersion": "1999-01-01" } });
        assert_eq!(
            s.handle(&req).await.unwrap()["result"]["protocolVersion"],
            PROTOCOLS[0]
        );
    }

    #[tokio::test]
    async fn notifications_get_no_reply_and_unknown_methods_an_error() {
        let s = server("notify");
        let n = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert_eq!(s.handle(&n).await, None);
        let r = s
            .handle(&json!({ "jsonrpc": "2.0", "id": 3, "method": "nope" }))
            .await
            .unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn every_listed_tool_has_a_schema() {
        let s = server("list");
        let r = s
            .handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/list" }))
            .await
            .unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 6);
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object", "{}", t["name"]);
        }
    }

    #[tokio::test]
    async fn episodes_and_sweeps_come_from_the_history() {
        let s = server("episodes");
        let eps: Value =
            serde_json::from_str(text(&call(&s, "list_episodes", json!({})).await)).unwrap();
        assert_eq!(eps["sweeps"], 3);
        assert_eq!(eps["episodes"][0]["start_ts"], 1010);
        assert_eq!(eps["episodes"][0]["end_ts"], 1020);

        let r = call(&s, "get_sweeps", json!({ "from_ts": 1005, "to_ts": 1015 })).await;
        let sweeps: Value = serde_json::from_str(text(&r)).unwrap();
        assert_eq!(sweeps["sweeps"].as_array().unwrap().len(), 1);
        assert!(!text(&r).contains("198.51.100.7") && text(&r).contains("198.51.100.x"));
        let raw = call(&s, "get_sweeps", json!({ "redact": false })).await;
        assert!(text(&raw).contains("198.51.100.7"));
    }

    #[tokio::test]
    async fn os_log_and_bundle_use_the_reader() {
        let s = server("oslog");
        let r = call(&s, "get_os_log", json!({ "from_ts": 1000, "to_ts": 1010 })).await;
        assert!(
            text(&r).contains("configd: window 1000-1010"),
            "{}",
            text(&r)
        );
        let r = call(&s, "get_os_log", json!({})).await;
        assert!(
            text(&r).contains("window 130-1030"),
            "15 minutes by default"
        );
        let b = call(&s, "get_bundle", json!({})).await;
        assert!(text(&b).starts_with("# wtfi network report"));
    }

    #[tokio::test]
    async fn every_tool_masks_the_same_way() {
        let s = server("masks");
        let log = text(&call(&s, "get_os_log", json!({ "from_ts": 1000, "to_ts": 1010 })).await)
            .to_string();
        let sweeps = text(&call(&s, "get_sweeps", json!({})).await).to_string();
        for leak in ["Cafe", "00:11:22", "93.184.215.14", "198.51.100.7"] {
            assert!(
                !log.contains(leak) && !sweeps.contains(leak),
                "{leak}: {log} {sweeps}"
            );
        }
        let tag = |t: &str, p: &str| t.split(p).nth(1).unwrap()[..4].to_string();
        assert_eq!(tag(&log, "ssid-"), tag(&sweeps, "ssid-"));
        assert_eq!(tag(&log, "mac-"), tag(&sweeps, "mac-"));
        let raw = call(
            &s,
            "get_os_log",
            json!({ "from_ts": 1000, "to_ts": 1010, "redact": false }),
        )
        .await;
        assert!(text(&raw).contains("'Cafe'"));
    }

    #[tokio::test]
    async fn to_ts_alone_reads_back_from_there() {
        let mut s = server("to-only");
        s.now = Some(1030 + 7 * 86_400);
        let r = call(&s, "get_sweeps", json!({ "to_ts": 1015 })).await;
        assert_ne!(r["isError"], true, "{r}");
        let v: Value = serde_json::from_str(text(&r)).unwrap();
        assert_eq!(v["sweeps"].as_array().unwrap().len(), 2, "{v}");
        let r = call(&s, "get_os_log", json!({ "to_ts": 1015 })).await;
        assert!(text(&r).contains("window 115-1015"), "{}", text(&r));
    }

    #[tokio::test]
    async fn get_os_log_honours_since() {
        let mut s = server("os-since");
        s.now = Some(100_000);
        let r = call(&s, "get_os_log", json!({ "since": "30m" })).await;
        assert!(text(&r).contains("window 98200-100000"), "{}", text(&r));
        let r = call(&s, "get_os_log", json!({ "since": "1d" })).await;
        assert_eq!(r["isError"], true);
    }

    #[tokio::test]
    async fn an_explicit_range_reaches_past_the_default_window() {
        let mut s = server("range");
        s.now = Some(1030 + 3 * 86_400);
        let r = call(&s, "get_sweeps", json!({ "from_ts": 1005, "to_ts": 1015 })).await;
        let v: Value = serde_json::from_str(text(&r)).unwrap();
        assert_eq!(v["sweeps"].as_array().unwrap().len(), 1, "{v}");
        let r = call(&s, "get_os_log", json!({ "from_ts": 0, "to_ts": 86_400 })).await;
        assert_eq!(r["isError"], true, "a day of log is refused");
    }

    #[tokio::test]
    async fn a_slow_log_read_doesnt_hold_up_other_requests() {
        let mut s = server("slow");
        s.log = Arc::new(|_, _, _| {
            std::thread::sleep(Duration::from_millis(800));
            Ok(LogRead::default())
        });
        let start = std::time::Instant::now();
        let ping = async {
            s.handle(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }))
                .await;
            start.elapsed()
        };
        let (_, pinged) = tokio::join!(call(&s, "get_os_log", json!({})), ping);
        assert!(
            pinged < Duration::from_millis(400),
            "ping waited {pinged:?}"
        );
    }

    #[tokio::test]
    async fn responses_and_batches_are_not_mistaken_for_requests() {
        let s = server("rpc");
        assert_eq!(
            s.handle(&json!({ "jsonrpc": "2.0", "id": 5, "result": {} }))
                .await,
            None
        );
        let r = s
            .handle(&json!([{ "jsonrpc": "2.0", "id": 1, "method": "ping" }]))
            .await
            .unwrap();
        assert_eq!(r["error"]["code"], -32600);
    }

    #[tokio::test]
    async fn bad_arguments_are_tool_errors_not_crashes() {
        let s = server("bad");
        let r = call(&s, "get_sweeps", json!({ "since": "soon" })).await;
        assert_eq!(r["isError"], true);
        let r = call(&s, "get_os_log", json!({ "from_ts": 9, "to_ts": 1 })).await;
        assert_eq!(r["isError"], true);
        let r = call(&s, "nope", json!({})).await;
        assert_eq!(r["isError"], true);
        let r = call(&none_server(), "get_os_log", json!({})).await;
        assert_ne!(r["isError"], true, "the OS log doesn't need a recording");
        assert!(
            !text(&r).contains("'Cafe'") && text(&r).contains("No recorded SSIDs"),
            "{}",
            text(&r)
        );
        let none = Server {
            history: None,
            log: Arc::new(log),
            now: Some(0),
            salt: RandomState::new(),
            sweeping: Default::default(),
            reading: Default::default(),
        };
        assert_eq!(
            call(&none, "list_episodes", json!({})).await["isError"],
            true
        );
    }
}
