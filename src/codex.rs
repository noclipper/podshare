//! The Codex CLI adapter. Sessions live in `~/.codex/sessions/YYYY/MM/DD/rollout-<time>-<id>.jsonl`.
//! Codex runs each tool call as a small script (`exec`); the real shell commands, the files
//! they read and the files they changed are logged as `item_completed` events between the
//! call and its output, which is what this adapter judges.

use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::filters::{Filter, Filters};
use crate::convert::Turn;
use crate::session::{
    blank_strings, home, rfc3339, normalize, replace_strings, under, url_path, withheld_note, Cleaned, Identity, Scrubber,
    Touch, ROOT, ROOT_URL,
};

/// This adapter's name in a pod's manifest.
pub const AGENT: &str = "codex";

/// Codex's own folder: `CODEX_HOME` if set, else `~/.codex`.
fn codex_dir() -> PathBuf {
    std::env::var_os("CODEX_HOME").filter(|d| !d.is_empty()).map(PathBuf::from).unwrap_or_else(|| home().join(".codex"))
}

fn sessions_dir() -> PathBuf {
    codex_dir().join("sessions")
}

fn rollouts(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.filter_map(|e| e.ok()) {
        let p = e.path();
        match e.file_type() {
            Ok(t) if t.is_dir() => rollouts(&p, out),
            Ok(t) if t.is_file() && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("rollout-")) => {
                out.push(p)
            }
            _ => {}
        }
    }
}

/// The session_meta payload on a session's first line.
fn meta(path: &Path) -> Option<Value> {
    // Only the first line: rollouts grow to hundreds of megabytes.
    let mut first = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(fs::File::open(path).ok()?), &mut first).ok()?;
    let line: Value = serde_json::from_str(&first).ok()?;
    (line["type"] == "session_meta").then(|| line["payload"].clone())
}

/// The session with `id`, or the most recent one started in `cwd`, with its last change.
pub fn find(cwd: &Path, id: Option<&str>) -> Result<(PathBuf, SystemTime)> {
    let modified = |p: &PathBuf| fs::metadata(p).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
    if let Some(id) = id {
        let mut all = vec![];
        rollouts(&sessions_dir(), &mut all);
        let path = all.into_iter().find(|p| p.to_string_lossy().ends_with(&format!("-{id}.jsonl")));
        let path = path.with_context(|| format!("no Codex session with id {id}"))?;
        let at = modified(&path);
        return Ok((path, at));
    }
    list(cwd).into_iter().max_by_key(|(_, at, _)| *at).map(|(p, at, _)| (p, at)).with_context(|| format!("no Codex sessions for {}", cwd.display()))
}

/// Every session started in `cwd`: its file, when it was last used, and its title (the
/// thread name Codex gave it, or else its first message).
pub fn list(cwd: &Path) -> Vec<(PathBuf, SystemTime, String)> {
    let mut all = vec![];
    rollouts(&sessions_dir(), &mut all);
    let here: Vec<PathBuf> = [Some(cwd.to_path_buf()), crate::session::canonical(cwd).ok()].into_iter().flatten().collect();
    let names: HashMap<String, String> = fs::read_to_string(codex_dir().join("session_index.jsonl"))
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|v| Some((v["id"].as_str()?.to_string(), v["thread_name"].as_str()?.to_string())))
        .collect();
    all.into_iter()
        .filter_map(|p| {
            let meta = meta(&p)?;
            let c = PathBuf::from(meta["cwd"].as_str()?);
            let ours = here.iter().any(|h| *h == c || crate::session::canonical(&c).ok().as_ref() == Some(h));
            if !ours {
                return None;
            }
            let at = fs::metadata(&p).and_then(|m| m.modified()).ok()?;
            let id = meta["id"].as_str().unwrap_or("");
            let title = names.get(id).cloned().or_else(|| first_message(&p)).unwrap_or_else(|| "(untitled)".into());
            Some((p, at, title))
        })
        .collect()
}

/// The first thing the user typed in a session, from its first few hundred lines.
fn first_message(path: &Path) -> Option<String> {
    use std::io::BufRead;
    let file = std::io::BufReader::new(fs::File::open(path).ok()?);
    file.lines().take(500).map_while(|l| l.ok()).find_map(|line| {
        let v: Value = serde_json::from_str(&line).ok()?;
        let p = &v["payload"];
        (p["type"] == "message" && p["role"] == "user")
            .then(|| p["content"][0]["text"].as_str().map(|t| crate::convert::strip_intro(t).to_string()))
            .flatten()
            .filter(|t| !t.is_empty() && !t.starts_with('<'))
    })
}

pub fn cwd(lines: &[Value]) -> Option<PathBuf> {
    lines.iter().find(|l| l["type"] == "session_meta").and_then(|l| l["payload"]["cwd"].as_str()).map(PathBuf::from)
}

pub fn version(lines: &[Value]) -> Option<&str> {
    lines.iter().find(|l| l["type"] == "session_meta").and_then(|l| l["payload"]["cli_version"].as_str())
}

/// A `file://` URL or plain path as a path.
fn as_path(s: &str) -> PathBuf {
    let s = s.strip_prefix("file://").unwrap_or(s);
    // file:///C:/… names a Windows drive: drop the slash before it.
    let s = match s.as_bytes() {
        [b'/', d, b':', ..] if d.is_ascii_alphabetic() => &s[1..],
        _ => s,
    };
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match (bytes[i], bytes.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok())) {
            (b'%', Some(b)) => {
                out.push(b);
                i += 3;
            }
            (b, _) => {
                out.push(b);
                i += 1;
            }
        }
    }
    PathBuf::from(String::from_utf8_lossy(&out).into_owned())
}

/// Files an apply_patch script adds, updates or deletes.
fn patched_files(script: &str) -> Vec<&str> {
    script
        .split(['\n', '"'])
        .flat_map(|l| l.split("\\n"))
        .filter_map(|l| {
            ["*** Update File: ", "*** Add File: ", "*** Delete File: "].iter().find_map(|h| l.trim().strip_prefix(h))
        })
        .map(str::trim)
        .collect()
}

/// Tools a Codex script may call whose effects the logged events describe.
const KNOWN_SCRIPT_TOOLS: &[&str] = &["exec_command", "apply_patch", "write_stdin"];

fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|x| strings(x, out)),
        Value::Object(map) => map.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

fn is_call(p: &Value) -> bool {
    matches!(p["type"].as_str(), Some("custom_tool_call" | "function_call" | "local_shell_call" | "web_search_call"))
}

fn is_output(p: &Value) -> bool {
    matches!(p["type"].as_str(), Some("custom_tool_call_output" | "function_call_output"))
}

/// For each line, the tool call it belongs to: the call itself, the events logged while it
/// ran, and its output.
fn call_of_each_line(lines: &[Value]) -> Vec<Option<String>> {
    let mut current: Option<String> = None;
    lines
        .iter()
        .map(|l| {
            let p = &l["payload"];
            match l["type"].as_str() {
                Some("response_item") if is_call(p) => {
                    current = p["call_id"].as_str().or(p["id"].as_str()).map(String::from);
                    current.clone()
                }
                Some("response_item") if is_output(p) => {
                    let id = p["call_id"].as_str().map(String::from);
                    current = None;
                    id
                }
                Some("event_msg") if p["type"] == "item_completed" => current.clone(),
                _ => None,
            }
        })
        .collect()
}

static PATCH_BODY: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?s)\*\*\* Begin Patch.*?(\*\*\* End Patch|$)").unwrap());

pub fn touched(lines: &[Value]) -> Vec<Touch<'_>> {
    let owner = call_of_each_line(lines);
    let mut outputs: HashMap<&str, Vec<&str>> = HashMap::new();
    for (l, id) in lines.iter().zip(&owner) {
        if let (Some(id), true) = (id, is_output(&l["payload"])) {
            strings(&l["payload"]["output"], outputs.entry(id.as_str()).or_default());
        }
    }
    let mut cwd = self::cwd(lines).unwrap_or_else(|| PathBuf::from("/"));
    let mut out = vec![];
    let touch = |id: &str, tool, cwd: &Path, file, inputs, outputs, opaque| Touch {
        id: id.to_string(),
        tool,
        attachment: false,
        cwd: cwd.to_path_buf(),
        file,
        inputs,
        outputs,
        opaque,
    };
    for (l, id) in lines.iter().zip(&owner) {
        let p = &l["payload"];
        if l["type"] == "turn_context" {
            if let Some(c) = p["cwd"].as_str() {
                cwd = as_path(c);
            }
        }
        let Some(id) = id.as_deref() else { continue };
        if l["type"] == "response_item" && is_call(p) {
            // The script itself, and what came back.
            let name = p["name"].as_str().unwrap_or(p["type"].as_str().unwrap_or("tool"));
            let mut inputs = vec![];
            strings(&p["input"], &mut inputs);
            strings(&p["arguments"], &mut inputs);
            strings(&p["action"], &mut inputs);
            let script = inputs.join("\n");
            let unknown = script.contains("tools.")
                && script.split("tools.").skip(1).any(|t| !KNOWN_SCRIPT_TOOLS.iter().any(|k| t.starts_with(k)));
            let tool = if name.starts_with("mcp") || name.contains("__") { "mcp__codex" } else { name };
            for f in patched_files(&script) {
                out.push(touch(id, "Edit", &cwd, Some(cwd.join(f)), vec![], vec![], false));
            }
            // Patches are judged by the files they change. Their body is code, and paths in it
            // (like an import's "../src/x.js") aren't places the agent went.
            let inputs = inputs.into_iter().flat_map(|i| PATCH_BODY.split(i)).collect();
            out.push(touch(id, tool, &cwd, None, inputs, outputs.remove(id).unwrap_or_default(), unknown));
        } else if l["type"] == "event_msg" {
            let item = &p["item"];
            let here = item["cwd"].as_str().map(as_path).unwrap_or_else(|| cwd.clone());
            match item["type"].as_str() {
                Some("CommandExecution") => {
                    let cmd = item["command"].as_array().and_then(|c| c.last()).and_then(Value::as_str).unwrap_or("");
                    let mut output = vec![];
                    strings(&item["aggregated_output"], &mut output);
                    out.push(touch(id, "Bash", &here, None, vec![cmd], output, false));
                    for read in item["parsed_cmd"].as_array().into_iter().flatten().filter(|r| r["type"] == "read") {
                        if let Some(path) = read["path"].as_str() {
                            out.push(touch(id, "Read", &here, Some(here.join(path)), vec![], vec![], false));
                        }
                    }
                }
                Some("FileChange") => {
                    for path in item["changes"].as_object().into_iter().flat_map(|c| c.keys()) {
                        out.push(touch(id, "Edit", &here, Some(here.join(path)), vec![], vec![], false));
                    }
                }
                _ => {}
            }
        }
    }
    out
}

/// Lines that hold usage, rate limits or the sender's full permission state.
const DROPPED: &[&str] = &["token_usage_record", "world_state"];
const DROPPED_EVENTS: &[&str] = &["token_count"];
/// Fields that record the sender's account or permissions.
const PRIVATE_FIELDS: &[&str] = &[
    "creator_user_id",
    "creator_account_id",
    "approval_policy",
    "approvals_reviewer",
    "sandbox_policy",
    "permission_profile",
    "permissions",
    // The sender's system prompt: the receiver's Codex supplies its own, and a pod could forge one.
    "base_instructions",
];

/// Display records podshare understands: conversation text, commands and file changes.
const KNOWN_ITEMS: &[&str] = &["UserMessage", "AgentMessage", "CommandExecution", "FileChange"];

/// Developer messages carry the sender's setup (skills, permissions) and act as strong
/// instructions, so neither side keeps them; the receiver's Codex adds its own.
fn developer_message(line: &Value) -> bool {
    line["type"] == "response_item" && line["payload"]["type"] == "message" && line["payload"]["role"] == "developer"
}

fn strip_private(line: &mut Value) {
    if let Some(p) = line.get_mut("payload").and_then(Value::as_object_mut) {
        for f in PRIVATE_FIELDS {
            p.remove(*f);
        }
    }
}

/// A copy of the transcript with reasoning and `withhold`'s tool calls removed, whatever
/// `filters` ask for cleaned, and the project path made portable.
pub fn clean(
    lines: Vec<Value>,
    withhold: &HashMap<String, String>,
    root: &Path,
    home: &Path,
    identity: &Identity,
    echoes: &[String],
    filters: &Filters,
) -> Cleaned {
    let owner = call_of_each_line(&lines);
    let calls: std::collections::HashSet<String> = lines
        .iter()
        .filter(|l| l["type"] == "response_item" && is_call(&l["payload"]))
        .filter_map(|l| l["payload"]["call_id"].as_str().or(l["payload"]["id"].as_str()).map(String::from))
        .collect();
    let scrubber = Scrubber::new(root, home, identity, echoes, filters);
    let images = filters.on(Filter::PastedImages);
    let mut c = Cleaned::default();
    for (mut line, id) in lines.into_iter().zip(owner) {
        let ty = line["type"].as_str().unwrap_or("").to_string();
        let sub = line["payload"]["type"].as_str().unwrap_or("").to_string();
        let (ty, sub) = (ty.as_str(), sub.as_str());
        if DROPPED.contains(&ty) || (ty == "event_msg" && DROPPED_EVENTS.contains(&sub)) {
            continue;
        }
        if ty == "response_item" && sub == "reasoning" {
            c.thinking += 1;
            continue;
        }
        if developer_message(&line) {
            continue;
        }
        strip_private(&mut line);
        // Default deny: tool output podshare can't tie to a checked call, and records it
        // doesn't recognise, are withheld whatever they contain.
        let item_type = line["payload"]["item"]["type"].as_str().unwrap_or("").to_string();
        let untraced = match (ty, sub) {
            ("event_msg", "item_completed") => {
                !KNOWN_ITEMS.contains(&item_type.as_str())
                    || (id.is_none() && !matches!(item_type.as_str(), "UserMessage" | "AgentMessage"))
            }
            ("response_item", _) if is_output(&line["payload"]) => id.as_deref().is_none_or(|i| !calls.contains(i)),
            _ => false,
        };
        let untraced_reason = "a tool record podshare can't trace to a checked call".to_string();
        let why = if untraced { Some(&untraced_reason) } else { id.as_deref().and_then(|id| withhold.get(id)) };
        if let Some(why) = why {
            let note = withheld_note(why);
            let p = &mut line["payload"];
            if ty == "response_item" && is_output(p) {
                p["output"] = json!([{ "type": "input_text", "text": note }]);
                c.withheld += 1;
            } else if ty == "response_item" {
                for key in ["input", "arguments", "action"] {
                    if let Some(v) = p.get_mut(key) {
                        blank_strings(v, &note);
                    }
                }
            } else {
                blank_strings(&mut p["item"], &note);
            }
        }
        if images && ty == "response_item" && sub == "message" {
            for part in line["payload"]["content"].as_array_mut().into_iter().flatten() {
                if part["type"] == "input_image" {
                    *part = json!({ "type": "input_text", "text": "[pasted image removed by podshare]" });
                    c.images += 1;
                }
            }
        }
        scrubber.scrub(&mut line, &mut c);
        c.lines.push(line);
    }
    c
}

fn text_of(content: &Value) -> String {
    let mut parts = vec![];
    strings(content, &mut parts);
    parts.retain(|p| !p.starts_with("input_") && !p.starts_with("output_"));
    parts.join("\n")
}

/// The neutral form of a cleaned transcript (docs/format.md). Tool calls are described by
/// the commands and file changes Codex logged, not by the script that made them.
pub fn to_neutral(lines: &[Value]) -> Vec<Value> {
    let owner = call_of_each_line(lines);
    let mut described: std::collections::HashSet<&str> = Default::default();
    let mut out = vec![];
    // After a compaction the agent only sees its summary and what follows.
    let start = lines.iter().rposition(|l| l["type"] == "compacted").unwrap_or(0);
    for (l, id) in lines.iter().zip(&owner).skip(start) {
        let p = &l["payload"];
        match (l["type"].as_str(), p["type"].as_str()) {
            (Some("compacted"), _) => {
                if let Some(text) = p["message"].as_str().filter(|t| !t.is_empty()) {
                    out.push(json!({ "type": "summary", "text": text }));
                }
            }
            (Some("response_item"), Some("message")) => {
                let role = p["role"].as_str().unwrap_or("");
                let text: Vec<&str> = p["content"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|c| c["text"].as_str())
                    .filter(|t| !t.starts_with("<environment_context>"))
                    .collect();
                if matches!(role, "user" | "assistant") && !text.is_empty() {
                    out.push(json!({ "role": role, "type": "text", "text": text.join("\n") }));
                }
            }
            (Some("event_msg"), Some("item_completed")) => {
                let item = &p["item"];
                let call = id.as_deref().unwrap_or("");
                let (tool, input, result) = match item["type"].as_str() {
                    Some("CommandExecution") => {
                        let cmd = item["command"].as_array().and_then(|c| c.last()).cloned().unwrap_or_default();
                        ("shell", json!({ "command": cmd }), text_of(&item["aggregated_output"]))
                    }
                    Some("FileChange") => {
                        let files: Vec<&String> = item["changes"].as_object().map(|c| c.keys().collect()).unwrap_or_default();
                        ("edit_file", json!({ "files": files }), String::new())
                    }
                    _ => continue,
                };
                described.insert(call);
                out.push(json!({ "role": "assistant", "type": "tool_call", "id": call, "tool": tool, "name": tool, "input": input }));
                out.push(json!({ "role": "tool", "type": "tool_result", "id": call, "content": result, "is_error": false }));
            }
            (Some("response_item"), _) if is_output(p) => {
                // A call Codex logged no commands or changes for: describe the call itself.
                let call = p["call_id"].as_str().unwrap_or("");
                if !described.contains(call) {
                    out.push(json!({ "role": "assistant", "type": "tool_call", "id": call, "tool": "other", "name": "exec", "input": {} }));
                    out.push(json!({ "role": "tool", "type": "tool_result", "id": call, "content": text_of(&p["output"]), "is_error": false }));
                }
            }
            _ => {}
        }
    }
    out
}

/// Roughly how many tokens Codex reads when it resumes this cleaned transcript: the
/// records the model sees (not the display events), from the last compaction on.
/// MCP servers the chat called (or tried to): `McpToolCall` items, and the older
/// `mcp_tool_call_*` events.
pub fn mcp_servers(lines: &[Value]) -> Vec<String> {
    lines
        .iter()
        .filter(|l| l["type"] == "event_msg")
        .filter_map(|l| {
            let p = &l["payload"];
            match p["type"].as_str() {
                Some("item_completed") if p["item"]["type"] == "McpToolCall" => p["item"]["server"].as_str(),
                Some(t) if t.starts_with("mcp_tool_call") => p["invocation"]["server"].as_str(),
                _ => None,
            }
        })
        .map(String::from)
        .collect()
}

pub fn estimate_tokens(lines: &[Value]) -> usize {
    let start = lines.iter().rposition(|l| l["type"] == "compacted").unwrap_or(0);
    let mut images = 0;
    let chars: usize = lines[start..]
        .iter()
        .filter(|l| matches!(l["type"].as_str(), Some("response_item" | "compacted")))
        .map(|l| crate::session::model_chars(&l["payload"], &mut images))
        .sum();
    text_tokens(chars) + images * IMAGE_TOKENS
}

/// Tokens for `chars` characters of session text. Measured against the counts Codex
/// reported for a real resumed session: about 3.3 characters per token.
pub fn text_tokens(chars: usize) -> usize {
    chars * 10 / 33
}

/// A typical image's cost to Codex's models.
const IMAGE_TOKENS: usize = 1_000;

/// Entry types `podshare open` keeps; a pod could carry anything, so the rest is dropped.
const ACCEPTED: &[&str] = &["session_meta", "response_item", "event_msg", "turn_context", "compacted"];

/// A received transcript made ready to resume in `dir` under a fresh id, with the resume
/// note added as a developer message. Returns the id and the transcript.
pub fn prepare(transcript: &[u8], dir: &Path, note: &str) -> Result<(String, String)> {
    let dir_str = dir.to_string_lossy().into_owned();
    let id = uuid::Uuid::now_v7().to_string();
    let mut old_id = None;
    let mut lines = vec![];
    for line in std::str::from_utf8(transcript).context("transcript is not text")?.lines() {
        let mut v: Value = serde_json::from_str(line).context("transcript line is not JSON")?;
        if !ACCEPTED.contains(&v["type"].as_str().unwrap_or("")) || developer_message(&v) {
            continue;
        }
        strip_private(&mut v);
        if v["type"] == "session_meta" {
            old_id = v["payload"]["id"].as_str().map(String::from);
        }
        lines.push(v);
    }
    let old_id = old_id.context("the pod's Codex transcript has no session_meta")?;
    let mut out = String::new();
    let mut ordinal = 0;
    for mut v in lines {
        // Inside file:// URLs the folder must be percent-encoded, whichever way it was written.
        replace_strings(&mut v, &format!("file://{ROOT}"), &format!("file://{}", url_path(&dir_str)));
        replace_strings(&mut v, ROOT_URL, &url_path(&dir_str));
        replace_strings(&mut v, ROOT, &dir_str);
        replace_strings(&mut v, &old_id, &id);
        // The agent works in the unpacked folder, wherever the sender says it was.
        let p = &mut v["payload"];
        if p["cwd"].as_str().is_some_and(|c| !under(&normalize(&as_path(c)), dir)) {
            p["cwd"] = dir_str.clone().into();
        }
        for roots in ["workspace_roots", "runtime_workspace_roots"] {
            if p.get(roots).is_some() {
                p[roots] = json!([dir_str]);
            }
        }
        ordinal = v["ordinal"].as_u64().unwrap_or(ordinal);
        out += &(v.to_string() + "\n");
    }
    let now = rfc3339(SystemTime::now());
    out += &(json!({ "timestamp": now, "ordinal": ordinal + 1, "type": "response_item",
        "payload": { "type": "message", "role": "developer", "content": [{ "type": "input_text", "text": note }] } })
    .to_string()
        + "\n");
    Ok((id, out))
}

/// Puts a prepared transcript where Codex looks for sessions.
pub fn install(_dir: &Path, id: &str, transcript: &str) -> Result<()> {
    let now = rfc3339(SystemTime::now());
    let (date, time) = (&now[..10], now[11..19].replace(':', "-"));
    let folder = date.split('-').fold(sessions_dir(), |dir, part| dir.join(part));
    fs::create_dir_all(&folder)?;
    Ok(fs::write(folder.join(format!("rollout-{date}T{time}-{id}.jsonl")), transcript)?)
}

/// A Codex session holding `turns`, in `dir`, with `note` as a developer message. It
/// mirrors what Codex itself writes: every record numbered, each exchange wrapped as a turn,
/// and the display events Codex's screen shows history from.
pub fn from_turns(turns: &[Turn], dir: &Path, note: &str) -> (String, String) {
    let id = uuid::Uuid::now_v7().to_string();
    let now = rfc3339(SystemTime::now());
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let cwd = dir.to_string_lossy();
    let mut lines = vec![json!({ "type": "session_meta", "payload": {
        "id": id, "session_id": id, "timestamp": now, "cwd": cwd, "runtime_workspace_roots": [cwd],
        "originator": "codex_exec", "cli_version": "0.0.0", "source": "exec", "thread_source": "user",
        "history_mode": "paginated", "model_provider": "openai" } })];
    let mut turn: Option<String> = None;
    let mut last_agent = String::new();
    let end = |turn: &str, last: &str| json!({ "type": "event_msg", "payload": { "type": "task_complete", "turn_id": turn,
        "last_agent_message": last, "started_at": secs, "completed_at": secs, "duration_ms": 0, "time_to_first_token_ms": 0 } });
    for t in turns {
        if t.user {
            if let Some(done) = turn.take() {
                lines.push(end(&done, &last_agent));
            }
            let started = uuid::Uuid::now_v7().to_string();
            lines.push(json!({ "type": "event_msg", "payload": { "type": "task_started", "turn_id": started,
                "root_turn_id": started, "started_at": secs, "model_context_window": 258_400, "collaboration_mode_kind": "default" } }));
            turn = Some(started);
        }
        let turn_id = turn.clone().unwrap_or_default();
        let (role, kind) = if t.user { ("user", "input_text") } else { ("assistant", "output_text") };
        lines.push(json!({ "type": "response_item", "payload": { "type": "message", "role": role,
            "content": [{ "type": kind, "text": t.text }], "internal_chat_message_metadata_passthrough": { "turn_id": turn_id } } }));
        let item = if t.user {
            json!({ "type": "UserMessage", "id": uuid::Uuid::now_v7().to_string(),
                "content": [{ "type": "text", "text": t.text, "text_elements": [] }] })
        } else {
            last_agent = t.text.clone();
            json!({ "type": "AgentMessage", "id": uuid::Uuid::now_v7().to_string(),
                "content": [{ "type": "Text", "text": t.text }], "phase": "final_answer" })
        };
        lines.push(json!({ "type": "event_msg", "payload": { "type": "item_completed", "thread_id": id, "turn_id": turn_id,
            "item": item, "started_at_ms": secs * 1000, "completed_at_ms": secs * 1000 } }));
    }
    lines.push(json!({ "type": "response_item", "payload": { "type": "message", "role": "developer",
        "content": [{ "type": "input_text", "text": note }] } }));
    if let Some(done) = turn {
        lines.push(end(&done, &last_agent));
    }
    let transcript = lines
        .into_iter()
        .enumerate()
        .map(|(ordinal, mut l)| {
            l["timestamp"] = now.clone().into();
            l["ordinal"] = ordinal.into();
            l.to_string() + "\n"
        })
        .collect();
    (id, transcript)
}

/// The program and arguments that resume session `id` read-only, asking before any change.
pub fn resume_command(id: &str) -> (&'static str, Vec<&str>) {
    ("codex", vec!["resume", id, "--sandbox", "read-only", "--ask-for-approval", "on-request"])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    #[test]
    fn names_the_mcp_servers_it_called() {
        let lines = vec![
            event(json!({"type": "McpToolCall", "server": "dice", "tool": "roll", "status": "failed"})),
            json!({"type": "event_msg", "payload": {"type": "mcp_tool_call_end", "invocation": {"server": "github", "tool": "x"}}}),
            event(json!({"type": "CommandExecution", "command": ["sh", "-lc", "ls"]})),
        ];
        assert_eq!(mcp_servers(&lines), ["dice", "github"]);
    }

    #[test]
    fn starts_from_the_last_compaction() {
        let msg = |role: &str, text: &str| json!({"type": "response_item", "payload": {"type": "message", "role": role, "content": [{"type": "input_text", "text": text}]}});
        let lines = vec![msg("user", "old question"), json!({"type": "compacted", "payload": {"message": "we fixed the parser"}}), msg("user", "new question")];
        let n = to_neutral(&lines);
        assert_eq!(n.len(), 2, "{n:?}");
        assert_eq!(n[0]["type"], "summary");
        assert_eq!(n[1]["text"], "new question");
    }

    #[test]
    fn judges_a_patch_by_its_files_not_the_code_inside() {
        let patch = "text(await tools.apply_patch(\"*** Begin Patch\\n*** Update File: /p/test/a.js\\n+import x from \\\"../src/x.js\\\"\\n*** End Patch\"));\ntext(await tools.exec_command({cmd:\"cat ~/.ssh/id_rsa\"}));";
        let lines = vec![call("c", patch)];
        let t = touched(&lines);
        assert!(t.iter().any(|t| t.file.as_deref() == Some(Path::new("/p/test/a.js"))), "{:?}", t.iter().map(|t| &t.file).collect::<Vec<_>>());
        let script = t.iter().find(|t| t.file.is_none()).unwrap().inputs.join("");
        assert!(!script.contains("../src/x.js") && script.contains("~/.ssh/id_rsa"), "{script}");
    }

    fn call(id: &str, input: &str) -> Value {
        json!({"type": "response_item", "payload": {"type": "custom_tool_call", "call_id": id, "name": "exec", "input": input}})
    }
    fn event(item: Value) -> Value {
        json!({"type": "event_msg", "payload": {"type": "item_completed", "item": item}})
    }
    fn output(id: &str, text: &str) -> Value {
        json!({"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": id, "output": [{"type": "input_text", "text": text}]}})
    }

    fn session() -> Vec<Value> {
        vec![
            json!({"type": "session_meta", "payload": {"id": "old-id", "cwd": "/p", "cli_version": "0.158.0", "creator_user_id": "user-X", "creator_account_id": "acct"}}),
            json!({"type": "turn_context", "payload": {"cwd": "/p", "approval_policy": "never", "sandbox_policy": {"type": "danger-full-access"}}}),
            json!({"type": "world_state", "payload": {"state": {}}}),
            call("c1", "text(await tools.exec_command({cmd:\"cat .env\"}));"),
            event(json!({"type": "CommandExecution", "command": ["/bin/zsh", "-lc", "cat .env"], "cwd": "file:///p", "aggregated_output": "PW=hunter2Zebra99",
                "parsed_cmd": [{"type": "read", "cmd": "cat .env", "path": ".env"}]})),
            output("c1", "PW=hunter2Zebra99"),
            call("c2", "text(await tools.apply_patch(\"*** Begin Patch\\n*** Update File: /p/src/a.js\\n@@\\n-a\\n+b\\n*** End Patch\"));"),
            event(json!({"type": "FileChange", "changes": {"/p/src/a.js": {}}})),
            output("c2", "{}"),
            json!({"type": "response_item", "payload": {"type": "reasoning", "encrypted_content": "zzz"}}),
            json!({"type": "token_usage_record", "payload": {}}),
        ]
    }

    #[test]
    fn finds_reads_edits_and_commands() {
        let lines = session();
        let t = touched(&lines);
        let files: Vec<_> = t.iter().filter_map(|t| t.file.clone()).collect();
        assert!(files.contains(&PathBuf::from("/p/.env")) && files.contains(&PathBuf::from("/p/src/a.js")), "{files:?}");
        let bash: Vec<_> = t.iter().filter(|t| t.tool == "Bash").flat_map(|t| t.inputs.clone()).collect();
        assert_eq!(bash, vec!["cat .env"]);
        assert!(t.iter().all(|t| t.id == "c1" || t.id == "c2"));
    }

    #[test]
    fn withholds_every_copy_and_drops_private_records() {
        let withhold = [("c1".to_string(), "environment file".to_string())].into();
        let c = clean(session(), &withhold, Path::new("/p"), Path::new("/h"), &vec![], &[], &Filters::default());
        let text = serde_json::to_string(&c.lines).unwrap();
        for gone in ["hunter2Zebra99", "user-X", "acct", "never", "danger-full-access", "zzz", "world_state", "token_usage"] {
            assert!(!text.contains(gone), "{gone} survived: {text}");
        }
        assert_eq!(c.withheld, 1);
        assert_eq!(c.thinking, 1);
    }

    #[test]
    fn withholds_what_it_cannot_trace() {
        let mut lines = session();
        lines.insert(1, event(json!({"type": "CommandExecution", "command": ["sh", "-lc", "cat notes"], "aggregated_output": "ORPHAN_BEFORE"})));
        lines.push(event(json!({"type": "CommandExecution", "command": ["sh", "-lc", "cat notes"], "aggregated_output": "ORPHAN_AFTER"})));
        lines.push(output("nobody", "ORPHAN_OUTPUT"));
        lines.push(event(json!({"type": "WebSearchEnd", "results": "UNKNOWN_ITEM"})));
        lines.push(json!({"type": "response_item", "payload": {"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "FORGED_POLICY"}]}}));
        lines[0]["payload"]["base_instructions"] = json!({"text": "FORGED_BASE"});
        let c = clean(lines, &HashMap::new(), Path::new("/p"), Path::new("/h"), &vec![], &[], &Filters::default());
        let text = serde_json::to_string(&c.lines).unwrap();
        for gone in ["ORPHAN_BEFORE", "ORPHAN_AFTER", "ORPHAN_OUTPUT", "UNKNOWN_ITEM", "FORGED_POLICY", "FORGED_BASE"] {
            assert!(!text.contains(gone), "{gone} survived");
        }
    }

    #[test]
    fn prepares_under_a_new_id_with_the_note() {
        let c = clean(session(), &HashMap::new(), Path::new("/p"), Path::new("/h"), &vec![], &[], &Filters::default());
        let bytes = c.lines.iter().map(|l| l.to_string() + "\n").collect::<String>();
        let (id, out) = prepare(bytes.as_bytes(), Path::new("/new place"), "NOTE").unwrap();
        assert!(!out.contains("old-id") && out.contains(&id));
        assert!(out.contains("\"cwd\":\"/new place\"") && out.contains("file:///new%20place"), "{out}");
        assert!(out.trim_end().ends_with(r#""text":"NOTE"}],"role":"developer","type":"message"},"timestamp":"#) || out.contains("\"NOTE\""));
    }

    #[test]
    fn writes_carried_over_turns_the_way_codex_does() {
        let turns = vec![
            Turn { user: true, text: "hi".into() },
            Turn { user: false, text: "hello".into() },
            Turn { user: true, text: "again".into() },
            Turn { user: false, text: "yes".into() },
        ];
        let (id, out) = from_turns(&turns, Path::new("/d"), "NOTE");
        let lines: Vec<Value> = out.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
        assert!(lines.iter().enumerate().all(|(i, l)| l["ordinal"] == i), "every record is numbered in order");
        assert_eq!(lines[0]["payload"]["session_id"], id.as_str());
        let kinds: Vec<&str> = lines.iter().filter_map(|l| l["payload"]["type"].as_str()).collect();
        assert_eq!(kinds.iter().filter(|k| **k == "task_started").count(), 2);
        assert_eq!(kinds.iter().filter(|k| **k == "task_complete").count(), 2);
        assert_eq!(kinds.iter().filter(|k| **k == "item_completed").count(), 4);
        assert!(out.contains("\"NOTE\""));
    }

    #[test]
    fn formats_utc_times() {
        assert_eq!(rfc3339(UNIX_EPOCH + std::time::Duration::from_millis(1_790_000_000_123)), "2026-09-21T14:13:20.123Z");
        assert_eq!(rfc3339(UNIX_EPOCH + std::time::Duration::from_millis(951_782_400_000)), "2000-02-29T00:00:00.000Z");
    }
}
