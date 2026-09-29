//! The Claude Code adapter: where its sessions live, how its transcript records tool
//! calls, and a cleaned copy of that transcript that is safe to hand to someone else.

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::filters::{Filter, Filters};
use crate::convert::Turn;
use crate::session::{blank_strings, rfc3339, home, normalize, replace_strings, under, withheld_note, Cleaned, Identity, Scrubber, Subagent, Touch, ROOT};

/// This adapter's name in a pod's manifest.
pub const AGENT: &str = "claude-code";

/// The Claude Code version that wrote the session.
pub fn version(lines: &[Value]) -> Option<&str> {
    lines.iter().find_map(|l| l["version"].as_str())
}

/// Claude Code's own folder: `CLAUDE_CONFIG_DIR` if set, else `~/.claude`.
fn claude_dir() -> PathBuf {
    std::env::var_os("CLAUDE_CONFIG_DIR").filter(|d| !d.is_empty()).map(PathBuf::from).unwrap_or_else(|| home().join(".claude"))
}

pub fn projects_dir() -> PathBuf {
    claude_dir().join("projects")
}

/// Claude Code's folder name for a working directory: every non-alphanumeric character becomes `-`.
pub fn encode(dir: &Path) -> String {
    dir.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

/// Claude Code's session folder for `cwd`, under whichever spelling of the folder exists.
fn sessions_for(cwd: &Path) -> Option<PathBuf> {
    // $PWD counts only when it is this folder: a parent program can leave it pointing elsewhere.
    let same = |p: &PathBuf| crate::session::canonical(p).ok() == crate::session::canonical(cwd).ok();
    let pwd = std::env::var_os("PWD").map(PathBuf::from).filter(same);
    let spellings = [Some(cwd.to_path_buf()), pwd, crate::session::canonical(cwd).ok()];
    spellings.into_iter().flatten().map(|p| projects_dir().join(encode(&p))).find(|d| d.is_dir())
}

/// The session with `id`, or the most recently active session started in `cwd`.
pub fn find(cwd: &Path, id: Option<&str>) -> Result<PathBuf> {
    if let Some(id) = id {
        ensure!(id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "not a session id: {id}");
        let dirs = fs::read_dir(projects_dir()).with_context(|| format!("no Claude Code session with id {id} (no {})", projects_dir().display()))?;
        for dir in dirs {
            let path = dir?.path().join(format!("{id}.jsonl"));
            if path.is_file() {
                return Ok(path);
            }
        }
        bail!("no Claude Code session with id {id}");
    }
    list(cwd).into_iter().max_by_key(|(_, at, _)| *at).map(|(p, _, _)| p).with_context(|| format!("no Claude Code sessions for {}", cwd.display()))
}

/// Every session started in `cwd`: its file, when it was last used, and its title (the
/// name Claude Code gave it, or else its first message).
pub fn list(cwd: &Path) -> Vec<(PathBuf, std::time::SystemTime, String)> {
    let Some(dir) = sessions_for(cwd) else { return vec![] };
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .filter_map(|p| {
            let at = fs::metadata(&p).and_then(|m| m.modified()).ok()?;
            // No prompt in it: nothing to share.
            let title = title(&p)?;
            Some((p, at, title))
        })
        .collect()
}

/// A session's title from its first few thousand lines, without reading a big file whole.
fn title(path: &Path) -> Option<String> {
    use std::io::BufRead;
    let file = std::io::BufReader::new(fs::File::open(path).ok()?);
    let mut first_prompt = None;
    let mut named = None;
    for line in file.lines().take(3000).map_while(|l| l.ok()) {
        if line.contains("\"ai-title\"") || (first_prompt.is_none() && line.contains("\"type\":\"user\"")) {
            let Ok(v) = serde_json::from_str::<Value>(&line) else { continue };
            if let Some(t) = v["aiTitle"].as_str() {
                named = Some(t.to_string());
            } else if v["isMeta"] != true {
                let c = &v["message"]["content"];
                let text = c.as_str().or_else(|| c.as_array()?.iter().find_map(|b| b["text"].as_str())).map(crate::convert::strip_intro).filter(|t| !t.is_empty() && !t.starts_with('<'));
                first_prompt = first_prompt.or(text.map(String::from));
            }
        }
    }
    named.or(first_prompt)
}

pub fn cwd(lines: &[Value]) -> Option<PathBuf> {
    lines.iter().find_map(|l| l["cwd"].as_str()).map(PathBuf::from)
}

/// Tools whose content comes from the one file they name, so only that file is judged.
const FILE_TOOLS: &[(&str, &str)] = &[
    ("Read", "file_path"),
    ("Edit", "file_path"),
    ("MultiEdit", "file_path"),
    ("Write", "file_path"),
    ("NotebookEdit", "notebook_path"),
];

/// Attachment fields that name the file whose content the attachment carries.
const ATTACHMENT_FILE_KEYS: &[&str] = &["filename", "path", "filePath", "file_path"];

pub fn touched(lines: &[Value]) -> Vec<Touch<'_>> {
    // Tool outputs live on later entries; index them by tool_use id first.
    let mut outputs: HashMap<&str, Vec<&str>> = HashMap::new();
    for line in lines {
        for b in blocks(line).filter(|b| b["type"] == "tool_result") {
            let texts = outputs.entry(b["tool_use_id"].as_str().unwrap_or("")).or_default();
            strings(&b["content"], texts);
            strings(&line["toolUseResult"], texts);
        }
    }
    let mut out = Vec::new();
    for line in lines {
        let cwd = PathBuf::from(line["cwd"].as_str().unwrap_or("/"));
        if line["type"] == "attachment" {
            // An attachment is judged by the file it names and by every path it mentions.
            let attachment = &line["attachment"];
            let mut outputs = vec![];
            strings(attachment, &mut outputs);
            let file = attachment_file(attachment).map(|f| cwd.join(f));
            let id = line["uuid"].as_str().unwrap_or("").to_string();
            let tool = attachment["type"].as_str().unwrap_or("attachment");
            out.push(Touch { id, tool, attachment: true, file, cwd, inputs: vec![], outputs, opaque: false });
            continue;
        }
        for b in blocks(line).filter(|b| b["type"] == "tool_use") {
            let (id, tool) = (b["id"].as_str().unwrap_or(""), b["name"].as_str().unwrap_or(""));
            let named = FILE_TOOLS.iter().find(|(t, _)| *t == tool).and_then(|(_, key)| b["input"][*key].as_str());
            let (mut inputs, output) = (vec![], outputs.remove(id).unwrap_or_default());
            let (file, outputs) = match named {
                Some(p) => (Some(cwd.join(p)), vec![]),
                None => {
                    strings(&b["input"], &mut inputs);
                    (None, output)
                }
            };
            out.push(Touch { id: id.to_string(), tool, attachment: false, cwd: cwd.clone(), file, inputs, outputs, opaque: false });
        }
    }
    out
}

/// The file an attachment carries, wherever in the attachment it is named.
fn attachment_file(v: &Value) -> Option<&str> {
    match v {
        Value::Object(map) => ATTACHMENT_FILE_KEYS
            .iter()
            .find_map(|k| map.get(*k).and_then(Value::as_str))
            .or_else(|| map.values().find_map(attachment_file)),
        Value::Array(items) => items.iter().find_map(attachment_file),
        _ => None,
    }
}

fn blocks(line: &Value) -> impl Iterator<Item = &Value> {
    line.pointer("/message/content").and_then(Value::as_array).into_iter().flatten()
}

fn strings<'a>(v: &'a Value, out: &mut Vec<&'a str>) {
    match v {
        Value::String(s) => out.push(s),
        Value::Array(items) => items.iter().for_each(|x| strings(x, out)),
        Value::Object(map) => map.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}

/// The subagents of a session, which Claude Code keeps next to it in `<session>/subagents/`.
pub fn subagents(session: &Path) -> Vec<Subagent> {
    let dir = session.with_extension("").join("subagents");
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.to_string_lossy().ends_with(".meta.json"))
        .filter_map(|meta| {
            let m: Value = serde_json::from_str(&fs::read_to_string(&meta).ok()?).ok()?;
            let transcript = PathBuf::from(meta.to_string_lossy().replace(".meta.json", ".jsonl"));
            Some(Subagent {
                transcript,
                tool_use_id: m["toolUseId"].as_str()?.to_string(),
                description: m["description"].as_str().unwrap_or("").to_string(),
            })
        })
        .collect()
}

/// Entries that hold file backups, local bookkeeping or the sender's permission settings.
const DROPPED: &[&str] = &[
    "file-history-snapshot",
    "file-history-delta",
    "cost-state",
    "queue-operation",
    "mode",
    "permission-mode",
    "atis-latch",
];

/// Attachments that describe the sender's account, permissions, hooks or personal memory.
const DROPPED_ATTACHMENTS: &[&str] = &["credential", "mode", "permission", "hook", "memory"];

/// Entry types `podshare open` accepts; a pod could carry anything, so the rest is dropped.
const ACCEPTED: &[&str] =
    &["user", "assistant", "attachment", "system", "summary", "ai-title", "custom-title", "last-prompt"];

/// Fields that point at another entry by uuid.
const LINKS: &[&str] = &["parentUuid", "logicalParentUuid", "leafUuid", "sourceToolAssistantUUID"];

/// A copy of the transcript with thinking and `withhold`'s tool calls and attachments
/// (id → reason) removed, whatever `filters` ask for cleaned, and the project path made portable.
pub fn clean(
    lines: Vec<Value>,
    withhold: &HashMap<String, String>,
    root: &Path,
    home: &Path,
    identity: &Identity,
    echoes: &[String],
    filters: &Filters,
) -> Cleaned {
    let mut c = Cleaned::default();
    let mut removed: HashMap<String, Value> = HashMap::new(); // uuid → its parentUuid
    let scrubber = Scrubber::new(root, home, identity, echoes, filters);
    let images = filters.on(Filter::PastedImages);
    for mut line in lines {
        let withheld_attachment = line["uuid"].as_str().is_some_and(|u| withhold.contains_key(u));
        let keep = !DROPPED.contains(&line["type"].as_str().unwrap_or(""))
            && !dropped_attachment(&line)
            && !withheld_attachment
            && clean_blocks(&mut line, withhold, images, &mut c);
        if !keep {
            c.withheld += withheld_attachment as usize;
            if let Some(uuid) = line["uuid"].as_str() {
                removed.insert(uuid.to_string(), line["parentUuid"].clone());
            }
            continue;
        }
        strip_permissions(&mut line);
        // Usage and request ids say nothing about the work.
        if let Some(message) = line.get_mut("message").and_then(Value::as_object_mut) {
            message.remove("usage");
        }
        if let Some(map) = line.as_object_mut() {
            map.remove("requestId");
        }
        scrubber.scrub(&mut line, &mut c);
        c.lines.push(line);
    }
    // Point entries that referenced a removed one at its nearest kept ancestor.
    for line in &mut c.lines {
        for key in LINKS {
            if let Some(v) = line.get_mut(*key) {
                while let Some(parent) = v.as_str().and_then(|u| removed.get(u)) {
                    *v = parent.clone();
                }
            }
        }
    }
    c
}

fn dropped_attachment(line: &Value) -> bool {
    line["attachment"]["type"].as_str().is_some_and(|t| DROPPED_ATTACHMENTS.iter().any(|d| t.contains(d)))
}

/// Claude Code also stamps the permission mode on individual messages.
fn strip_permissions(line: &mut Value) {
    if let Some(message) = line.get_mut("message").and_then(Value::as_object_mut) {
        message.remove("permissionMode");
        message.remove("mode");
    }
    if let Some(map) = line.as_object_mut() {
        map.remove("permissionMode");
        map.remove("mode");
    }
}

/// Whether `podshare open` keeps this entry of a received transcript. It never trusts the
/// sender to have left out permission settings.
pub fn accept(line: &mut Value) -> bool {
    strip_permissions(line);
    ACCEPTED.contains(&line["type"].as_str().unwrap_or("")) && !dropped_attachment(line)
}

/// Drops thinking, withholds flagged tool calls (input and output) and, if `images`,
/// removes pasted images and documents. Returns false when nothing is left of the entry.
fn clean_blocks(line: &mut Value, withhold: &HashMap<String, String>, images: bool, c: &mut Cleaned) -> bool {
    let Some(blocks) = line.pointer_mut("/message/content").and_then(Value::as_array_mut) else { return true };
    let before = blocks.len();
    blocks.retain(|b| !matches!(b["type"].as_str(), Some("thinking" | "redacted_thinking")));
    c.thinking += before - blocks.len();
    let mut note = None;
    for b in blocks.iter_mut() {
        if images && matches!(b["type"].as_str(), Some("image" | "document")) {
            *b = json!({ "type": "text", "text": "[pasted image or document removed by podshare]" });
            c.images += 1;
        }
        let id = b["id"].as_str().or(b["tool_use_id"].as_str()).unwrap_or("");
        let Some(why) = withhold.get(id) else { continue };
        let text = withheld_note(why);
        match b["type"].as_str() {
            Some("tool_use") => blank_strings(&mut b["input"], &text),
            Some("tool_result") => {
                b["content"] = text.clone().into();
                note = Some(text);
                c.withheld += 1;
            }
            _ => {}
        }
    }
    if blocks.is_empty() {
        return false;
    }
    // Claude Code keeps a second copy of every tool result next to the message.
    if let (Some(text), Some(copy)) = (note, line.get_mut("toolUseResult")) {
        *copy = text.into();
    }
    true
}

/// A tool's kind in the neutral format (see docs/format.md).
fn tool_kind(name: &str) -> &'static str {
    match name {
        "Read" => "read_file",
        "Write" => "write_file",
        "Edit" | "MultiEdit" | "NotebookEdit" => "edit_file",
        "Bash" => "shell",
        "Grep" => "search",
        "Glob" => "list_files",
        "Agent" | "Task" => "subagent",
        "WebFetch" | "WebSearch" => "web",
        n if n.starts_with("mcp__") => "connected_tool",
        _ => "other",
    }
}

fn result_text(content: &Value) -> String {
    match content {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .map(|p| p["text"].as_str().map_or_else(|| format!("[{}]", p["type"].as_str().unwrap_or("content")), str::to_string))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => String::new(),
    }
}

/// The neutral form of a cleaned transcript (docs/format.md): what was said, which tools ran
/// and what kind they were, and what they returned. Other agents' adapters import this.
pub fn to_neutral(lines: &[Value]) -> Vec<Value> {
    // After a compaction the agent only sees its summary and what follows.
    let start = lines.iter().rposition(|l| l["isCompactSummary"] == true).unwrap_or(0);
    let mut out = vec![];
    for line in lines[start..].iter().filter(|l| l["isSidechain"] != true) {
        let role = match line["type"].as_str() {
            Some("summary") => {
                out.push(json!({ "type": "summary", "text": line["summary"] }));
                continue;
            }
            Some(r @ ("user" | "assistant")) if line["isMeta"] != true => r,
            _ => continue,
        };
        let content = &line["message"]["content"];
        if line["isCompactSummary"] == true {
            out.push(json!({ "type": "summary", "text": result_text(content) }));
            continue;
        }
        let Value::Array(blocks) = content else {
            if let Some(text) = content.as_str() {
                out.push(json!({ "role": role, "type": "text", "text": text }));
            }
            continue;
        };
        for b in blocks {
            match b["type"].as_str() {
                Some("text") => out.push(json!({ "role": role, "type": "text", "text": b["text"] })),
                Some("tool_use") => {
                    let name = b["name"].as_str().unwrap_or("");
                    out.push(json!({ "role": "assistant", "type": "tool_call", "id": b["id"], "tool": tool_kind(name), "name": name, "input": b["input"] }));
                }
                Some("tool_result") => out.push(json!({
                    "role": "tool", "type": "tool_result", "id": b["tool_use_id"],
                    "content": result_text(&b["content"]), "is_error": b["is_error"] == true,
                })),
                _ => {}
            }
        }
    }
    out
}

/// A received transcript made ready to resume in `dir`: only conversation entries, the
/// project path swapped in, and a fresh session id so it never collides with the original
/// or an earlier open. Returns the id and the transcript.
pub fn prepare(transcript: &[u8], dir: &Path) -> Result<(String, String)> {
    let dir_str = dir.to_string_lossy();
    let id = uuid::Uuid::new_v4().to_string();
    let mut out = String::new();
    for line in std::str::from_utf8(transcript).context("transcript is not text")?.lines() {
        let mut v: Value = serde_json::from_str(line).context("transcript line is not JSON")?;
        if !accept(&mut v) {
            continue;
        }
        replace_strings(&mut v, ROOT, &dir_str);
        for k in ["sessionId", "session_id"] {
            if v.get(k).is_some() {
                v[k] = id.clone().into();
            }
        }
        // The agent works in the unpacked folder, wherever the sender says it was.
        if v["cwd"].as_str().is_some_and(|c| !under(&normalize(Path::new(c)), dir)) {
            v["cwd"] = dir_str.clone().into();
        }
        out += &(v.to_string() + "\n");
    }
    Ok((id, out))
}

/// Roughly how many tokens Claude reads when it resumes this cleaned transcript: messages,
/// tool calls and results, and the context entries Claude Code attached, from the last
/// compaction on.
pub fn estimate_tokens(lines: &[Value]) -> usize {
    let start = lines.iter().rposition(|l| l["isCompactSummary"] == true).unwrap_or(0);
    let mut images = 0;
    let chars: usize = lines[start..]
        .iter()
        .map(|l| match l["type"].as_str() {
            Some("user" | "assistant") => crate::session::model_chars(&l["message"]["content"], &mut images),
            Some("attachment") => crate::session::model_chars(&l["attachment"], &mut images),
            _ => 0,
        })
        .sum();
    text_tokens(chars) + images * IMAGE_TOKENS
}

/// Tokens for `chars` characters of session text. Measured against the counts Claude Code
/// reported for real resumed sessions: its models read code, paths and JSON at about 2.2
/// characters per token (within a few percent on sessions from 10k to 200k tokens).
pub fn text_tokens(chars: usize) -> usize {
    chars * 10 / 22
}

/// What an image in a resumed session cost Claude in the same measurements.
const IMAGE_TOKENS: usize = 2_000;

/// A Claude Code session holding `turns`, in `dir`.
pub fn from_turns(turns: &[Turn], dir: &Path) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = rfc3339(std::time::SystemTime::now());
    let cwd = dir.to_string_lossy();
    let mut parent = Value::Null;
    let mut out = String::new();
    for (i, t) in turns.iter().enumerate() {
        let uuid = uuid::Uuid::new_v4().to_string();
        let message = if t.user {
            json!({ "role": "user", "content": t.text })
        } else {
            json!({ "id": format!("msg_podshare_{i}"), "type": "message", "role": "assistant", "model": "<synthetic>",
                "content": [{ "type": "text", "text": t.text }], "stop_reason": "end_turn", "stop_sequence": null,
                "usage": { "input_tokens": 0, "output_tokens": 0 } })
        };
        let line = json!({ "type": if t.user { "user" } else { "assistant" }, "uuid": uuid, "parentUuid": parent,
            "sessionId": id, "cwd": cwd, "version": "2.1.0", "timestamp": now, "isSidechain": false,
            "userType": "external", "message": message });
        out += &(line.to_string() + "\n");
        parent = uuid.into();
    }
    (id, out)
}

/// Puts a prepared transcript where Claude Code looks for `dir`'s sessions.
pub fn install(dir: &Path, id: &str, transcript: &str) -> Result<()> {
    let sessions = projects_dir().join(encode(dir));
    fs::create_dir_all(&sessions)?;
    Ok(fs::write(sessions.join(format!("{id}.jsonl")), transcript)?)
}

/// The program and arguments that resume session `id` in plan mode, with `note` added
/// to the system prompt.
pub fn resume_command<'a>(id: &'a str, note: &'a str) -> (&'static str, Vec<&'a str>) {
    ("claude", vec!["--resume", id, "--permission-mode", "plan", "--append-system-prompt", note])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::{normalize, paths_in};

    fn run(lines: Vec<Value>, withhold: &[(&str, &str)]) -> Cleaned {
        run_with(lines, withhold, Filters::default())
    }

    fn run_with(lines: Vec<Value>, withhold: &[(&str, &str)], filters: Filters) -> Cleaned {
        let withhold = withhold.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let identity = vec![("me".to_string(), "user"), ("Alice Smith".to_string(), "[name]")];
        let echoes = vec!["hunter2Zebra99".to_string()];
        clean(lines, &withhold, Path::new("/Users/me/proj"), Path::new("/Users/me"), &identity, &echoes, &filters)
    }

    #[test]
    fn starts_from_the_last_compaction_and_skips_side_chains() {
        let user = |text: &str| json!({"type": "user", "message": {"content": text}});
        let mut side = user("helper chatter");
        side["isSidechain"] = true.into();
        let lines = vec![
            user("old question"),
            json!({"type": "user", "isCompactSummary": true, "message": {"content": "we fixed the parser"}}),
            side,
            user("new question"),
        ];
        let n = to_neutral(&lines);
        assert_eq!(n.len(), 2, "{n:?}");
        assert_eq!(n[0]["type"], "summary");
        assert_eq!(n[1]["text"], "new question");
    }

    #[test]
    fn drops_thinking_and_relinks_the_chain() {
        let c = run(
            vec![
                json!({"type": "user", "uuid": "a", "parentUuid": null, "message": {"content": [{"type": "text", "text": "hi"}]}}),
                json!({"type": "assistant", "uuid": "t", "parentUuid": "a", "message": {"content": [{"type": "thinking", "thinking": "hmm", "signature": "x"}]}}),
                json!({"type": "assistant", "uuid": "b", "parentUuid": "t", "message": {"content": [{"type": "text", "text": "hello"}]}}),
                json!({"type": "last-prompt", "leafUuid": "t"}),
                json!({"type": "file-history-snapshot", "snapshot": {}}),
                json!({"type": "permission-mode", "permissionMode": "bypassPermissions"}),
                json!({"type": "attachment", "uuid": "o", "parentUuid": "b", "attachment": {"type": "credential_org", "organizationUuid": "x"}}),
            ],
            &[],
        );
        assert_eq!(c.thinking, 1);
        assert_eq!(c.lines.len(), 3);
        assert_eq!(c.lines[1]["parentUuid"], "a");
        assert_eq!(c.lines[2]["leafUuid"], "a");
    }

    #[test]
    fn receiver_drops_unknown_entries_and_permission_fields() {
        let mut ok = json!({"type": "user", "permissionMode": "bypassPermissions", "mode": "bypassPermissions",
            "message": {"content": "hi", "permissionMode": "bypassPermissions"}});
        assert!(accept(&mut ok));
        assert!(!ok.to_string().contains("bypass"), "{ok}");
        for mut bad in [
            json!({"type": "permission-mode", "permissionMode": "bypassPermissions"}),
            json!({"type": "attachment", "attachment": {"type": "auto_mode", "bypass": true}}),
            json!({"type": "attachment", "attachment": {"type": "hook_result", "command": "x"}}),
            json!({"type": "something-new"}),
        ] {
            assert!(!accept(&mut bad), "{bad}");
        }
    }

    #[test]
    fn withholds_input_output_and_attachments() {
        let c = run(
            vec![
                json!({"type": "assistant", "uuid": "u", "message": {"content": [{"type": "tool_use", "id": "t1", "name": "Edit",
                    "input": {"file_path": "/Users/me/proj/.env", "old_string": "A=1", "new_string": "SECRET=1"}}]}}),
                json!({"type": "user", "uuid": "r", "parentUuid": "u", "toolUseResult": {"file": {"content": "SECRET=1"}},
                    "message": {"content": [{"type": "tool_result", "tool_use_id": "t1", "content": "SECRET=1"}]}}),
                json!({"type": "attachment", "uuid": "at", "parentUuid": "r", "attachment": {"type": "file", "filename": ".env", "content": "SECRET=1"}}),
            ],
            &[("t1", "environment file"), ("at", "environment file")],
        );
        let text = serde_json::to_string(&c.lines).unwrap();
        assert!(!text.contains("SECRET=1") && !text.contains(".env"), "{text}");
        assert_eq!(c.lines.len(), 2);
        assert_eq!(c.lines[1]["toolUseResult"], "[withheld by podshare when sharing; the agent saw the real content at the time: environment file]");
    }

    #[test]
    fn makes_paths_portable_and_masks_personal_data() {
        let c = run(
            vec![json!({"type": "user", "uuid": "a", "cwd": "/Users/me/proj",
                "message": {"content": [{"type": "text", "text": "read /Users/me/proj/src/a.rs and /Users/me/notes, mail me@example.com; -rw-r--r-- 1 me staff; /tmp/-Users-ME-x; %2FUsers%2Fme%2F; alice smith wrote it"},
                                        {"type": "image", "source": {"type": "base64", "data": "AAmeAA"}}]},
                "toolUseResult": {"me@example.com": 1}})],
            &[],
        );
        assert_eq!(c.lines[0]["cwd"], ROOT);
        assert_eq!(
            c.lines[0]["message"]["content"][0]["text"],
            "read {{POD_ROOT}}/src/a.rs and ~/notes, mail [email]; -rw-r--r-- 1 user staff; /tmp/-Users-user-x; %2FUsers%2Fuser%2F; [name] wrote it"
        );
        assert_eq!(c.lines[0]["message"]["content"][1]["text"], "[pasted image or document removed by podshare]");
        assert!(c.lines[0]["toolUseResult"].get("[email]").is_some());
    }

    #[test]
    fn redacts_secrets_the_agent_repeated() {
        let c = run(
            vec![json!({"type": "assistant", "message": {"content": [{"type": "text", "text": "The password is `hunter2Zebra99`."}]}})],
            &[],
        );
        assert_eq!(c.lines[0]["message"]["content"][0]["text"], "The password is `[REDACTED:repeated]`.");
    }

    #[test]
    fn exports_a_neutral_conversation() {
        let lines = vec![
            json!({"type": "user", "message": {"content": "fix the bug"}}),
            json!({"type": "user", "isMeta": true, "message": {"content": "<system reminder>"}}),
            json!({"type": "assistant", "message": {"content": [
                {"type": "text", "text": "Reading it."},
                {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "{{POD_ROOT}}/a.rs"}}]}}),
            json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "t1",
                "content": [{"type": "text", "text": "fn a() {}"}, {"type": "image", "source": {}}]}]}}),
        ];
        let n = to_neutral(&lines);
        assert_eq!(n.len(), 4);
        assert_eq!(n[0], json!({"role": "user", "type": "text", "text": "fix the bug"}));
        assert_eq!(n[2]["tool"], "read_file");
        assert_eq!(n[3]["content"], "fn a() {}\n[image]");
    }

    #[test]
    fn leaves_base64_image_data_alone() {
        let c = run_with(
            vec![json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "x",
                "content": [{"type": "image", "source": {"type": "base64", "data": "AAmeAA"}}]}]}})],
            &[],
            Filters::default(),
        );
        assert_eq!(c.lines[0]["message"]["content"][0]["content"][0]["source"]["data"], "AAmeAA");
    }

    #[test]
    fn turned_off_filters_leave_text_alone_but_root_stays_portable() {
        let line = json!({"type": "user", "uuid": "a", "message": {"content": [
            {"type": "text", "text": "/Users/me/proj/a me@example.com /Users/me/x DB_PASSWORD=hunter22"},
            {"type": "image", "source": {"data": "AAAA"}}]}});
        let all_off = Filters::new(crate::filters::ALL.to_vec());
        let c = run_with(vec![line], &[], all_off);
        let content = &c.lines[0]["message"]["content"];
        assert_eq!(content[0]["text"], "{{POD_ROOT}}/a me@example.com /Users/me/x DB_PASSWORD=hunter22");
        assert_eq!(content[1]["type"], "image");
    }

    #[test]
    fn finds_every_path_a_call_touched() {
        let lines = vec![
            json!({"type": "assistant", "cwd": "/p", "message": {"content": [
                {"type": "tool_use", "id": "r", "name": "Read", "input": {"file_path": "a.rs"}},
                {"type": "tool_use", "id": "b", "name": "Bash", "input": {"command": "ls ~/.ssh"}}]}}),
            json!({"type": "user", "message": {"content": [{"type": "tool_result", "tool_use_id": "b", "content": "id_rsa\nknown_hosts"}]}}),
            json!({"type": "attachment", "uuid": "at", "cwd": "/p", "attachment": {"type": "file", "filename": ".env"}}),
        ];
        let t = touched(&lines);
        assert_eq!(t[0].file.as_deref(), Some(Path::new("/p/a.rs")));
        assert_eq!(t[2].file.as_deref(), Some(Path::new("/p/.env")));
        let nested = json!({"type": "attachment", "attachment": {"type": "x", "content": {"file": {"filePath": "/p/.env"}}}});
        assert_eq!(touched(std::slice::from_ref(&nested))[0].file.as_deref(), Some(Path::new("/p/.env")));
        let home = Path::new("/h");
        let bash: Vec<PathBuf> =
            t[1].inputs.iter().chain(&t[1].outputs).flat_map(|s| paths_in(s, &t[1].cwd, home)).collect();
        assert!(bash.contains(&PathBuf::from("/h/.ssh")) && bash.contains(&PathBuf::from("/p/id_rsa")), "{bash:?}");
        assert_eq!(normalize(Path::new("/p/../../h/.ssh/x")), PathBuf::from("/h/.ssh/x"));
        let up: Vec<PathBuf> = paths_in("cd .. and ../x, see a.rs.", Path::new("/p/q"), home).collect();
        assert!(up.contains(&PathBuf::from("/p")) && up.contains(&PathBuf::from("/p/x")) && up.contains(&PathBuf::from("/p/q/a.rs")), "{up:?}");
    }
}
