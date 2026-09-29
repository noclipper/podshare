//! Turning a neutral conversation (docs/format.md) into plain turns another agent can
//! resume: what was said, and each tool call as a line of text with its trimmed result.
//! Tool calls can't move between agents as tool calls (the tools differ), but what the
//! agent did and saw can.

use serde_json::Value;

/// Characters of text in carried-over turns, for the receiving agent's token estimate.
pub fn turns_chars(turns: &[Turn]) -> usize {
    turns.iter().map(|t| t.text.len()).sum()
}

/// `s` on one line, cut to `n` characters.
pub fn short_line(s: &str, n: usize) -> String {
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

/// A token count as people say it: 850, 42k, 1.2M.
pub fn short_count(n: usize) -> String {
    match n {
        n if n >= 1_000_000 => format!("{:.1}M", n as f64 / 1e6),
        n if n >= 10_000 => format!("{}k", n / 1000),
        n if n >= 1_000 => format!("{:.1}k", n as f64 / 1e3),
        n => n.to_string(),
    }
}

/// `text` without the intro podshare adds when a conversation moves between agents.
pub fn strip_intro(text: &str) -> &str {
    match text.strip_prefix("[This conversation started in ").and_then(|r| r.split_once("followed by what they returned.]")) {
        Some((_, rest)) => rest.trim_start(),
        None => text,
    }
}

/// One turn of a conversation: the user's, or the agent's.
pub struct Turn {
    pub user: bool,
    pub text: String,
}

/// Longest tool result carried over; the rest is trimmed so the context stays useful.
const RESULT_LIMIT: usize = 2000;

fn trim(s: &str, limit: usize) -> String {
    match s.char_indices().nth(limit) {
        Some((i, _)) => format!("{}\n… (trimmed)", &s[..i]),
        None => s.to_string(),
    }
}

/// A tool call as one line, like "▸ ran `npm test`".
fn describe(call: &Value) -> String {
    let input = &call["input"];
    let first = |keys: &[&str]| keys.iter().find_map(|k| input[*k].as_str()).map(|s| trim(s, 300)).unwrap_or_default();
    let files = || match input["files"].as_array() {
        Some(files) => files.iter().filter_map(Value::as_str).map(|f| format!("`{f}`")).collect::<Vec<_>>().join(", "),
        None => format!("`{}`", first(&["file_path", "path", "notebook_path"])),
    };
    match call["tool"].as_str() {
        Some("shell") => format!("▸ ran `{}`", first(&["command", "cmd"])),
        Some("read_file") => format!("▸ read {}", files()),
        Some("write_file") => format!("▸ wrote {}", files()),
        Some("edit_file") => format!("▸ edited {}", files()),
        Some("search") => format!("▸ searched for `{}`", first(&["pattern", "query"])),
        Some("list_files") => format!("▸ listed `{}`", first(&["pattern", "path"])),
        Some("subagent") => format!("▸ asked a helper agent: {}", first(&["description", "prompt"])),
        Some("web") => format!("▸ looked up {}", first(&["url", "query"])),
        _ => format!("▸ used {}", call["name"].as_str().unwrap_or("a tool")),
    }
}

/// The conversation as alternating turns, starting with the user and ending with the
/// agent, with a first line saying where it came from.
pub fn turns(neutral: &[Value], from: &str) -> Vec<Turn> {
    let mut out: Vec<Turn> = vec![];
    let mut push = |user: bool, text: String| {
        if text.trim().is_empty() {
            return;
        }
        match out.last_mut() {
            Some(t) if t.user == user => {
                t.text.push_str("\n\n");
                t.text.push_str(&text);
            }
            _ => out.push(Turn { user, text }),
        }
    };
    for v in neutral {
        let text = v["text"].as_str().unwrap_or("").to_string();
        match (v["type"].as_str(), v["role"].as_str()) {
            // A conversation moved twice keeps one intro: the new one below.
            (Some("text"), Some("user")) => push(true, strip_intro(&text).to_string()),
            (Some("text"), _) => push(false, text),
            (Some("tool_call"), _) => push(false, describe(v)),
            (Some("tool_result"), _) => {
                let result = v["content"].as_str().unwrap_or("").trim();
                if !result.is_empty() {
                    push(false, format!("```\n{}\n```", trim(result, RESULT_LIMIT)));
                }
            }
            (Some("summary"), _) => push(true, format!("[Summary of the conversation before this point]\n{text}")),
            _ => {}
        }
    }
    let intro = format!(
        "[This conversation started in {from} and was moved here with podshare. {from}'s tool calls \
         appear as text lines (▸ …) followed by what they returned.]"
    );
    match out.first_mut() {
        Some(t) if t.user => t.text = format!("{intro}\n\n{}", t.text),
        _ => out.insert(0, Turn { user: true, text: intro }),
    }
    if out.last().is_some_and(|t| t.user) {
        out.push(Turn { user: false, text: "(Picked up here.)".into() });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keeps_one_intro_when_moved_twice() {
        let once = turns(&[json!({"type": "text", "role": "user", "text": "fix it"})], "Codex");
        let twice = turns(&[json!({"type": "text", "role": "user", "text": once[0].text})], "Claude Code");
        assert_eq!(twice[0].text.matches("moved here with podshare").count(), 1, "{}", twice[0].text);
        assert!(twice[0].text.contains("started in Claude Code") && twice[0].text.ends_with("fix it"));
    }

    #[test]
    fn writes_token_counts_the_way_people_say_them() {
        assert_eq!(short_count(42_300), "42k");
        assert_eq!(short_count(1_234), "1.2k");
        assert_eq!(short_count(850), "850");
    }

    #[test]
    fn alternates_turns_and_describes_tools_as_text() {
        let neutral = vec![
            json!({"role": "user", "type": "text", "text": "fix the bug"}),
            json!({"role": "user", "type": "text", "text": "in sum.js"}),
            json!({"role": "assistant", "type": "text", "text": "Looking."}),
            json!({"role": "assistant", "type": "tool_call", "id": "1", "tool": "read_file", "name": "Read", "input": {"file_path": "src/sum.js"}}),
            json!({"role": "tool", "type": "tool_result", "id": "1", "content": "x".repeat(3000)}),
            json!({"role": "assistant", "type": "tool_call", "id": "2", "tool": "shell", "name": "shell", "input": {"command": "npm test"}}),
            json!({"role": "tool", "type": "tool_result", "id": "2", "content": ""}),
            json!({"role": "user", "type": "text", "text": "thanks"}),
        ];
        let t = turns(&neutral, "Codex");
        assert_eq!(t.iter().map(|t| t.user).collect::<Vec<_>>(), vec![true, false, true, false]);
        assert!(t[0].text.starts_with("[This conversation started in Codex") && t[0].text.contains("fix the bug\n\nin sum.js"));
        assert!(t[1].text.contains("▸ read `src/sum.js`") && t[1].text.contains("… (trimmed)") && t[1].text.contains("▸ ran `npm test`"));
        assert_eq!(t[3].text, "(Picked up here.)");
    }
}
