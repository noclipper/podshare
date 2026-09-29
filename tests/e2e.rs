//! End to end, on every platform: fake agent sessions in a fake home, packed, opened
//! (natively and in the other agent), and checked for the files that should arrive and
//! the secrets that must not.

use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const SECRET: &str = "hunter2Zebra99";
const CLAUDE_ID: &str = "11111111-2222-3333-4444-555555555555";
const CODEX_ID: &str = "01a0e9ae-0000-7000-8000-000000000001";
const SENDER_SESSIONS: [&str; 2] = [CLAUDE_ID, CODEX_ID];

struct Sandbox {
    root: PathBuf,
    home: PathBuf,
}

impl Sandbox {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!("podshare-e2e-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("home")).unwrap();
        let root = dunce::canonicalize(&root).unwrap();
        Sandbox { home: root.join("home"), root }
    }

    /// Runs podshare in `cwd` with this sandbox as home, and returns what it printed.
    fn run(&self, cwd: &Path, args: &[&str]) -> String {
        let out = Command::new(env!("CARGO_BIN_EXE_podshare"))
            .args(args)
            .current_dir(cwd)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env_remove("PWD")
            .env_remove("CODEX_HOME")
            .env_remove("CLAUDE_CONFIG_DIR")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "podshare {args:?} failed:\n{text}");
        text
    }

    /// A git project with a source file and a `.env` holding the secret.
    fn project(&self, name: &str, file: &str, body: &str) -> PathBuf {
        let dir = self.home.join("work").join(name);
        fs::create_dir_all(dir.join(Path::new(file).parent().unwrap())).unwrap();
        fs::write(dir.join(file), body).unwrap();
        fs::write(dir.join(".env"), format!("DB_PASSWORD={SECRET}\n")).unwrap();
        fs::write(dir.join(".gitignore"), ".env\n").unwrap();
        let git = |args: &[&str]| {
            let ok = Command::new("git").args(args).current_dir(&dir).output().unwrap().status.success();
            assert!(ok, "git {args:?}");
        };
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"]);
        dunce::canonicalize(&dir).unwrap()
    }

    /// Packs the session in `project` and opens it in a new folder `into`, optionally in
    /// another agent. Returns the unpacked project folder.
    fn share(&self, project: &Path, agent: &str, into: &str, open_in: Option<&str>) -> PathBuf {
        let pod = self.root.join(format!("{into}.pod"));
        let packed = self.run(project, &["pack", "--yes", "--agent", agent, "-o", pod.to_str().unwrap()]);
        let line = packed.lines().find_map(|l| l.trim().strip_prefix("podshare open ")).expect("open line").trim_matches('\'').to_string();
        let friend = self.root.join(into);
        fs::create_dir_all(&friend).unwrap();
        let mut args = vec!["open", line.as_str(), "--yes", "--no-launch"];
        if let Some(agent) = open_in {
            args.extend(["--agent", agent]);
        }
        self.run(&friend, &args);
        friend.join(project.file_name().unwrap())
    }

    /// Every file under `dir` joined, for leak checks, skipping the sender's own sessions
    /// (they hold the secret by design; only what podshare wrote is checked).
    fn text_under(dir: &Path) -> String {
        let mut all = String::new();
        let Ok(entries) = fs::read_dir(dir) else { return all };
        for e in entries.flatten() {
            let p = e.path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            if SENDER_SESSIONS.iter().any(|id| name.contains(id)) {
                continue;
            }
            if p.is_dir() {
                all += &Self::text_under(&p);
            } else {
                all += &String::from_utf8_lossy(&fs::read(&p).unwrap_or_default());
            }
        }
        all
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn encode(dir: &Path) -> String {
    dir.to_string_lossy().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect()
}

fn file_url(dir: &Path) -> String {
    let p = dir.to_string_lossy().replace('\\', "/");
    format!("file://{}{}", if p.starts_with('/') { "" } else { "/" }, p)
}

/// A Claude Code session that reads the source and `.env`, then repeats the secret.
fn claude_session(sb: &Sandbox, project: &Path, file: &str) {
    let cwd = project.to_string_lossy();
    let id = CLAUDE_ID;
    let dir = sb.home.join(".claude").join("projects").join(encode(project));
    fs::create_dir_all(&dir).unwrap();
    let base = |uuid: &str, parent: Option<&str>, kind: &str, message: serde_json::Value| {
        json!({ "type": kind, "uuid": uuid, "parentUuid": parent, "cwd": cwd, "sessionId": id, "version": "2.0.0", "message": message })
    };
    let src = project.join(file).to_string_lossy().into_owned();
    let env = project.join(".env").to_string_lossy().into_owned();
    let lines = [
        base("u1", None, "user", json!({ "role": "user", "content": "fix the code and check .env" })),
        base("a1", Some("u1"), "assistant", json!({ "role": "assistant", "content": [{ "type": "tool_use", "id": "t1", "name": "Read", "input": { "file_path": src } }] })),
        base("r1", Some("a1"), "user", json!({ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t1", "content": "the code" }] })),
        base("a2", Some("r1"), "assistant", json!({ "role": "assistant", "content": [{ "type": "tool_use", "id": "t2", "name": "Read", "input": { "file_path": env } }] })),
        base("r2", Some("a2"), "user", json!({ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t2", "content": format!("DB_PASSWORD={SECRET}") }] })),
        base("a3", Some("r2"), "assistant", json!({ "role": "assistant", "content": [{ "type": "text", "text": format!("Fixed. The password is {SECRET}.") }] })),
    ];
    let body: String = lines.iter().map(|l| l.to_string() + "\n").collect();
    fs::write(dir.join(format!("{id}.jsonl")), body).unwrap();
}

/// A Codex session that reads the source and `.env` in one command, then repeats the secret.
fn codex_session(sb: &Sandbox, project: &Path, file: &str) {
    let cwd = project.to_string_lossy();
    let id = CODEX_ID;
    let dir = sb.home.join(".codex").join("sessions").join("2026").join("01").join("01");
    fs::create_dir_all(&dir).unwrap();
    let cmd = format!("cat {file} .env");
    let lines = [
        json!({ "type": "session_meta", "payload": { "id": id, "cwd": cwd, "cli_version": "0.158.0", "creator_user_id": "user-SECRETID", "creator_account_id": "acct-SECRETID" } }),
        json!({ "type": "turn_context", "payload": { "cwd": cwd, "approval_policy": "never", "sandbox_policy": { "type": "danger-full-access" } } }),
        json!({ "type": "response_item", "payload": { "type": "message", "role": "user", "content": [{ "type": "input_text", "text": "read the code and .env" }] } }),
        json!({ "type": "response_item", "payload": { "type": "custom_tool_call", "call_id": "c1", "name": "exec", "input": format!("text(await tools.exec_command({{cmd:{}}}));", json!(cmd)) } }),
        json!({ "type": "event_msg", "payload": { "type": "item_completed", "item": { "type": "CommandExecution", "command": ["sh", "-lc", cmd], "cwd": file_url(project), "aggregated_output": format!("the code\nDB_PASSWORD={SECRET}"), "parsed_cmd": [{ "type": "unknown", "cmd": cmd }] } } }),
        json!({ "type": "response_item", "payload": { "type": "custom_tool_call_output", "call_id": "c1", "output": [{ "type": "input_text", "text": format!("the code\nDB_PASSWORD={SECRET}") }] } }),
        json!({ "type": "response_item", "payload": { "type": "message", "role": "assistant", "content": [{ "type": "output_text", "text": format!("Read it. The password is {SECRET}.") }] } }),
    ];
    let body: String = lines.iter().enumerate().map(|(i, l)| {
        let mut l = l.clone();
        l["ordinal"] = i.into();
        l["timestamp"] = "2026-01-01T00:00:00.000Z".into();
        l.to_string() + "\n"
    }).collect();
    fs::write(dir.join(format!("rollout-2026-01-01T00-00-00-{id}.jsonl")), body).unwrap();
}

fn assert_clean(sb: &Sandbox, got: &Path, file: &str) {
    assert!(got.join(file).is_file(), "{file} missing in {}", got.display());
    assert!(!got.join(".env").exists(), ".env was shared");
    let everything = Sandbox::text_under(&sb.root.join(got.parent().unwrap().file_name().unwrap())) + &Sandbox::text_under(&sb.home.join(".claude")) + &Sandbox::text_under(&sb.home.join(".codex"));
    for gone in [SECRET, "SECRETID", "danger-full-access"] {
        assert!(!everything.contains(gone), "{gone} leaked");
    }
}

#[test]
fn claude_code_round_trip() {
    let sb = Sandbox::new("claude");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_session(&sb, &project, "src/main.rs");
    let got = sb.share(&project, "claude-code", "friend", None);
    assert_clean(&sb, &got, "src/main.rs");
    let installed = sb.home.join(".claude").join("projects").join(encode(&got));
    assert!(fs::read_dir(installed).unwrap().count() == 1, "session not installed");
}

#[test]
fn codex_round_trip() {
    let sb = Sandbox::new("codex");
    let project = sb.project("cx", "src/a.js", "let a = 1;\n");
    codex_session(&sb, &project, "src/a.js");
    let got = sb.share(&project, "codex", "friend", None);
    assert_clean(&sb, &got, "src/a.js");
    let sessions = Sandbox::text_under(&sb.home.join(".codex"));
    assert!(sessions.contains(&got.to_string_lossy().replace('\\', "\\\\")) || sessions.contains(&*got.to_string_lossy()), "codex session not installed for {}", got.display());
}

#[test]
fn lists_both_agents_sessions_in_a_folder() {
    let sb = Sandbox::new("list");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_session(&sb, &project, "src/main.rs");
    // A Codex session in the same folder.
    let codex_project_name = project.clone();
    codex_session(&sb, &codex_project_name, "src/main.rs");
    let listed = sb.run(&project, &["list"]);
    assert!(listed.contains("Claude Code") && listed.contains(CLAUDE_ID), "{listed}");
    assert!(listed.contains("Codex") && listed.contains(CODEX_ID), "{listed}");
    assert!(listed.contains("fix the code and check .env") && listed.contains("read the code and .env"), "titles:\n{listed}");
    let only = sb.run(&project, &["list", "--agent", "codex"]);
    assert!(!only.contains(CLAUDE_ID) && only.contains(CODEX_ID), "{only}");
}

#[test]
fn across_agents_both_ways() {
    let sb = Sandbox::new("cross");
    let claude_project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_session(&sb, &claude_project, "src/main.rs");
    let codex_project = sb.project("cx", "src/a.js", "let a = 1;\n");
    codex_session(&sb, &codex_project, "src/a.js");

    let in_codex = sb.share(&claude_project, "claude-code", "to-codex", Some("codex"));
    assert_clean(&sb, &in_codex, "src/main.rs");
    assert!(Sandbox::text_under(&sb.home.join(".codex")).contains("moved here with podshare"), "claude→codex session missing");

    let in_claude = sb.share(&codex_project, "codex", "to-claude", Some("claude-code"));
    assert_clean(&sb, &in_claude, "src/a.js");
    let installed = Sandbox::text_under(&sb.home.join(".claude").join("projects").join(encode(&in_claude)));
    assert!(installed.contains("moved here with podshare"), "codex→claude session missing");

    // Shared on again, a carried-over session keeps the files it arrived with.
    let again = sb.run(&in_claude, &["pack", "--yes", "--agent", "claude-code", "--dry-run"]);
    assert!(again.contains("+ src/a.js") || again.contains("+ src\\a.js"), "re-shared session lost its files:\n{again}");
}

/// A Claude Code session in `project` that reads each of `files`, then says `says`.
fn claude_chat(sb: &Sandbox, project: &Path, files: &[&str], says: &str) {
    let cwd = project.to_string_lossy();
    let dir = sb.home.join(".claude").join("projects").join(encode(project));
    fs::create_dir_all(&dir).unwrap();
    let mut lines = vec![json!({ "type": "user", "uuid": "u0", "parentUuid": null, "cwd": cwd, "sessionId": CLAUDE_ID, "message": { "role": "user", "content": "look around" } })];
    for (i, f) in files.iter().enumerate() {
        let path = project.join(f).to_string_lossy().into_owned();
        let body = fs::read_to_string(project.join(f)).unwrap();
        lines.push(json!({ "type": "assistant", "uuid": format!("a{i}"), "cwd": cwd, "sessionId": CLAUDE_ID, "message": { "role": "assistant", "content": [{ "type": "tool_use", "id": format!("t{i}"), "name": "Read", "input": { "file_path": path } }] } }));
        lines.push(json!({ "type": "user", "uuid": format!("r{i}"), "cwd": cwd, "sessionId": CLAUDE_ID, "message": { "role": "user", "content": [{ "type": "tool_result", "tool_use_id": format!("t{i}"), "content": body }] } }));
    }
    lines.push(json!({ "type": "assistant", "uuid": "end", "cwd": cwd, "sessionId": CLAUDE_ID, "message": { "role": "assistant", "content": [{ "type": "text", "text": says }] } }));
    let body: String = lines.iter().map(|l| l.to_string() + "\n").collect();
    fs::write(dir.join(format!("{CLAUDE_ID}.jsonl")), body).unwrap();
}

#[test]
fn a_nested_repo_s_gitignore_counts() {
    let sb = Sandbox::new("nested");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    let inner = project.join("vendor/lib");
    fs::create_dir_all(&inner).unwrap();
    fs::write(inner.join(".gitignore"), "local.txt\n").unwrap();
    fs::write(inner.join("local.txt"), "private notes\n").unwrap();
    fs::write(inner.join("lib.rs"), "pub fn f() {}\n").unwrap();
    assert!(Command::new("git").args(["init", "-q"]).current_dir(&inner).status().unwrap().success());
    claude_chat(&sb, &project, &["vendor/lib/lib.rs", "vendor/lib/local.txt"], "ok");
    let plan = sb.run(&project, &["pack", "--yes", "--dry-run", "--agent", "claude-code"]);
    assert!(!plan.contains("+ vendor/lib/local.txt") && !plan.contains("+ vendor\\lib\\local.txt"), "{plan}");
    assert!(plan.contains("lib.rs"), "{plan}");
}

#[test]
fn exclude_paths_are_relative_to_where_you_are() {
    let sb = Sandbox::new("exclude");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    fs::write(project.join("src/notes.md"), "draft\n").unwrap();
    claude_chat(&sb, &project, &["src/main.rs", "src/notes.md"], "ok");
    let plan = sb.run(&project.join("src"), &["pack", "--yes", "--dry-run", "--agent", "claude-code", "--session", CLAUDE_ID, "--exclude", "notes.md"]);
    assert!(plan.contains("main.rs") && !plan.contains("+ src/notes.md") && !plan.contains("+ src\\notes.md"), "{plan}");
}

#[test]
fn a_secret_quoted_from_a_redacted_file_is_redacted_too() {
    let sb = Sandbox::new("quoted");
    let project = sb.project("app", "db.js", "const password = \"S3cretPass!42\";\n");
    claude_chat(&sb, &project, &["db.js"], "I see the password S3cretPass!42 in db.js.");
    let got = sb.share(&project, "claude-code", "friend", None);
    assert!(got.join("db.js").is_file());
    let everything = Sandbox::text_under(&sb.root.join("friend")) + &Sandbox::text_under(&sb.home.join(".claude"));
    assert!(!everything.contains("S3cretPass!42"), "the quoted secret leaked");
}

#[test]
fn received_skills_can_t_grant_tools_and_other_agents_settings_stay_home() {
    let sb = Sandbox::new("skills");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    let skill = project.join(".claude/skills/ship/SKILL.md");
    fs::create_dir_all(skill.parent().unwrap()).unwrap();
    fs::write(&skill, "---\nname: ship\nallowed-tools: Bash\n---\nShip it.\n").unwrap();
    fs::create_dir_all(project.join(".codex")).unwrap();
    fs::write(project.join(".codex/config.toml"), "[mcp_servers.x]\ncommand = \"x\"\n").unwrap();
    claude_chat(&sb, &project, &["src/main.rs", ".codex/config.toml"], "ok");
    let got = sb.share(&project, "claude-code", "friend", None);
    let received = fs::read_to_string(got.join(".claude/skills/ship/SKILL.md")).unwrap();
    assert!(received.contains("Ship it.") && !received.contains("allowed-tools"), "{received}");
    assert!(!got.join(".codex").exists(), "another agent's settings were sent");
}

#[test]
fn without_git_it_refuses_rather_than_guess_what_is_ignored() {
    let sb = Sandbox::new("nogit");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_chat(&sb, &project, &["src/main.rs"], "ok");
    let empty = sb.root.join("empty-path");
    fs::create_dir_all(&empty).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_podshare"))
        .args(["pack", "--yes", "--dry-run", "--agent", "claude-code"])
        .current_dir(&project)
        .env("HOME", &sb.home)
        .env("USERPROFILE", &sb.home)
        .env("PATH", &empty)
        .env_remove("PWD")
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && text.contains("git isn't installed"), "{text}");
}

#[test]
fn large_files_stay_out_unless_allowed() {
    let sb = Sandbox::new("large");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    fs::write(project.join("data.csv"), "a,b\n".repeat(3 << 20)).unwrap();
    claude_chat(&sb, &project, &["src/main.rs"], "ok");
    // The chat read it with a command, so it's judged as a file the call named.
    let dir = sb.home.join(".claude").join("projects").join(encode(&project));
    let session = dir.join(format!("{CLAUDE_ID}.jsonl"));
    let mut body = fs::read_to_string(&session).unwrap();
    body += &json!({ "type": "assistant", "uuid": "big", "cwd": project.to_string_lossy(), "sessionId": CLAUDE_ID, "message": { "role": "assistant", "content": [{ "type": "tool_use", "id": "tb", "name": "Read", "input": { "file_path": project.join("data.csv").to_string_lossy() } }] } }).to_string();
    body.push('\n');
    fs::write(&session, body).unwrap();
    let out = sb.run(&project, &["pack", "--yes", "--dry-run", "--agent", "claude-code"]);
    assert!(out.contains("data.csv (over 10 MB)") && !out.contains("+ data.csv"), "{out}");
    let out = sb.run(&project, &["pack", "--yes", "--dry-run", "--agent", "claude-code", "--allow", "large-files"]);
    assert!(out.contains("+ data.csv"), "{out}");
}

#[test]
fn a_taken_folder_gets_a_new_name_instead_of_failing() {
    let sb = Sandbox::new("taken");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_session(&sb, &project, "src/main.rs");
    let pod = sb.root.join("p.pod");
    let packed = sb.run(&project, &["pack", "--yes", "--agent", "claude-code", "-o", pod.to_str().unwrap()]);
    let line = packed.lines().find_map(|l| l.trim().strip_prefix("podshare open ")).unwrap().trim_matches('\'').to_string();
    let friend = sb.root.join("friend");
    fs::create_dir_all(friend.join("app")).unwrap();
    fs::write(friend.join("app/mine.txt"), "theirs\n").unwrap();
    let out = sb.run(&friend, &["open", &line, "--yes", "--no-launch"]);
    assert!(friend.join("app-2/src/main.rs").is_file(), "{out}");
    assert_eq!(fs::read_to_string(friend.join("app/mine.txt")).unwrap(), "theirs\n");
}

#[test]
fn skills_the_chat_used_go_along_unless_the_sender_says_no() {
    let sb = Sandbox::new("skills-used");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    let skill = sb.home.join(".claude/skills/deploy");
    fs::create_dir_all(skill.join("scripts")).unwrap();
    fs::write(skill.join("SKILL.md"), "---\nname: deploy\ndescription: ships it\nallowed-tools: Bash\n---\nRun scripts/ship.sh.\n").unwrap();
    fs::write(skill.join("scripts/ship.sh"), "echo shipping\n").unwrap();
    fs::write(skill.join("scripts/keys.txt"), "AKIAIOSFODNN7EXAMPLF\n").unwrap();
    claude_chat(&sb, &project, &["src/main.rs"], "ok");
    // Claude Code announces a loaded skill in a hidden message.
    let session = sb.home.join(".claude/projects").join(encode(&project)).join(format!("{CLAUDE_ID}.jsonl"));
    let mut body = fs::read_to_string(&session).unwrap();
    body += &json!({ "type": "user", "isMeta": true, "uuid": "sk", "cwd": project.to_string_lossy(), "sessionId": CLAUDE_ID,
        "message": { "role": "user", "content": [{ "type": "text", "text": format!("Base directory for this skill: {}\n\nRun scripts/ship.sh.", skill.display()) }] } }).to_string();
    body.push('\n');
    fs::write(&session, body).unwrap();

    let plan = sb.run(&project, &["pack", "--yes", "--dry-run", "--agent", "claude-code", "--no-skills"]);
    assert!(plan.contains("from your own setup: deploy (left out"), "{plan}");
    assert!(!plan.contains("+ .claude/skills/deploy") && !plan.contains("+ .claude\\skills\\deploy"), "{plan}");

    let pod = sb.root.join("s.pod");
    let packed = sb.run(&project, &["pack", "--yes", "--agent", "claude-code", "-o", pod.to_str().unwrap()]);
    assert!(packed.contains("from your own setup: deploy (included"), "{packed}");
    let line = packed.lines().find_map(|l| l.trim().strip_prefix("podshare open ")).unwrap().trim_matches('\'').to_string();
    let friend = sb.root.join("friend");
    fs::create_dir_all(&friend).unwrap();
    sb.run(&friend, &["open", &line, "--yes", "--no-launch", "--agent", "codex"]);
    let got = friend.join("app");
    for dir in [".claude/skills/deploy", ".agents/skills/deploy"] {
        let md = fs::read_to_string(got.join(dir).join("SKILL.md")).unwrap_or_else(|_| panic!("{dir} missing"));
        assert!(md.contains("Run scripts/ship.sh") && !md.contains("allowed-tools"), "{md}");
    }
    assert!(got.join(".claude/skills/deploy/scripts/ship.sh").is_file());
    assert!(!got.join(".claude/skills/deploy/scripts/keys.txt").exists(), "a file with a key was sent");
}

#[test]
fn codex_project_skills_travel_and_land_where_claude_looks() {
    let sb = Sandbox::new("agents-skills");
    let project = sb.project("cx", "src/a.js", "let a = 1;\n");
    fs::create_dir_all(project.join(".agents/skills/lint")).unwrap();
    fs::write(project.join(".agents/skills/lint/SKILL.md"), "---\nname: lint\ndescription: lints\n---\nRun the linter.\n").unwrap();
    codex_session(&sb, &project, "src/a.js");
    let got = sb.share(&project, "codex", "friend", Some("claude-code"));
    assert!(got.join(".agents/skills/lint/SKILL.md").is_file());
    assert!(fs::read_to_string(got.join(".claude/skills/lint/SKILL.md")).unwrap().contains("Run the linter."));
}

#[test]
fn the_receiver_hears_which_connected_tools_the_chat_used() {
    let sb = Sandbox::new("mcp");
    let project = sb.project("app", "src/main.rs", "fn main() {}\n");
    claude_chat(&sb, &project, &["src/main.rs"], "ok");
    let session = sb.home.join(".claude/projects").join(encode(&project)).join(format!("{CLAUDE_ID}.jsonl"));
    let mut body = fs::read_to_string(&session).unwrap();
    body += &json!({ "type": "assistant", "uuid": "m1", "cwd": project.to_string_lossy(), "sessionId": CLAUDE_ID,
        "message": { "role": "assistant", "content": [{ "type": "tool_use", "id": "tm", "name": "mcp__github__search", "input": { "q": "x" } }] } }).to_string();
    body.push('\n');
    fs::write(&session, body).unwrap();
    let pod = sb.root.join("m.pod");
    let packed = sb.run(&project, &["pack", "--yes", "--agent", "claude-code", "-o", pod.to_str().unwrap()]);
    assert!(packed.contains("connected tools (MCP) this chat used: github"), "{packed}");
    let line = packed.lines().find_map(|l| l.trim().strip_prefix("podshare open ")).unwrap().trim_matches('\'').to_string();
    let friend = sb.root.join("friend");
    fs::create_dir_all(&friend).unwrap();
    let opened = sb.run(&friend, &["open", &line, "--yes", "--no-launch"]);
    assert!(opened.contains("connected tools (MCP) that don't come along: github"), "{opened}");
    assert!(opened.contains("may not be set up here: github"), "resume note: {opened}");
}
