//! The agents podshare can share sessions from, each with its own adapter.

use anyhow::{anyhow, Result};
use clap::ValueEnum;
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::convert::Turn;
use crate::filters::Filters;
use crate::session::{Cleaned, Identity, Subagent, Touch};
use crate::{claude_code, codex};

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Agent {
    ClaudeCode,
    Codex,
}

const ALL: [Agent; 2] = [Agent::ClaudeCode, Agent::Codex];

impl Agent {
    /// The name in a pod's manifest.
    pub fn name(self) -> &'static str {
        match self {
            Agent::ClaudeCode => claude_code::AGENT,
            Agent::Codex => codex::AGENT,
        }
    }

    pub fn from_name(name: &str) -> Option<Agent> {
        ALL.into_iter().find(|a| a.name() == name)
    }

    pub fn label(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::Codex => "Codex",
        }
    }

    pub fn homepage(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "https://claude.com/claude-code",
            Agent::Codex => "https://github.com/openai/codex",
        }
    }

    /// How the resumed agent starts: it asks before changing anything.
    pub fn safe_mode(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "in plan mode",
            Agent::Codex => "read-only",
        }
    }

    fn find(self, cwd: &Path, id: Option<&str>) -> Result<(PathBuf, SystemTime)> {
        match self {
            Agent::ClaudeCode => {
                let path = claude_code::find(cwd, id)?;
                let at = fs::metadata(&path).and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                Ok((path, at))
            }
            Agent::Codex => codex::find(cwd, id),
        }
    }

    pub fn cwd(self, lines: &[Value]) -> Option<PathBuf> {
        match self {
            Agent::ClaudeCode => claude_code::cwd(lines),
            Agent::Codex => codex::cwd(lines),
        }
    }

    pub fn version(self, lines: &[Value]) -> Option<String> {
        match self {
            Agent::ClaudeCode => claude_code::version(lines),
            Agent::Codex => codex::version(lines),
        }
        .map(String::from)
    }

    pub fn touched(self, lines: &[Value]) -> Vec<Touch<'_>> {
        match self {
            Agent::ClaudeCode => claude_code::touched(lines),
            Agent::Codex => codex::touched(lines),
        }
    }

    pub fn subagents(self, session: &Path) -> Vec<Subagent> {
        match self {
            Agent::ClaudeCode => claude_code::subagents(session),
            Agent::Codex => vec![],
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn clean(
        self,
        lines: Vec<Value>,
        withhold: &HashMap<String, String>,
        root: &Path,
        home: &Path,
        identity: &Identity,
        echoes: &[String],
        filters: &Filters,
    ) -> Cleaned {
        match self {
            Agent::ClaudeCode => claude_code::clean(lines, withhold, root, home, identity, echoes, filters),
            Agent::Codex => codex::clean(lines, withhold, root, home, identity, echoes, filters),
        }
    }

    /// Roughly how many tokens the agent reads when it resumes this cleaned transcript.
    /// The MCP servers (connected tools) the chat called. Only their names: their setup
    /// runs programs and holds logins, so it never travels.
    pub fn mcp_servers(self, lines: &[Value]) -> Vec<String> {
        let names = match self {
            Agent::ClaudeCode => claude_code::mcp_servers(lines),
            Agent::Codex => codex::mcp_servers(lines),
        };
        let mut names: Vec<String> = names
            .into_iter()
            .map(|n| n.chars().filter(|c| c.is_ascii_alphanumeric() || "_-.".contains(*c)).take(60).collect::<String>())
            .filter(|n| !n.is_empty())
            .collect();
        names.sort();
        names.dedup();
        names
    }

    pub fn estimate_tokens(self, lines: &[Value]) -> usize {
        match self {
            Agent::ClaudeCode => claude_code::estimate_tokens(lines),
            Agent::Codex => codex::estimate_tokens(lines),
        }
    }

    /// Tokens this agent's models spend on `chars` characters of session text.
    pub fn text_tokens(self, chars: usize) -> usize {
        match self {
            Agent::ClaudeCode => claude_code::text_tokens(chars),
            Agent::Codex => codex::text_tokens(chars),
        }
    }

    pub fn to_neutral(self, lines: &[Value]) -> Vec<Value> {
        match self {
            Agent::ClaudeCode => claude_code::to_neutral(lines),
            Agent::Codex => codex::to_neutral(lines),
        }
    }

    /// A received transcript made ready to resume in `dir`: its new session id and content.
    pub fn prepare(self, transcript: &[u8], dir: &Path, note: &str) -> Result<(String, String)> {
        match self {
            Agent::ClaudeCode => claude_code::prepare(transcript, dir),
            Agent::Codex => codex::prepare(transcript, dir, note),
        }
    }

    /// A session of this agent holding a conversation carried over from another agent.
    pub fn from_turns(self, turns: &[Turn], dir: &Path, note: &str) -> (String, String) {
        match self {
            Agent::ClaudeCode => claude_code::from_turns(turns, dir),
            Agent::Codex => codex::from_turns(turns, dir, note),
        }
    }

    /// The program that runs this agent.
    pub fn program(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "claude",
            Agent::Codex => "codex",
        }
    }

    /// The other agent podshare supports.
    pub fn other(self) -> Agent {
        match self {
            Agent::ClaudeCode => Agent::Codex,
            Agent::Codex => Agent::ClaudeCode,
        }
    }

    pub fn install(self, dir: &Path, id: &str, transcript: &str) -> Result<()> {
        match self {
            Agent::ClaudeCode => claude_code::install(dir, id, transcript),
            Agent::Codex => codex::install(dir, id, transcript),
        }
    }

    pub fn resume_command<'a>(self, id: &'a str, note: &'a str) -> (&'static str, Vec<&'a str>) {
        match self {
            Agent::ClaudeCode => claude_code::resume_command(id, note),
            Agent::Codex => codex::resume_command(id),
        }
    }
}

/// A session found in a folder, for choosing which one to share.
pub struct Found {
    pub agent: Agent,
    pub path: PathBuf,
    pub modified: SystemTime,
    pub title: String,
}

/// Every session started in `cwd` (by `only`, or by any agent), most recent first.
pub fn list(cwd: &Path, only: Option<Agent>) -> Vec<Found> {
    let mut found: Vec<Found> = only
        .map_or(ALL.to_vec(), |a| vec![a])
        .into_iter()
        .flat_map(|agent| {
            let sessions = match agent {
                Agent::ClaudeCode => claude_code::list(cwd),
                Agent::Codex => codex::list(cwd),
            };
            sessions.into_iter().map(move |(path, modified, title)| Found { agent, path, modified, title })
        })
        .collect();
    found.sort_by_key(|f| std::cmp::Reverse(f.modified));
    found
}

/// The session to share: `agent`'s if given, otherwise whichever agent was used most
/// recently in `cwd`.
pub fn find(agent: Option<Agent>, cwd: &Path, id: Option<&str>) -> Result<(Agent, PathBuf)> {
    let mut found = vec![];
    let mut missed = vec![];
    for a in agent.map_or(ALL.to_vec(), |a| vec![a]) {
        match a.find(cwd, id) {
            Ok((path, at)) => found.push((at, a, path)),
            Err(e) => missed.push(e.to_string()),
        }
    }
    found.into_iter().max_by_key(|(at, _, _)| *at).map(|(_, a, p)| (a, p)).ok_or_else(|| anyhow!(missed.join("; ")))
}
