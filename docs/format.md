# The pod format

A `.pod` file is `POD1` + a 24-byte nonce + an XChaCha20-Poly1305 ciphertext. The
32-byte key travels separately: after `#k=` in the open line (base64url, no padding),
or inside the wormhole for `podshare send`. The plaintext is a zstd-compressed tar:

| Entry | What it holds |
|---|---|
| `manifest.json` | what the pod is (below) |
| `transcript.jsonl` | the cleaned session in the source agent's own format, for resuming in that agent |
| `conversation.jsonl` | the same conversation in the neutral format (below), for any agent |
| `files/<path>` | the project files, relative to the project root |

Only regular files are allowed. Paths with `..`, absolute paths, links and agent or tool
configuration (`.claude/` except `.claude/skills/`, `.mcp.json`, `.envrc`, `.git/`,
`.vscode/`, `.husky/`, `.githooks/`, `.devcontainer/`, and other agents' folders like
`.codex/`, `.gemini/`, `.cursor/`) are refused on open. `allowed-tools` is removed from
received skills.

## manifest.json

```json
{
  "format": 2,
  "agent": "claude-code",
  "agent_version": "2.1.283",
  "name": "myapp",
  "session": "56b3cd4f-…",
  "messages": 79,
  "tokens": 42300,
  "instructions": ["CLAUDE.md", "AGENTS.md"],
  "skills": [".claude/skills/…/SKILL.md"],
  "filters_off": [],
  "files_left_out_by_sender": 0
}
```

`agent` names the adapter that wrote `transcript.jsonl`: `claude-code` or `codex`. To continue
in a different agent, podshare builds that agent's session from `conversation.jsonl` instead:
messages carry over as they are, and each tool call becomes a line of text (`▸ ran \`npm test\``)
followed by its result, trimmed to 2,000 characters. A receiver resumes natively when
it has that adapter, and otherwise imports `conversation.jsonl`.

## conversation.jsonl

One JSON object per line, in order. Everything in it has already been cleaned:
withheld calls read `[withheld by podshare …]`, secrets `[REDACTED:<rule>]`, and the
project folder is the placeholder `{{POD_ROOT}}`.

```json
{"role": "user", "type": "text", "text": "fix the bug in src/sum.js"}
{"role": "assistant", "type": "text", "text": "Reading it."}
{"role": "assistant", "type": "tool_call", "id": "t1", "tool": "read_file", "name": "Read", "input": {"file_path": "{{POD_ROOT}}/src/sum.js"}}
{"role": "tool", "type": "tool_result", "id": "t1", "content": "…", "is_error": false}
{"type": "summary", "text": "Summary of the conversation so far …"}
```

`tool` is the kind of tool, whatever the agent called it:

| `tool` | Meaning |
|---|---|
| `read_file` | read one file |
| `write_file` | created or replaced a file |
| `edit_file` | changed part of a file |
| `shell` | ran a shell command |
| `search` | searched file contents |
| `list_files` | listed or globbed files |
| `subagent` | delegated to another agent, which returned a summary |
| `web` | fetched or searched the web |
| `connected_tool` | an external (MCP) tool |
| `other` | anything else; `name` says what |

`name` and `input` are the agent's own, so an adapter for the same agent loses nothing.
`summary` lines mark where the agent compacted earlier history.
