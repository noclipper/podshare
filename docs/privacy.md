# How podshare keeps things private

podshare only sends what it can check is safe. Everything else is left out, and you
see exactly what's in before anything leaves your machine.

## Files

A file is left out if it is:

- outside your project folder
- in a personal folder (like `~/Library`, `~/Pictures` or `~/.claude`)
- a secrets file (`.env`, keys, certificates, `.ssh`, `.aws`, shell history, databases)
- ignored by git
- holding an API key or private key

If a file only has a password like `password = …`, it's sent with that value blanked out.

Skills the chat used from outside your project (your own, or a plugin's) are sent too, with
the same checks as project files. They're listed before sending; untick them with `c`, or
use `--no-skills`.

## The conversation

The agent's conversation holds a copy of everything it read, so it's cleaned too:

- Anything that came from a left-out file is replaced with `[withheld by podshare]`.
- Shell commands it can't check (inline scripts, `$(…)`, tricks like `.en''v`) are withheld.
- Results from connected tools (a browser, mail) are withheld.
- Secrets it recognises are blanked, and so is the agent repeating one it read.
- Your name, email, username, computer name and home folder are replaced.
- The agent's private reasoning, pasted images, and your account IDs, usage, and permission
  or sandbox settings are removed.

## Settings you can change

All of these are on to start with. Press `f` before sending to switch any of them off:

`outside-project` · `personal-folders` · `credential-files` · `gitignored` ·
`secret-scan` · `unchecked-commands` · `connected-tools` · `emails` · `identity` ·
`pasted-images` · `large-files`

The person you send to is told if you switched any off.

## Things that are never sent

Agent settings and hooks (`.claude`, `.codex`, `.gemini`, `.cursor` and similar), MCP
server configs (only the names of the MCP servers the chat used go along, so the receiver
knows what to set up), `.envrc`, `.git`, and editor config that could run code. podshare refuses
to open a pod that contains them. Skills are shared, but a received skill can't
pre-approve tools (`allowed-tools` is removed).

## Sending

The code works once. Your pod is encrypted end to end: it goes directly to the other
person when it can, otherwise through the public Magic Wormhole relay, which can't read it.
The relay does see what any internet service sees: both of your IP addresses, when you sent,
and roughly how big the pod was. Someone trying to guess your code gets one try, and a wrong
guess ends the transfer for both of you.

## Opening a pod from someone else

- It's encrypted, and podshare checks nothing was changed on the way.
- Files can't be written outside the new folder.
- You're shown the instructions that will guide your agent before anything unpacks.
- Your agent starts in plan mode (Claude Code) or read-only (Codex): it can read the
  files but asks before changing anything.

Treat it like code from someone you don't know: read before you run it.

## What it can't catch

- Secrets with no recognisable pattern (including ones you typed into the chat), or
  ones split up or encoded.
- Binary files like images are sent as they are.
- Things the agent described in its own words without quoting.
- What a script reads when it runs.
- Personal details inside your project files. These are sent as they are, but flagged.

That's why you see the list first. Have a look before you send.
