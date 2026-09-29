---
name: receive
description: Receive a coding-agent chat someone is sending with podshare, given a code like 7-crossover-clockwork, and unpack it so it can be resumed in Claude Code or Codex.
argument-hint: <code>
allowed-tools: Bash(podshare receive *)
---

Receive the podshare session with the code the user gave (`$ARGUMENTS`). If `podshare` isn't installed,
stop and tell the user to install it: `brew install noclipper/tap/podshare` or `npm install -g podshare`, or see
https://github.com/noclipper/podshare#install.

Running it here accepts the session without the "Incoming… Accept?" preview. Say so
first; if the user wants to see what's coming before accepting, they can run
`podshare receive $ARGUMENTS` in a terminal themselves instead.

1. Run `podshare receive $ARGUMENTS --yes --no-launch` (in Codex, ask to run it with
   network access; it downloads over the internet). It unpacks into a new folder
   named after the project, inside the current folder. If the user wants to continue in a
   different agent than the sender used, add `--agent codex` or `--agent claude-code`.

2. Show the user what it printed, in particular:
   - the files listed under "These files steer the agent" (instructions and skills
     that will shape the resumed agent) — suggest they read them if they don't know
     the sender well;
   - any "sender turned off these safety filters" line.

3. Give them the `resume with:` command exactly as printed, to run in a new terminal.
   It starts in plan mode (read-only in Codex): the agent can read the files but
   changes nothing until they approve.

If the code is rejected, say so plainly: codes work once, so the sender needs to run
`/podshare:share` (or `podshare send`) again for a new one.
