---
name: share
description: Share this coding-agent chat (Claude Code or Codex), with the files it used, as an encrypted pod someone else can resume. Use when the user asks to share, send, hand off or pass on this session or conversation.
allowed-tools: Bash(podshare send *)
---

Share this chat with podshare. If `podshare` isn't installed, stop and tell the user
to install it: `brew install noclipper/tap/podshare` or `npm install -g podshare`, or see
https://github.com/noclipper/podshare#install.

Which chat this is:
- In Claude Code: `--agent claude-code --session ${CLAUDE_SESSION_ID}`
- In Codex: `--agent codex --session "$CODEX_THREAD_ID"`

Below, SESSION means the flags for your agent. Run the commands in the project folder.

1. Preview what would be sent:

   `podshare send SESSION --dry-run`

   Show the user the summary as printed: the files going in, what is left out and why,
   and every warning (`!` lines, "filters OFF"). Don't soften or drop warnings.

2. Ask the user whether to send it, with these choices: send it now, leave some files
   out first, or cancel. To leave files out, re-run the preview with
   `--exclude <path>` for each file and show it again. If files were left out for
   being over 10 MB, ask whether to include them; if yes, add `--allow large-files`.
   If the preview lists "skills this chat used from your own setup", mention that they go
   along; if the user doesn't want that, add `--no-skills`.

3. Send it. It needs the network and keeps running until the other person connects,
   so in Codex ask to run it with network access, and don't wait for it to finish:

   `podshare send SESSION --yes` plus any `--exclude`, `--allow large-files` or
   `--no-skills` flags.
   In Claude Code, run it with `run_in_background: true`.

   As soon as the line `podshare receive <code>` appears, give the user that exact
   line to pass on. Tell them:
   - the code works once, and only while this keeps running, so keep this session
     open until they have received it;
   - the other person needs podshare installed too, and runs that line in a terminal.

4. When the command ends, say whether it was sent or what went wrong.

Never add `--allow` for any other filter (they're safety filters) unless the user asks
for it by name, and then say what that filter protects.
