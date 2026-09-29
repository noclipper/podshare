# podshare plugin

Adds two skills to Claude Code and Codex:

- **share**: sends this chat, with the files and skills it used, to another person as an
  encrypted pod they can resume. It shows you what will be sent first and asks before sending.
- **receive**: receives a chat someone sent you, given their one-time code.

## Requirements

The skills run the podshare command-line tool, which must be installed first:
`brew install noclipper/tap/podshare`, `npm install -g podshare`, or see
https://github.com/noclipper/podshare#install.

## Where data goes

Nothing is sent until you confirm. When you do, the chat and its files are encrypted on your
machine and sent only to the person holding the one-time code, through the public Magic
Wormhole servers (relay.magic-wormhole.io and transit.magic-wormhole.io), which pass along
encrypted data they can't read. podshare keeps no copy and has no server of its own.
Secrets, `.env` files, personal folders and your identity are filtered out before sending:
https://github.com/noclipper/podshare/blob/main/docs/privacy.md

## License

FSL-1.1-ALv2 (see LICENSE.md).
