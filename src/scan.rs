//! What counts as sensitive: secrets inside text, and paths that never leave the machine.

use regex::{Captures, Regex};
use std::borrow::Cow;
use std::ops::Range;
use std::path::Path;
use std::sync::LazyLock;

struct Rule {
    name: &'static str,
    /// A key format (AWS, PEM…) rather than a `password = …` assignment. A file with
    /// one is left out whole: keys rarely travel alone.
    strong: bool,
    re: Regex,
    /// For rules that match more than the secret (`password = hunter22`): the span to
    /// redact, or None when the value doesn't look like a secret after all.
    value: Option<fn(&Captures) -> Option<Range<usize>>>,
}

/// Whether a key name is about a secret: one of its words is `password`, `token`,
/// `secret`…, or it ends in `api key`-style pairs. Whole words only, so `passport`,
/// `bypass`, `TOKENIZER` and `max_tokens` don't count.
pub fn secret_key(name: &str) -> bool {
    let mut words: Vec<String> = vec![String::new()];
    let mut prev_lower = false;
    for c in name.chars() {
        if !c.is_ascii_alphanumeric() || (c.is_ascii_uppercase() && prev_lower) {
            words.push(String::new());
        }
        if c.is_ascii_alphanumeric() {
            words.last_mut().unwrap().push(c.to_ascii_lowercase());
        }
        prev_lower = c.is_ascii_lowercase();
    }
    words.retain(|w| !w.is_empty());
    const WORDS: &[&str] = &[
        "secret", "secrets", "token", "pass", "passwd", "password", "passphrase", "pwd", "pw", "apikey", "cookie",
        "credential", "credentials",
    ];
    const KEY_PAIRS: &[&str] = &["api", "access", "auth", "private", "signing", "secret", "client", "encryption", "master"];
    words.iter().any(|w| WORDS.contains(&w.as_str()))
        || words.windows(2).any(|p| p[1] == "key" && KEY_PAIRS.contains(&p[0].as_str()))
}

static PLACEHOLDER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:your[-_ ]?[a-z_ -]*|changeme|example|placeholder|dummy|test|todo|tbd|none|null|x{3,}|\*+|<[^>]*>|\$\{?[a-z_][a-z0-9_]*\}?|\{\{.*\}\}|%s|\.\.\.|(?:process\.env|os\.environ|env)[.\[].*|[\^~<>=]*\d+(?:\.\d+)+[-+.\w]*)$",
    )
    .unwrap()
});

/// Values that stand in for a secret rather than being one. The whole value must look
/// like a placeholder: `your-password-here` is one, `your-Pr0dPass` is not.
fn placeholder(value: &str, key: &str) -> bool {
    let v = value.trim().to_lowercase();
    v.len() < 4 || PLACEHOLDER.is_match(&v) || key.to_lowercase().contains(&v) // "password_label": "Password"
}

const TYPE_WORDS: &[&str] = &[
    "string", "str", "number", "int", "integer", "bool", "boolean", "true", "false", "null", "none", "required",
    "optional", "hidden", "text", "secret", "password", "token",
];

/// `password = …`-style assignments: any quoted value that isn't a placeholder, or an
/// unquoted one that isn't just a name (`password: string`, `token = getToken()`).
fn assigned_secret(c: &Captures) -> Option<Range<usize>> {
    let key = c.get(1)?.as_str();
    if !secret_key(key) {
        return None;
    }
    if let Some(quoted) = c.get(2).or(c.get(3)) {
        return (!placeholder(quoted.as_str(), key)).then(|| quoted.range());
    }
    let v = c.get(4)?;
    let s = v.as_str();
    let alpha = s.bytes().any(|b| b.is_ascii_alphabetic());
    let other = s.bytes().any(|b| !b.is_ascii_alphabetic() && !b"_.-".contains(&b));
    (s.len() >= 6 && alpha && other && !placeholder(s, key)).then(|| v.range())
}

/// `KEY=value` and `key: value` lines in env and config files, where the whole line is
/// the assignment: any value counts, letters-only included, unless it is a type name.
fn config_secret(c: &Captures) -> Option<Range<usize>> {
    let (key, value) = (c.get(1)?.as_str(), c.get(2)?);
    let v = value.as_str();
    (secret_key(key) && !placeholder(v, key) && !TYPE_WORDS.contains(&v.to_lowercase().as_str())).then(|| value.range())
}

fn auth_token(c: &Captures) -> Option<Range<usize>> {
    let token = c.get(2)?;
    let t = token.as_str();
    let ok = match &c[1] {
        "Bearer" => t.len() >= 16,
        _ => t.bytes().any(|b| b.is_ascii_digit() || b"=+/".contains(&b)),
    };
    ok.then(|| token.range())
}

fn group_1(c: &Captures) -> Option<Range<usize>> {
    c.get(1).map(|m| m.range())
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    let exact = |name, pat: &str| Rule { name, strong: true, re: Regex::new(pat).unwrap(), value: None };
    let inner = |name, pat: &str| Rule { name, strong: true, re: Regex::new(pat).unwrap(), value: Some(group_1) };
    vec![
        exact(
            "private-key",
            r"(?s)-----BEGIN[A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END[A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\z)",
        ),
        exact("putty-key", r"(?s)PuTTY-User-Key-File-\d+:.*?(?:Private-MAC:\s*\S+|\z)"),
        exact("aws-access-key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
        inner("aws-secret-key", r#"(?i)aws.{0,20}?(?:secret|sk).{0,20}?[:=]\s*["']?([A-Za-z0-9/+=]{40})\b"#),
        exact("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        exact("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        exact("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        exact("openai-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}"),
        exact("slack-token", r"\b(?:xox[abposre]|xapp)-[A-Za-z0-9-]{10,}"),
        exact("stripe-key", r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}"),
        exact("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}"),
        exact("google-oauth-secret", r"\bGOCSPX-[A-Za-z0-9_-]{20,}"),
        exact("gcp-service-account", r#""private_key_id"\s*:\s*"[a-f0-9]{40}""#),
        exact("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}"),
        exact("npm-token", r"\bnpm_[A-Za-z0-9]{36}"),
        exact("pypi-token", r"\bpypi-[A-Za-z0-9_-]{50,}"),
        exact("digitalocean-token", r"\bdo[por]_v1_[a-f0-9]{64}"),
        exact("vault-token", r"\bhv[sbr]\.[A-Za-z0-9_-]{20,}"),
        exact("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"),
        exact("twilio-key", r"\bSK[0-9a-fA-F]{32}\b"),
        exact("telegram-token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
        exact("discord-token", r"\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}"),
        inner("azure-key", r"(?i)AccountKey=([A-Za-z0-9+/=]{20,})"),
        exact("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        // Capitalised as in HTTP headers. A Bearer token is any long word; a Basic one must
        // look encoded, so "Basic questions" is left alone.
        Rule { strong: false, value: Some(auth_token), ..inner("auth-header", r"\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{12,})") },
        exact("url-credentials", r"\b[a-z][a-z0-9+.-]*://[^\s:/@'\x22]+:[^\s@/'\x22]+@"),
        // Whole-line assignments in env and config files (`DB_PASS=letmein`, `password: zebrafish`).
        Rule {
            name: "config-secret",
            strong: false,
            re: Regex::new(r#"(?m)^[ \t]*(?:export[ \t]+)?([\w.-]+)[ \t]*[:=][ \t]*["']?([^\s"'#]{4,})["']?[ \t]*$"#).unwrap(),
            value: Some(config_secret),
        },
        Rule {
            name: "secret-assignment",
            strong: false,
            re: Regex::new(
                r#"(?i)([\w.-]*(?:secret|token|pass|pwd|pw|key|cookie|credential)[\w.-]*)["']?\s*(?:=>|[:=,])\s*(?:"([^"\n]*)"|'([^'\n]*)'|([^\s"',;(){}\[\]<>]+))"#,
            )
            .unwrap(),
            value: Some(assigned_secret),
        },
    ]
});

/// Name of the first secret rule that fires anywhere in `text`.
pub fn find_secret(text: &str) -> Option<&'static str> {
    first_hit(text, false)
}

/// Name of the first key-format rule (not a mere assignment) that fires in `text`.
pub fn find_key(text: &str) -> Option<&'static str> {
    first_hit(text, true)
}

fn first_hit(text: &str, strong_only: bool) -> Option<&'static str> {
    RULES
        .iter()
        .filter(|r| r.strong || !strong_only)
        .find(|r| match r.value {
            None => r.re.is_match(text),
            Some(value) => r.re.captures_iter(text).any(|c| value(&c).is_some()),
        })
        .map(|r| r.name)
}

static VALUE_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?m)^[ \t]*(?:export[ \t]+)?["']?[\w.-]+["']?[ \t]*[:=][ \t]*["']?([^\s"'#,]{8,})"#).unwrap()
});

/// Values in text that was withheld as sensitive (the right side of `KEY=value` lines,
/// and anything a key rule matches), so the same strings can be redacted wherever the
/// agent repeated them. Paths and plain words are left out: redacting them everywhere
/// would break the transcript.
pub fn secret_values(text: &str) -> Vec<String> {
    let assigned = VALUE_LINE.captures_iter(text).map(|c| c[1].to_string());
    let keys = RULES.iter().filter(|r| r.strong).flat_map(|r| r.re.find_iter(text).map(|m| m.as_str().to_string()));
    assigned
        .chain(keys)
        .filter(|v| {
            let mixed = v.chars().any(|c| c.is_ascii_digit()) || v.chars().any(|c| !c.is_alphanumeric());
            mixed && !v.chars().all(|c| c.is_ascii_digit() || c == '.') && !v.starts_with(['/', '~', '.']) && !v.contains("://")
        })
        .collect()
}

/// Replaces every secret in `text` with `[REDACTED:<rule>]` and counts them.
pub fn redact(text: &str) -> (String, usize) {
    let mut found = vec![];
    let out = redact_into(text, &mut found);
    (out, found.len())
}

/// The values `redact` would blank in `text`.
pub fn redacted_values(text: &str) -> Vec<String> {
    let mut found = vec![];
    redact_into(text, &mut found);
    found
}

fn redact_into(text: &str, found: &mut Vec<String>) -> String {
    let mut out = text.to_string();
    for r in RULES.iter() {
        if !r.re.is_match(&out) {
            continue;
        }
        out = r
            .re
            .replace_all(&out, |c: &Captures| {
                let all = c.get(0).unwrap();
                let span = match r.value {
                    None => Some(all.range()),
                    Some(value) => value(c),
                };
                match span {
                    None => all.as_str().to_string(),
                    Some(s) => {
                        let (start, end) = (s.start - all.start(), s.end - all.start());
                        found.push(all.as_str()[start..end].to_string());
                        format!("{}[REDACTED:{}]{}", &all.as_str()[..start], r.name, &all.as_str()[end..])
                    }
                }
            })
            .into_owned();
    }
    out
}

/// Text content of a file for scanning: UTF-16 when it has a byte-order mark, else
/// lossy UTF-8, so binary files are scanned too.
/// Whether bytes look like UTF-16 text: a byte-order mark, or a zero in every other byte.
pub fn is_utf16(bytes: &[u8]) -> bool {
    let head = &bytes[..bytes.len().min(512)];
    let zeros_at = |odd: usize| head.iter().skip(odd).step_by(2).filter(|&&b| b == 0).count() * 10 >= head.len() / 2 * 9;
    bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) || (head.len() >= 8 && (zeros_at(0) || zeros_at(1)))
}

pub fn text_of(bytes: &[u8]) -> Cow<'_, str> {
    let utf16 = |be: bool, skip: usize| {
        let units = bytes[skip..].chunks_exact(2).map(|p| if be { u16::from_be_bytes([p[0], p[1]]) } else { u16::from_le_bytes([p[0], p[1]]) });
        Cow::Owned(char::decode_utf16(units).map(|c| c.unwrap_or('\u{FFFD}')).collect())
    };
    // Without a byte-order mark, UTF-16 text shows as a zero in every other byte.
    let head = &bytes[..bytes.len().min(512)];
    let zeros_at = |odd: usize| head.iter().skip(odd).step_by(2).filter(|&&b| b == 0).count() * 10 >= head.len() / 2 * 9;
    match bytes {
        [0xFF, 0xFE, ..] => utf16(false, 2),
        [0xFE, 0xFF, ..] => utf16(true, 2),
        _ if head.len() >= 8 && zeros_at(1) => utf16(false, 0),
        _ if head.len() >= 8 && zeros_at(0) => utf16(true, 0),
        _ => String::from_utf8_lossy(bytes),
    }
}

static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+(?:@|%40)([A-Za-z0-9-]+)(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b").unwrap());
static RETINA: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+x$").unwrap());

/// Replaces email addresses with `[email]` and counts them. Leaves `git@host` remotes,
/// `noreply@` addresses and image names like `icon@2x.png` alone.
pub fn mask_emails(text: &str) -> (String, usize) {
    if !text.contains('@') && !text.contains("%40") {
        return (text.to_string(), 0);
    }
    let mut n = 0;
    let out = EMAIL
        .replace_all(text, |c: &Captures| {
            let m = &c[0];
            if m.starts_with("git@") || m.starts_with("noreply@") || RETINA.is_match(&c[1]) {
                m.to_string()
            } else {
                n += 1;
                "[email]".to_string()
            }
        })
        .into_owned();
    (out, n)
}

const DENIED_DIRS: &[&str] = &[".ssh", ".aws", ".azure", ".gnupg", ".kube", ".docker", ".password-store"];
const DENIED_NAMES: &[&str] = &[
    ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".htpasswd", ".pgpass", ".vault-token", "credentials",
    "credentials.json", "credentials.toml", "kubeconfig", "secrets.json", "secrets.yaml", "secrets.yml",
    "secrets.toml", "service-account.json", "claude.local.md",
];
/// Files that would run code or reconfigure the agent on the receiver's machine.
const EXECUTABLE_CONFIG: &[&str] = &[".envrc", ".mcp.json"];
const DENIED_EXTS: &[&str] = &[
    "pem", "key", "p8", "p12", "pfx", "jks", "keystore", "ppk", "asc", "gpg", "age", "kdbx", "keychain",
    "keychain-db", "ovpn", "tfstate", "sqlite", "sqlite3", "db",
];

/// Why a file would configure or run code in the receiver's agent. Never shared,
/// never accepted, whatever the filters say.
pub fn agent_config(path: &Path) -> Option<&'static str> {
    let parts: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect();
    for (i, part) in parts.iter().enumerate() {
        if part == ".claude" && parts.get(i + 1).map(String::as_str) != Some("skills") {
            return Some("agent settings (hooks, permissions)");
        }
        if part == ".git" {
            return Some("git internals (hooks run code)");
        }
        if part == ".podshare" {
            return Some("podshare's own records");
        }
        if [".vscode", ".husky", ".githooks", ".devcontainer"].contains(&part.as_str()) {
            return Some("editor or git-hook config that runs code");
        }
        // Other agents' project settings can start tools (MCP servers) or change permissions.
        if [".codex", ".gemini", ".cursor", ".continue", ".zed", ".windsurf", ".roo", ".cline", ".kiro", ".amazonq", ".aider"].contains(&part.as_str())
            || part.starts_with(".aider.")
        {
            return Some("agent settings (tools, permissions)");
        }
    }
    EXECUTABLE_CONFIG.contains(&parts.last()?.as_str()).then_some("config that runs code on open")
}

/// Why a file looks like a credential, key, history or private data store, by its path alone.
pub fn credential_path(path: &Path) -> Option<&'static str> {
    let parts: Vec<String> = path.components().map(|c| c.as_os_str().to_string_lossy().to_lowercase()).collect();
    if parts.iter().any(|p| DENIED_DIRS.contains(&p.as_str())) {
        return Some("credential directory");
    }
    let name = parts.last()?;
    let ext = name.rsplit_once('.').map_or("", |(_, e)| e);
    let example = ["example", "sample", "template"].contains(&ext);
    if name == ".env" || ext == "env" || (name.starts_with(".env") && !example) {
        return Some("environment file");
    }
    if ["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"].iter().any(|k| name.starts_with(k)) {
        return Some("SSH key");
    }
    if name.ends_with("_history") || name.ends_with(".tfstate.backup") {
        return Some("history or state file");
    }
    if DENIED_NAMES.contains(&name.as_str()) || DENIED_EXTS.contains(&ext) {
        return Some("key, credential or database file");
    }
    None
}

/// Personal folders in the home directory that a shared session must never reach into.
pub fn denied_personal(path: &Path, home: &Path) -> Option<&'static str> {
    // The agents' own folders, wherever they were moved (they hold logins and chats).
    let moved = ["CODEX_HOME", "CLAUDE_CONFIG_DIR"].iter().filter_map(std::env::var_os).filter(|d| !d.is_empty());
    if moved.map(std::path::PathBuf::from).any(|d| path.starts_with(&d)) {
        return Some("personal folder in the home directory");
    }
    let first = path.strip_prefix(home).ok()?.components().next()?;
    matches!(
        first.as_os_str().to_str()?.to_lowercase().as_str(),
        "library" | "pictures" | "movies" | "music" | "appdata" | ".claude" | ".codex" | ".config" | ".local" | ".cursor" | ".ssh"
            | ".aws" | ".azure" | ".gnupg" | ".kube" | ".docker" | ".password-store"
    )
    .then_some("personal folder in the home directory")
}

static SENSITIVE_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\.env\b|\.ssh|\.aws|\.azure|\.gnupg|\bid_(?:rsa|ed25519|ecdsa|dsa)|(?:^|[\s/'\x22])(?:secrets?|credentials?)(?:\.[a-z]+|/)|\.netrc|\.npmrc|\.pypirc|_history\b|keychain|security\s+find-|\bprintenv\b|(?:^|[|;&]\s*)(?:env|set|export)\s*(?:$|[|;&])|git\s+show\s+\S*:|\$\{?HOME\b|\$\{?[A-Z_]*(?:KEY|TOKEN|SECRET|PASS)|\$env:|\benv:|%(?:USERPROFILE|APPDATA|HOMEPATH|[A-Z_]*(?:KEY|TOKEN|SECRET|PASS)[A-Z_]*)%",
    )
    .unwrap()
});

/// Whether a shell command looks like it reads credentials, history or the environment.
pub fn sensitive_command(cmd: &str) -> bool {
    SENSITIVE_COMMAND.is_match(cmd)
}

static QUOTED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"'[^']*'|"(?:[^"\\]|\\.)*""#).unwrap());
static OPAQUE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\$\(|`|\beval\b",                                             // substitution, eval
        r"|\bxargs\b|\s-exec(?:dir)?\b|\btar\b[^|;&]*\s-?[a-zA-Z]*O",           // reads a list of files
        r"|\b(?:grep|rg|ag)\b[^|;&]*\s(?:-[a-zA-Z]*h[a-zA-Z]*|--no-filename)\b", // search output without file names
        r"|\b(?:python\d*(?:\.\d+)?|node|deno|bun|ruby|perl|php|bash|sh|zsh|osascript)\s+-[ce]\b", // inline code
        r"|(?i:\b(?:powershell|pwsh)(?:\.exe)?\s+-(?:c|command|e|enc|encodedcommand)\b|\biex\b|invoke-expression|\bcmd(?:\.exe)?\s+/[ck]\b)", // Windows
        r"|(?:^|\s)\.[^\s]*[?*\[]",                                         // globs over hidden files
        r"|\S\\\S",                                                     // backslash inside a word
    ))
    .unwrap()
});
static GLUED_QUOTES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"\S(?:''|"")|(?:''|"")\S|\S['"][^'"\s]*['"]\S"#).unwrap());

/// Whether a shell command's reads can't be read off its text: inline scripts, command
/// substitution, globs over hidden files, or names spelled in pieces (`.en''v`).
pub fn opaque_command(cmd: &str) -> bool {
    // A heredoc is a script unless it only feeds `cat` or `tee` to write a file.
    let script_heredoc = cmd.match_indices("<<").any(|(i, _)| {
        let segment = cmd[..i].rsplit(['|', ';', '&', '\n']).next().unwrap_or("").trim_start();
        !(segment.starts_with("cat") || segment.starts_with("tee"))
    });
    script_heredoc || GLUED_QUOTES.is_match(cmd) || OPAQUE.is_match(&QUOTED.replace_all(cmd, "''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_redacts_known_key_formats() {
        let aws = format!("AKIA{}", "Q7".repeat(8));
        let text = format!("export KEY_ID={aws} # prod");
        assert!(find_secret(&text).is_some());
        let (out, n) = redact(&text);
        assert!(n >= 1 && !out.contains(&aws), "{out}");
        for secret in [
            format!("glpat-{}", "x".repeat(20)),
            format!("GOCSPX-{}", "y".repeat(24)),
            format!("hvs.{}", "Z".repeat(24)),
            format!("Authorization: Bearer {}", "abc123".repeat(4)),
            "Authorization: Bearer mkletteronlytokenvalue".to_string(),
            "Authorization: Basic dXNlcjpodW50ZXIy".to_string(),
            format!("DefaultEndpointsProtocol=https;AccountKey={}==", "k".repeat(40)),
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nxyz".to_string(),
        ] {
            assert!(find_secret(&secret).is_some(), "{secret}");
        }
    }

    #[test]
    fn assignment_rules_catch_secrets_but_not_code() {
        for s in [
            "DB_PASSWORD=hunter22",
            "DB_PASS=letmein",
            "SIGNING_KEY=abcdef",
            r#"define('DB_PASSWORD', 'correct horse');"#,
            r#"'password' => 'swordfish'"#,
            r#"{"password": "hunteraaa"}"#,
            "password: zebrafish",
            "password=mkletterpass",
            "DB_PASS=Example2024!",
            "API_KEY=changeme_Xk29",
            "PASSWORD=your-Pr0dPass",
            r#"connect(pw="hunter2xx")"#,
            r#"password = "2024secretPass""#,
            r#"csrfToken: "a8f5f167f44f4964e6c998dee827110c""#,
        ] {
            assert!(find_secret(s).is_some(), "{s}");
        }
        for s in [
            "password: string",
            "const token = getToken();",
            "max_tokens = 4096",
            "passes = 100000",
            r#""password": {"type": "string"}"#,
            r#""passport": "^0.6.0""#,
            r#""token-types": "^5.0.1""#,
            r#""password_label": "Password""#,
            r#"TOKENIZER = "bert-base""#,
            r#"let bypass = "always";"#,
            r#"password: "your-password-here""#,
            "api_key: ${API_KEY}",
            "Use it for basic arithmetic questions and simple edits.",
        ] {
            assert_eq!(find_secret(s), None, "{s}");
        }
        assert_eq!(redact("DB_PASSWORD=hunter22").0, "DB_PASSWORD=[REDACTED:config-secret]");
    }

    #[test]
    fn learns_secret_values_but_not_paths_or_words() {
        let env = "DB_HOST=db.internal.shop\nDB_PASSWORD=hunter2Zebra99\nNODE_ENV=production\nHOME=/Users/me\nPORT=8080\n";
        assert_eq!(secret_values(env), vec!["db.internal.shop", "hunter2Zebra99"]);
    }

    #[test]
    fn redacts_whole_private_key_blocks() {
        let text = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----\nafter";
        assert_eq!(redact(text).0, "before\n[REDACTED:private-key]\nafter");
    }

    #[test]
    fn scans_utf16_files_with_or_without_a_bom() {
        let text = "$password = 'hunter22xx'";
        let le: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let with_bom: Vec<u8> = [0xFF, 0xFE].into_iter().chain(le.iter().copied()).collect();
        assert!(find_secret(&text_of(&with_bom)).is_some());
        assert!(find_secret(&text_of(&le)).is_some());
    }

    #[test]
    fn flags_shell_commands_that_hide_what_they_read() {
        for c in [
            "cat .en''v.production",
            r#"cat ".e""nv""#,
            "cat .en?",
            "cat .[e]nv",
            r"cat .e\nv",
            "cat $(ls -a | grep nv)",
            "python3 -c \"open('.'+'env')\"",
            "python3 - <<'EOF'\nprint(1)\nEOF",
            "ls -a | xargs cat",
            "find . -name '*nv' -exec cat {} +",
            "tar cf - . | tar xOf -",
            "grep -rh '' .",
            "powershell -Command \"Get-Content x\"",
            "iex (Get-Content run.ps1 -Raw)",
            "cmd /c type x",
        ] {
            assert!(opaque_command(c), "{c}");
        }
        for c in [
            "cargo test",
            "ls -la src",
            r#"grep -n "foo[0-9]?" src/*.rs"#,
            "git commit -m 'a b'",
            r"cat My\ Notes.txt",
            "cat <<'EOF' > src/new.rs\nfn a() {}\nEOF",
            "grep -rn TODO src",
        ] {
            assert!(!opaque_command(c), "{c}");
        }
    }

    #[test]
    fn masks_emails_but_not_image_names_or_git_remotes() {
        let (out, n) = mask_emails("mail me@example.com or me%40example.org, see icon@2x.png and git@github.com:a/b");
        assert_eq!(n, 2);
        assert_eq!(out, "mail [email] or [email], see icon@2x.png and git@github.com:a/b");
    }

    #[test]
    fn denies_sensitive_paths_only() {
        let denied = |p: &str| credential_path(Path::new(p)).or(agent_config(Path::new(p))).is_some();
        for p in [
            ".env", "app/.env.local", ".env-prod", "prod.env", "certs/server.pem", ".claude/settings.json", ".Claude/x",
            ".envrc", "a/.git/config", "id_ed25519", ".zsh_history", "key.ppk",
        ] {
            assert!(denied(p), "{p}");
        }
        for p in [".env.example", "src/main.rs", ".claude/skills/x/SKILL.md", "CLAUDE.md", "keys.rs", "environment.rs"] {
            assert!(!denied(p), "{p}");
        }
    }

    #[test]
    fn denies_personal_home_folders() {
        let home = Path::new("/Users/me");
        assert!(denied_personal(Path::new("/Users/me/Library/Messages/a.jpg"), home).is_some());
        assert!(denied_personal(Path::new("/Users/me/.codex/auth.json"), home).is_some());
        assert!(denied_personal(Path::new("/Users/me/AppData/Roaming/x"), home).is_some());
        assert!(denied_personal(Path::new("/Users/me/Desktop/proj/a.rs"), home).is_none());
        assert!(denied_personal(Path::new("/tmp/x"), home).is_none());
    }

    #[test]
    fn flags_commands_that_read_credentials_however_spelled() {
        for c in [
            "cat .env.p*",
            "git show HEAD:.env.production",
            "cat \"$HOME/.ssh/config\"",
            "env",
            "ls | env",
            "printenv",
            "echo $API_KEY",
            "Get-ChildItem Env:",
            "echo $env:OPENAI_API_KEY",
            "type %USERPROFILE%\\secrets.txt",
            "Get-Content .env",
        ] {
            assert!(sensitive_command(c), "{c}");
        }
        for c in ["cargo test", "ls -la src", "grep -n environment src/main.rs", "npm run dev", "grep -rn secret src/", "cargo test credential"] {
            assert!(!sensitive_command(c), "{c}");
        }
    }
}
