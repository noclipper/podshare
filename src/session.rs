//! What podshare knows about an agent session, whichever agent wrote it: the files a tool
//! call touched, where paths point, and who the sender is. Agent formats live in their
//! own adapters (`claude_code`).

use anyhow::{Context, Result};
use regex::Regex;
use serde_json::{Map, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::filters::{Filter, Filters};
use crate::scan;

/// Stands in for the project folder inside a shared transcript; `podshare open` swaps in the new one.
pub const ROOT: &str = "{{POD_ROOT}}";
/// The same, as it appears inside a `file://` URL.
pub const ROOT_URL: &str = "{{POD_ROOT_URL}}";

/// A path as it appears in a `file://` URL: forward slashes, a leading `/` before a
/// Windows drive, and everything but unreserved characters percent-encoded, the way agents
/// write working folders.
pub fn url_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let path = if path.as_bytes().get(1) == Some(&b':') { format!("/{path}") } else { path };
    path.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The real path of `p`, without the `\\?\` prefix Windows adds, so it compares and
/// prints like the paths agents record.
pub fn canonical(p: &Path) -> std::io::Result<PathBuf> {
    dunce::canonicalize(p)
}

/// Reads a JSON-lines session file.
/// Reads a JSONL transcript. A half-written last line (the agent is still writing) is skipped.
pub fn load(path: &Path) -> Result<Vec<Value>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let lines: Vec<(usize, &str)> = text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()).collect();
    let last = lines.len().saturating_sub(1);
    let mut out = vec![];
    for (i, (n, line)) in lines.into_iter().enumerate() {
        match serde_json::from_str(line) {
            Ok(v) => out.push(v),
            Err(_) if i == last && !text.ends_with('\n') => {}
            Err(e) => return Err(e).with_context(|| format!("{} line {}: not valid JSON", path.display(), n + 1)),
        }
    }
    Ok(out)
}

/// Long, unusual names are safe to replace anywhere; short or common ones aren't.
pub fn distinctive(word: &str) -> bool {
    const COMMON: &[&str] = &[
        "admin", "user", "users", "root", "test", "tests", "guest", "owner", "local", "localhost", "server", "ubuntu",
        "debian", "master", "main", "default", "build", "runner", "docker", "vagrant", "developer", "desktop", "laptop",
        "macbook", "computer", "public", "shared", "worker", "staff", "admin1", "administrator", "system", "service",
    ];
    word.chars().count() >= 5 && !COMMON.contains(&word.to_lowercase().as_str())
}

/// What replaces a withheld tool call's content in a shared transcript.
pub fn withheld_note(why: &str) -> String {
    format!("[withheld by podshare when sharing; the agent saw the real content at the time: {why}]")
}

pub fn blank_strings(v: &mut Value, with: &str) {
    match v {
        Value::String(s) => *s = with.to_string(),
        Value::Array(items) => items.iter_mut().for_each(|x| blank_strings(x, with)),
        Value::Object(map) => map.values_mut().for_each(|x| blank_strings(x, with)),
        _ => {}
    }
}

/// Cleans text for sharing: secrets and emails redacted, the project folder made
/// portable, and the sender's home folder and identity replaced.
pub struct Scrubber<'a> {
    root: String,
    /// The root with forward slashes, as tools on Windows often print it.
    root_fwd: String,
    root_url: String,
    home: Option<String>,
    words: Vec<(Regex, String)>,
    secrets: bool,
    emails: bool,
    /// Secret values seen in withheld content, redacted wherever they were repeated.
    echoes: &'a [String],
}

impl<'a> Scrubber<'a> {
    pub fn new(root: &Path, home: &Path, identity: &Identity, echoes: &'a [String], filters: &Filters) -> Self {
        let words = if filters.on(Filter::Identity) {
            identity
                .iter()
                .flat_map(|(word, with)| {
                    let w = regex::escape(word);
                    let with = format!("${{1}}{with}${{2}}");
                    if distinctive(word) {
                        // Letters on either side mean a different word; digits and punctuation don't.
                        vec![(Regex::new(&format!(r"(?i)(^|[^a-z]|%2f){w}([^a-z]|$)")).unwrap(), with)]
                    } else {
                        // A name like "dev" or "admin" is everywhere in code: replace it only
                        // where it names a person — home folders and file owners in `ls -l`.
                        vec![
                            (Regex::new(&format!(r"(?i)(/Users/|/home/|\\Users\\|-Users-|-home-|%2FUsers%2F|%2Fhome%2F){w}([^a-z0-9]|$)")).unwrap(), with.clone()),
                            (Regex::new(&format!(r"((?:^|\s)[-dlcbps][-rwxsStT]{{9}}[@+.]?\s+\d+\s+){w}(\s)")).unwrap(), with),
                        ]
                    }
                })
                .collect()
        } else {
            vec![]
        };
        let root = root.to_string_lossy().into_owned();
        Scrubber {
            root_url: url_path(&root),
            root_fwd: root.replace('\\', "/"),
            root,
            home: filters.on(Filter::Identity).then(|| home.to_string_lossy().into_owned()),
            words,
            secrets: filters.on(Filter::SecretScan),
            emails: filters.on(Filter::Emails),
            echoes: if filters.on(Filter::SecretScan) { echoes } else { &[] },
        }
    }

    fn text(&self, s: &str, c: &mut Cleaned) -> String {
        let mut s = s.to_string();
        if self.secrets {
            let (text, n) = scan::redact(&s);
            (s, c.secrets) = (text, c.secrets + n);
        }
        if self.emails {
            let (text, n) = scan::mask_emails(&s);
            (s, c.emails) = (text, c.emails + n);
        }
        s = s.replace(&self.root, ROOT);
        if self.root_fwd != self.root {
            s = s.replace(&self.root_fwd, ROOT);
        }
        if self.root_url != self.root {
            s = s.replace(&self.root_url, ROOT_URL);
        }
        if let Some(home) = &self.home {
            s = s.replace(home.as_str(), "~");
            let fwd = home.replace('\\', "/");
            if fwd != *home {
                s = s.replace(&fwd, "~");
            }
        }
        for (re, with) in &self.words {
            // Twice: adjacent matches share the separator between them.
            for _ in 0..2 {
                s = re.replace_all(&s, with.as_str()).into_owned();
            }
        }
        for echo in self.echoes {
            if s.contains(echo.as_str()) {
                c.secrets += s.matches(echo.as_str()).count();
                s = s.replace(echo.as_str(), "[REDACTED:repeated]");
            }
        }
        s
    }

    /// Scrubs every string and object key in `v`, leaving embedded image data alone:
    /// scanning it would only corrupt it.
    pub fn scrub(&self, v: &mut Value, c: &mut Cleaned) {
        self.walk(v, false, c)
    }

    fn walk(&self, v: &mut Value, opaque: bool, c: &mut Cleaned) {
        match v {
            Value::String(s) if !opaque && !s.starts_with("data:") => *s = self.text(s, c),
            Value::Array(items) => items.iter_mut().for_each(|x| self.walk(x, false, c)),
            Value::Object(map) => {
                let base64 = map.get("type").is_some_and(|t| t == "base64");
                let entries = std::mem::take(map);
                *map = entries
                    .into_iter()
                    .map(|(k, mut x)| {
                        self.walk(&mut x, base64 && k == "data", c);
                        (self.text(&k, c), x)
                    })
                    .collect::<Map<_, _>>();
            }
            _ => {}
        }
    }
}

pub fn home() -> PathBuf {
    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    PathBuf::from(home.expect("neither HOME nor USERPROFILE is set"))
}

/// One tool call, or one attachment, and everything that says where its content came from.
pub struct Touch<'a> {
    /// The tool_use id, or the attachment entry's uuid.
    pub id: String,
    /// The tool's name, or the attachment's type.
    pub tool: &'a str,
    pub attachment: bool,
    pub cwd: PathBuf,
    /// The file whose content this put in the transcript (Read, Edit, Write, attachments).
    pub file: Option<PathBuf>,
    /// For every other tool: the text of its input and of its output, to search for paths.
    pub inputs: Vec<&'a str>,
    pub outputs: Vec<&'a str>,
    /// The call used something podshare can't check from the record (like an unknown tool
    /// inside a Codex script).
    pub opaque: bool,
}

/// Every path-like word in `text`, resolved against `cwd`: absolute paths, `~/…`, and
/// relative names (which is how `ls` and `grep` print them).
pub fn paths_in<'a>(text: &'a str, cwd: &'a Path, home: &'a Path) -> impl Iterator<Item = PathBuf> + 'a {
    words(text).filter(|t| !t.is_empty() && t.len() < 1024 && !t.starts_with('-')).map(move |t| {
        // A trailing period ends a sentence, except in `.` and `..`.
        let t = if t.ends_with("..") || t == "." { t } else { t.trim_end_matches(['.', '\\']) };
        let path = match t.strip_prefix('~') {
            Some("") => home.to_path_buf(),
            Some(rest) if rest.starts_with(['/', '\\']) => home.join(&rest[1..]),
            _ => cwd.join(t),
        };
        normalize(&path)
    })
}

/// Splits text into words at whitespace and shell punctuation. A colon splits too, unless
/// it is a Windows drive's (`C:\` or `C:/`).
fn words(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    let mut out = vec![];
    let mut start = 0;
    for (i, c) in text.char_indices() {
        let drive = c == ':' && i == start + 1 && bytes[start].is_ascii_alphabetic() && matches!(bytes.get(i + 1), Some(b'\\' | b'/'));
        if c.is_whitespace() || "|;&<>()'\"`=,[]{}".contains(c) || (c == ':' && !drive) {
            out.push(&text[start..i]);
            start = i + c.len_utf8();
        }
    }
    out.push(&text[start..]);
    out.into_iter()
}

/// Resolves `.` and `..` without touching the disk, so `proj/../../.ssh` can't pass as inside `proj`.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            c => out.push(c),
        }
    }
    out
}

/// A subagent the session started: its own transcript, and the parent's Agent call.
pub struct Subagent {
    pub transcript: PathBuf,
    pub tool_use_id: String,
    pub description: String,
}

#[derive(Default)]
pub struct Cleaned {
    pub lines: Vec<Value>,
    pub secrets: usize,
    pub emails: usize,
    pub withheld: usize,
    pub images: usize,
    pub thinking: usize,
}

/// Words that identify the sender (account name, full name, computer name) and what
/// replaces each.
pub type Identity = Vec<(String, &'static str)>;

/// Replaces `from` with `to` in every string of `v`.
pub fn replace_strings(v: &mut Value, from: &str, to: &str) {
    match v {
        Value::String(s) if s.contains(from) => *s = s.replace(from, to),
        Value::Array(items) => items.iter_mut().for_each(|x| replace_strings(x, from, to)),
        Value::Object(map) => map.values_mut().for_each(|x| replace_strings(x, from, to)),
        _ => {}
    }
}

/// Whether `path` is `dir` or inside it, ignoring case (as macOS and Windows do) and which
/// way the slashes lean.
pub fn under(path: &Path, dir: &Path) -> bool {
    let key = |p: &Path| p.to_string_lossy().replace('\\', "/").to_lowercase();
    let (p, d) = (key(path), key(dir));
    p == d || p.starts_with(&format!("{}/", d.trim_end_matches('/')))
}

/// UTC time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
pub fn rfc3339(t: SystemTime) -> String {
    let ms = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis()) as i64;
    let (days, rem) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + (m <= 2) as i64;
    let (h, mi, s, milli) = (rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000);
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{milli:03}Z")
}


/// Adds up what a model reads in `v`: its strings, with base64 image data counted as
/// images rather than text.
pub fn model_chars(v: &Value, images: &mut usize) -> usize {
    match v {
        Value::String(s) if s.starts_with("data:image") => {
            *images += 1;
            0
        }
        Value::String(s) => s.len(),
        Value::Array(items) => items.iter().map(|x| model_chars(x, images)).sum(),
        Value::Object(map) if map.get("type").is_some_and(|t| t == "base64") => {
            *images += 1;
            0
        }
        Value::Object(map) => map.iter().filter(|(k, _)| k.as_str() != "type").map(|(_, x)| model_chars(x, images)).sum(),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scrubbed(text: &str, name: &str) -> String {
        let identity: Identity = vec![(name.to_string(), "user")];
        let scrubber = Scrubber::new(Path::new("/work/app"), Path::new("/elsewhere"), &identity, &[], &Filters::default());
        let mut v = json!(text);
        scrubber.scrub(&mut v, &mut Cleaned::default());
        v.as_str().unwrap().to_string()
    }

    #[test]
    fn replaces_a_common_username_only_where_it_names_the_person() {
        let out = scrubbed("git checkout dev; cat /Users/dev/notes and /home/dev/x\n-rw-r--r--  1 dev  staff  12 a.txt", "dev");
        assert!(out.starts_with("git checkout dev;"), "{out}");
        assert!(out.contains("/Users/user/notes") && out.contains("/home/user/x"), "{out}");
        assert!(out.contains("1 user  staff"), "{out}");
    }

    #[test]
    fn replaces_a_distinctive_name_everywhere() {
        assert_eq!(scrubbed("thanks jrousselot, see jrousselot.txt", "jrousselot"), "thanks user, see user.txt");
    }

    #[test]
    fn skips_a_half_written_last_line_but_not_a_broken_one_in_the_middle() {
        let dir = std::env::temp_dir().join(format!("podshare-load-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("s.jsonl");
        fs::write(&f, "{\"a\":1}\n{\"b\":").unwrap();
        assert_eq!(load(&f).unwrap().len(), 1);
        fs::write(&f, "{\"a\":1}\n{\"b\":\n{\"c\":1}\n").unwrap();
        let err = format!("{:#}", load(&f).unwrap_err());
        assert!(err.contains("line 2"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
