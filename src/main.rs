//! podshare: share a coding-agent session, with its files, as an encrypted pod someone else can resume.

mod bundle;
mod filters;
mod scan;
mod agent;
mod claude_code;
mod codex;
mod convert;
mod session;
mod wormhole;

use anyhow::{bail, ensure, Context, Result};
use clap::Parser;
use agent::Agent;
use filters::{Filter, Filters, ALL};
use serde_json::{json, Value};
use session::{under, Identity, Touch};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::{env, fs, io};

#[derive(Parser)]
#[command(name = "podshare", version, about = "Share a coding-agent session, with its files, as an encrypted pod someone else can resume")]
enum Cli {
    /// Pack this folder's latest session (or --session) into an encrypted .pod file
    Pack {
        /// Session id (default: the most recent session started in this folder)
        #[arg(long)]
        session: Option<String>,
        /// Which agent's session to share (default: whichever you used last here)
        #[arg(long)]
        agent: Option<Agent>,
        /// Where to write the pod
        #[arg(short, long)]
        out: Option<PathBuf>,
        /// Show what would be packed, then stop
        #[arg(long)]
        dry_run: bool,
        /// Turn a safety filter off; repeat for several. All are on by default
        #[arg(long, value_name = "FILTER")]
        allow: Vec<Filter>,
        /// Leave a project file out (path relative to the project); repeat for several
        #[arg(long, value_name = "PATH")]
        exclude: Vec<PathBuf>,
        /// Don't send the skills the chat used from your own setup (the project's still go)
        #[arg(long)]
        no_skills: bool,
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    /// Pack this folder's latest session and send it straight to someone with a short code
    Send {
        /// Session id (default: the most recent session started in this folder)
        #[arg(long)]
        session: Option<String>,
        /// Which agent's session to share (default: whichever you used last here)
        #[arg(long)]
        agent: Option<Agent>,
        /// Turn a safety filter off; repeat for several. All are on by default
        #[arg(long, value_name = "FILTER")]
        allow: Vec<Filter>,
        /// Leave a project file out (path relative to the project); repeat for several
        #[arg(long, value_name = "PATH")]
        exclude: Vec<PathBuf>,
        /// Don't send the skills the chat used from your own setup (the project's still go)
        #[arg(long)]
        no_skills: bool,
        /// Show what would be sent, then stop
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt
        #[arg(short, long)]
        yes: bool,
    },
    /// List the agent sessions started in this folder, most recent first
    List {
        /// Only this agent's sessions
        #[arg(long)]
        agent: Option<Agent>,
    },
    /// Receive a pod someone is sending with `podshare send`, then resume its session
    Receive {
        /// The code the sender was given, like 7-crossover-clockwork
        code: String,
        /// Folder to unpack into (default: the project's name)
        #[arg(long)]
        into: Option<PathBuf>,
        /// Agent to continue in (default: the one the session was made in)
        #[arg(long)]
        agent: Option<Agent>,
        /// Skip the confirmation prompts
        #[arg(short, long)]
        yes: bool,
        /// Unpack only; don't start the agent
        #[arg(long)]
        no_launch: bool,
    },
    /// Unpack a pod and resume its session
    Open {
        /// <file>.pod#k=<key>, exactly as `podshare pack` printed it
        target: String,
        /// Folder to unpack into (default: the project's name)
        #[arg(long)]
        into: Option<PathBuf>,
        /// Agent to continue in (default: the one the session was made in)
        #[arg(long)]
        agent: Option<Agent>,
        /// Skip the confirmation prompts
        #[arg(short, long)]
        yes: bool,
        /// Unpack only; don't start the agent
        #[arg(long)]
        no_launch: bool,
    },
}

const QUICK_START: &str = "podshare: share a coding-agent session so someone else can pick it up

  podshare send                  send this folder's latest session; prints a code
  podshare receive <code>        get a session someone is sending you
  podshare pack / open           the same, as a file you pass along yourself

More: podshare help, or https://github.com/noclipper/podshare";

fn main() {
    if let Err(e) = run() {
        // A progress line may still be open.
        eprintln!("\nError: {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    if env::args().len() == 1 {
        println!("{QUICK_START}");
        return Ok(());
    }
    ensure!(
        env::var_os("HOME").is_some() || env::var_os("USERPROFILE").is_some(),
        "can't find your home folder: set HOME (or USERPROFILE on Windows)"
    );
    match Cli::parse() {
        Cli::Pack { session, agent, out, allow, exclude, no_skills, dry_run, yes } => {
            let mut filters = Filters::new(allow);
            filters.excluded.extend(exclude);
            filters.no_skills = no_skills;
            share(session, agent, if dry_run { Dest::Nowhere } else { Dest::File(out) }, filters, yes)
        }
        Cli::Send { session, agent, allow, exclude, no_skills, dry_run, yes } => {
            let mut filters = Filters::new(allow);
            filters.excluded.extend(exclude);
            filters.no_skills = no_skills;
            share(session, agent, if dry_run { Dest::Nowhere } else { Dest::Wormhole }, filters, yes)
        }
        Cli::Receive { code, into, agent, yes, no_launch } => {
            // Checked before connecting: once connected, the code is spent.
            if let Some(dir) = &into {
                ensure!(!busy(dir), "{} already exists and isn't empty; pick a new folder for --into", dir.display());
            }
            match wormhole::receive(&code, 2 << 30, |summary, size| incoming(summary, size, yes))? {
                Some((data, key)) => open_pod(&data, &key, into, agent, yes, !no_launch),
                None => {
                    println!("Declined; nothing was downloaded.");
                    Ok(())
                }
            }
        }
        Cli::Open { target, into, agent, yes, no_launch } => open(&target, into, agent, yes, !no_launch),
        Cli::List { agent } => {
            let here = env::current_dir()?;
            let found = agent::list(&here, agent);
            ensure!(!found.is_empty(), "no Claude Code or Codex sessions for {}", here.display());
            let mut out = io::stdout().lock();
            for f in found {
                let stem = f.path.file_stem().unwrap_or_default().to_string_lossy().into_owned();
                let id = stem.get(stem.len().saturating_sub(36)..).unwrap_or(&stem).to_string();
                let line = format!("{:<11}  {:>11}  {}  {}", f.agent.label(), ago(f.modified), id, convert::short_line(&plain(&f.title), 60));
                // A closed pipe (`podshare list | head`) just means the reader has enough.
                if writeln!(out, "{line}").is_err() {
                    break;
                }
            }
            Ok(())
        }
    }
}

const MAX_FILE: u64 = 10 << 20;
/// Even with large files allowed: bigger than this never goes in a pod.
const HARD_MAX_FILE: u64 = 1 << 30;

/// Past this many tokens a resumed session takes much of a model's context.
const LARGE: usize = 150_000;
/// Past this many, no agent can load it at all.
const HUGE: usize = 1_000_000;

/// Where `podshare open` lists the files it unpacked, relative to the folder.
const RECEIVED: &str = ".podshare/received.json";

/// Tells the resumed agent that the gaps in its history are deliberate, so it doesn't
/// take its earlier (real) answers for things it made up.
const RESUME_NOTE: &str = "This conversation was shared from another person's machine with podshare. Before sharing, \
it withheld some tool calls and redacted secrets and personal details ([withheld by podshare ...], [REDACTED:...], \
[email], user, ~). These edits were made afterwards: at the time, the agent saw the real content, so answers \
based on withheld results were real, not made up. Don't apologise for them; just note the values are hidden now. \
You are working in an unpacked copy of the project that holds only the files the session used.";

/// Files a project needs to build and test, shared even if the session never named them.
const MANIFESTS: &[&str] = &[
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "tsconfig.json", "deno.json",
    "Cargo.toml", "Cargo.lock", "pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock", "composer.json", "pom.xml", "build.gradle", "CMakeLists.txt", "Makefile",
];

/// Why a file is not in the pod.
enum Skip {
    Outside,
    Missing,
    Ignored,
    TooBig,
    /// Over the most a pod holds per file, allowed or not.
    Huge,
    Excluded,
    Sensitive(String),
}

impl Skip {
    fn reason(&self) -> String {
        match self {
            Skip::Outside => "outside the project".into(),
            Skip::Missing => "no longer exists".into(),
            Skip::Ignored => "gitignored".into(),
            Skip::TooBig => "over 10 MB".into(),
            Skip::Huge => "over 1 GB".into(),
            Skip::Excluded => "left out by you".into(),
            Skip::Sensitive(why) => format!("sensitive: {why}"),
        }
    }
}

/// Why `path` is somewhere a shared session must not reach, judged by the path alone.
fn off_limits(path: &Path, root: &Path, home: &Path, filters: &Filters) -> Option<Skip> {
    let personal = scan::denied_personal(path, home).filter(|_| filters.on(Filter::PersonalFolders));
    let credential = scan::credential_path(path).filter(|_| filters.on(Filter::CredentialFiles));
    if let Some(why) = personal.or_else(|| scan::agent_config(path)).or(credential) {
        return Some(Skip::Sensitive(why.into()));
    }
    (!under(path, root)).then_some(Skip::Outside)
}

/// A file that may be shared: its path relative to the project, and the exact bytes to
/// seal (with secrets redacted), so it can't change between this check and the pod.
struct Shared {
    rel: PathBuf,
    bytes: Vec<u8>,
    redacted: usize,
}

fn check(path: &Path, root: &Path, home: &Path, filters: &Filters) -> Result<Shared, Skip> {
    if let Some(skip @ Skip::Sensitive(_)) = off_limits(&session::normalize(path), root, home, filters) {
        return Err(skip);
    }
    // Resolve symlinks before judging where the file really is.
    let abs = session::canonical(path).map_err(|_| match under(&session::normalize(path), root) {
        true => Skip::Missing,
        false => Skip::Outside,
    })?;
    if let Some(skip) = off_limits(&abs, root, home, filters) {
        return Err(skip);
    }
    let rel = abs.strip_prefix(root).map_err(|_| Skip::Outside)?.to_path_buf();
    if filters.excluded.contains(&rel) {
        return Err(Skip::Excluded);
    }
    if filters.on(Filter::Gitignored) && gitignored(root, &rel) {
        return Err(Skip::Ignored);
    }
    let bytes = match fs::metadata(&abs) {
        Ok(m) if !m.is_file() => return Err(Skip::Missing),
        Ok(m) if m.len() > MAX_FILE && filters.on(Filter::LargeFiles) => return Err(Skip::TooBig),
        Ok(m) if m.len() > HARD_MAX_FILE => return Err(Skip::Huge),
        Ok(_) => fs::read(&abs).map_err(|_| Skip::Missing)?,
        Err(_) => return Err(Skip::Missing),
    };
    vet(rel, bytes, filters)
}

/// The content checks every shared file gets: key formats keep it out whole,
/// `password = …` style secrets are redacted.
fn vet(rel: PathBuf, bytes: Vec<u8>, filters: &Filters) -> Result<Shared, Skip> {
    if !filters.on(Filter::SecretScan) {
        return Ok(Shared { rel, bytes, redacted: 0 });
    }
    // Text with a key format stays out whole; text with only `password = …` style
    // secrets is shared redacted. Binary (and UTF-16) files can't be redacted.
    if let Some(rule) = scan::find_key(&scan::text_of(&bytes)) {
        return Err(Skip::Sensitive(format!("contains a {rule}")));
    }
    match String::from_utf8(bytes).map_err(|e| e.into_bytes()).and_then(|t| if t.contains('\0') { Err(t.into_bytes()) } else { Ok(t) }) {
        Ok(text) => {
            let (text, redacted) = scan::redact(&text);
            Ok(Shared { rel, bytes: text.into_bytes(), redacted })
        }
        // UTF-16 text gets every rule; other binary data only the key formats checked
        // above, since `password = …` rules fire on random bytes.
        Err(bytes) => match scan::is_utf16(&bytes).then(|| scan::find_secret(&scan::text_of(&bytes))).flatten() {
            Some(rule) => Err(Skip::Sensitive(format!("UTF-16 file contains a {rule}"))),
            None => Ok(Shared { rel, bytes, redacted: 0 }),
        },
    }
}

/// System folders a command may name (programs, libraries) without that counting as
/// reading something outside the project.
const SYSTEM: &[&str] = &[
    "/usr", "/bin", "/sbin", "/opt", "/Applications", "/System", "/Library", "/dev", "/nix",
    "C:/Windows", "C:/Program Files", "C:/Program Files (x86)", "C:/ProgramData",
];

/// A leading `cd <dir> &&` or `cd <dir>;`, which says nothing about what a command does.
static CD_PREFIX: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"^\s*cd\s+\S+\s*(?:&&|;)\s*").unwrap());

fn short(s: &str, n: usize) -> String {
    let s = s.replace('\n', " ");
    match s.char_indices().nth(n) {
        Some((i, _)) => format!("{}…", &s[..i]),
        None => s,
    }
}

static CD: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"(?:^|[;&|(]\s*)(?:cd|pushd)(?:\s+([^\s;&|)]+))?\s*(?:$|[;&|)])").unwrap());

/// Why the content of this tool call or attachment must not appear in the pod, if it
/// must not. Files it may share are added to `files`.
/// Whether a tool call is withheld, and why. `culprit` gets the path that caused it, if any.
fn judge(t: &Touch, root: &Path, home: &Path, filters: &Filters, files: &mut BTreeMap<PathBuf, Shared>, culprit: &mut Option<PathBuf>) -> Option<String> {
    let outside_ok = !filters.on(Filter::OutsideProject);
    if t.tool.starts_with("mcp__") && filters.on(Filter::ConnectedTools) {
        return Some("result of a connected tool (MCP)".into());
    }
    let mut share = |f: Shared| {
        files.insert(f.rel.clone(), f);
    };
    if let Some(file) = &t.file {
        match check(file, root, home, filters) {
            Ok(f) => share(f),
            Err(Skip::Outside) if outside_ok => {}
            Err(skip) => {
                *culprit = Some(file.clone());
                return Some(skip.reason());
            }
        }
    }
    // What the call's input names. Files are judged on their own and shared if they pass,
    // even when the call itself is withheld: hiding a command's output shouldn't also drop
    // the project files it wrote. Anything sensitive or outside the project keeps the call out.
    let mut reason = None;
    for p in t.inputs.iter().flat_map(|s| session::paths_in(s, &t.cwd, home)) {
        let system = SYSTEM.iter().any(|d| under(&p, Path::new(d)));
        let why = if p.is_file() {
            match check(&p, root, home, filters) {
                Ok(f) => {
                    share(f);
                    None
                }
                Err(skip @ (Skip::Sensitive(_) | Skip::Ignored | Skip::Excluded)) => Some(skip.reason()),
                Err(Skip::Outside) if !outside_ok && !system => Some(Skip::Outside.reason()),
                Err(_) => None,
            }
        } else {
            match off_limits(&p, root, home, filters) {
                Some(skip @ Skip::Sensitive(_)) => Some(skip.reason()),
                Some(Skip::Outside) if !outside_ok && under(&p, home) => Some(Skip::Outside.reason()),
                _ => None,
            }
        };
        if reason.is_none() && why.is_some() {
            *culprit = Some(p.clone());
        }
        reason = reason.or(why);
    }
    if reason.is_some() {
        return reason;
    }
    if t.opaque && filters.on(Filter::UncheckedCommands) {
        return Some("unchecked command (a tool podshare can't follow)".into());
    }
    if t.tool == "Bash" {
        let cmd = t.inputs.first().copied().unwrap_or("");
        if filters.on(Filter::CredentialFiles) && scan::sensitive_command(cmd) {
            return Some("sensitive: command reads credentials, history or the environment".into());
        }
        if filters.on(Filter::UncheckedCommands) {
            let cd_out = CD.captures_iter(cmd).any(|c| match c.get(1).map(|m| m.as_str()) {
                None | Some("~" | "-") => true,
                Some(dir) => session::paths_in(dir, &t.cwd, home).any(|p| !under(&p, root)),
            });
            if cd_out || scan::opaque_command(cmd) {
                return Some("unchecked command (inline script, $(…), glob or cd out of the project)".into());
            }
        }
    }
    // What the output shows: only a sensitive place counts (`~/.ssh/…`, or `.env:3:…`
    // lines from a search); ordinary paths like `~/.cargo/registry` in build output don't.
    for text in &t.outputs {
        let sensitive = |p: &Path| {
            scan::denied_personal(p, home).filter(|_| filters.on(Filter::PersonalFolders))
                .or(scan::credential_path(p).filter(|_| filters.on(Filter::CredentialFiles)))
        };
        let absolute = session::paths_in(text, &t.cwd, home).filter(|p| !under(p, root));
        let searched = text.lines().filter_map(|l| l.split_once(':')).map(|(file, _)| t.cwd.join(file.trim()));
        if let Some(why) = absolute.chain(searched).find_map(|p| sensitive(&p)) {
            return Some(format!("sensitive: {why}"));
        }
    }
    None
}

/// Whether `rel` (inside `root`) is gitignored, judged by the nearest repository around it,
/// so a submodule's own `.gitignore` counts. Each repository is asked once, for all its
/// ignored paths; if git can't answer, the file counts as ignored (fail closed).
fn gitignored(root: &Path, rel: &Path) -> bool {
    use std::sync::{Mutex, OnceLock};
    static IGNORED: OnceLock<Mutex<HashMap<PathBuf, Option<Vec<String>>>>> = OnceLock::new();
    let file = root.join(rel);
    let Some(repo) = file.ancestors().skip(1).find(|d| d.join(".git").exists()).map(Path::to_path_buf) else {
        return false;
    };
    let mut cache = IGNORED.get_or_init(Default::default).lock().unwrap();
    let listed = cache.entry(repo.clone()).or_insert_with(|| {
        let out = Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z"])
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())?;
        Some(String::from_utf8_lossy(&out.stdout).split('\0').filter(|e| !e.is_empty()).map(String::from).collect())
    });
    let Some(ignored) = listed else { return true };
    let inner = portable(file.strip_prefix(&repo).unwrap_or(rel));
    ignored.iter().any(|e| inner == *e || (e.ends_with('/') && inner.starts_with(e.as_str())))
}

/// The repository folder containing `dir`, found by walking up to a `.git`.
fn repo_of(dir: &Path) -> Option<PathBuf> {
    dir.ancestors().find(|d| d.join(".git").exists()).map(Path::to_path_buf)
}

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).stderr(Stdio::null()).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !text.is_empty()).then_some(text)
}

/// The git repository containing `cwd`, or `cwd` itself.
fn project_root(cwd: &Path) -> Result<PathBuf> {
    let root = output("git", &["-C", &cwd.to_string_lossy(), "rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .or_else(|| repo_of(cwd))
        .unwrap_or_else(|| cwd.to_path_buf());
    session::canonical(&root).with_context(|| format!("project folder {} no longer exists", root.display()))
}

/// The sender's account name, git author name and computer names.
fn identity(root: &Path, home: &Path) -> Identity {
    let mut words: Identity = home.file_name().map(|u| (u.to_string_lossy().into_owned(), "user")).into_iter().collect();
    let root = root.to_string_lossy();
    let found = [
        (output("git", &["-C", &root, "config", "user.name"]), "[name]"),
        (output("scutil", &["--get", "ComputerName"]), "[computer]"),
        (output("scutil", &["--get", "LocalHostName"]), "[computer]"),
        (output("hostname", &["-s"]), "[computer]"),
        (env::var("COMPUTERNAME").ok(), "[computer]"),
    ];
    for (word, with) in found {
        if let Some(word) = word.filter(|w| w.len() >= 3 && !words.iter().any(|(x, _)| x == w)) {
            words.push((word, with));
        }
    }
    words
}

/// Every file under `dir`, not following symlinks.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else { return vec![] };
    entries
        .filter_map(|e| e.ok())
        .flat_map(|e| match e.file_type() {
            Ok(t) if t.is_dir() => walk(&e.path()),
            Ok(t) if t.is_file() => vec![e.path()],
            _ => vec![],
        })
        .collect()
}

/// A relative path with forward slashes, the same on every system.
fn portable(rel: &Path) -> String {
    rel.to_string_lossy().replace('\\', "/")
}

fn show(p: &Path, root: &Path, home: &Path) -> String {
    match (p.strip_prefix(root), p.strip_prefix(home)) {
        (Ok(rel), _) => rel.display().to_string(),
        (_, Ok(rel)) => format!("~/{}", rel.display()),
        _ => p.display().to_string(),
    }
}

/// `s` with control and text-direction characters replaced, so text from a pod can't
/// rewrite the terminal or hide part of a prompt.
fn plain(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') { '?' } else { c })
        .collect()
}

/// `s` quoted for the user's shell (POSIX, or PowerShell on Windows), so a printed command
/// can be pasted as-is.
fn shell_quote(s: &str) -> String {
    if s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=".contains(c)) {
        return s.to_string();
    }
    if cfg!(windows) {
        format!("'{}'", s.replace('\'', "''"))
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Where `program` is on the PATH. On Windows that includes `program.exe` and the
/// `program.cmd` shims npm installs.
fn find_program(program: &str) -> Option<PathBuf> {
    let exts: &[&str] = if cfg!(windows) { &[".exe", ".cmd", ".bat", ""] } else { &[""] };
    let paths = env::var_os("PATH")?;
    env::split_paths(&paths).find_map(|dir| exts.iter().map(|e| dir.join(format!("{program}{e}"))).find(|p| p.is_file()))
}

fn on_path(program: &str) -> bool {
    find_program(program).is_some()
}

fn ask(question: &str) -> Result<String> {
    print!("{question} ");
    io::stdout().flush()?;
    let mut answer = String::new();
    if io::stdin().read_line(&mut answer)? == 0 {
        // No one there to answer: never take an action by default.
        println!();
        return Ok("n".into());
    }
    Ok(answer.trim().to_lowercase())
}

/// What `podshare pack` or `send` would put in the pod under the current filters.
struct Plan {
    files: BTreeMap<PathBuf, Shared>,
    skipped: BTreeMap<String, String>,  // what was left out → why
    /// (short reason, file or kind of call) → how many, for the summary.
    left_out: BTreeMap<(String, String), usize>,
    instructions: Vec<PathBuf>,
    skills: Vec<PathBuf>,
    /// Names of skills the chat used from outside the project.
    outside_skills: Vec<String>,
    /// Shared files that mention the sender's home folder, identity or an email.
    /// They are shared as-is: rewriting someone's code would break it.
    personal: Vec<PathBuf>,
    cleaned: session::Cleaned,
    messages: usize,
    /// Roughly how many tokens the receiving agent reads when it resumes.
    tokens: usize,
    agent_version: Option<String>,
}

fn plan(agent: Agent, path: &Path, cwd: &Path, root: &Path, home: &Path, identity: &Identity, filters: &Filters) -> Result<Plan> {
    // Loaded afresh each time: large sessions take gigabytes once parsed.
    let lines = session::load(path)?;
    let (mut files, mut skipped) = (BTreeMap::new(), BTreeMap::new());
    let mut withhold = HashMap::new(); // tool call or attachment id → why it is hidden
    let mut echoes = BTreeSet::new(); // secret values seen in what was withheld
    let mut described: HashMap<String, String> = HashMap::new(); // tool call id → its line in `skipped`
    let mut briefly: BTreeMap<String, (String, String)> = BTreeMap::new(); // id → (what, why), for the summary
    let mut used_skills = BTreeSet::new(); // skill folders the chat loaded
    lines.iter().for_each(|l| skills_announced(l, &mut used_skills));
    for t in agent.touched(&lines) {
        note_skills(&t, home, &mut used_skills);
        let mut culprit = None;
        if let Some(why) = judge(&t, root, home, filters, &mut files, &mut culprit) {
            let label = match culprit.as_ref().or(t.file.as_ref()) {
                Some(f) => show(f, root, home),
                None if t.tool.starts_with("mcp__") => CONNECTED.into(),
                None if t.attachment => CONTEXT.into(),
                None => COMMAND.into(),
            };
            match briefly.get(&t.id) {
                Some((old, _)) if old != COMMAND && old != CONTEXT => {}
                _ => {
                    briefly.insert(t.id.clone(), (plain(&label), why.clone()));
                }
            }
            if why.contains("sensitive") {
                learn_secrets(&t, &mut echoes);
            }
            let what = match (&t.file, t.inputs.first()) {
                _ if t.attachment => format!("attachment ({})", t.tool),
                (Some(file), _) => show(file, root, home),
                (None, input) => format!("{}: {}", t.tool, short(CD_PREFIX.replace(input.unwrap_or(&""), "").trim(), 50)),
            };
            // One line per call: a Codex script's own text says less than the command it ran.
            let what = plain(&what.replace('\n', " "));
            let script = |w: &str| w.contains("tools.");
            match described.get(&t.id) {
                Some(old) if script(old) && !script(&what) => {
                    skipped.remove(old);
                }
                Some(_) => continue,
                None => {}
            }
            described.insert(t.id.clone(), what.clone());
            skipped.insert(what, why.clone());
            withhold.insert(t.id.clone(), why);
        }
    }
    // Subagents keep their own transcripts. Files they read are shared like any other,
    // and if one touched something off limits, its summary to the parent is withheld.
    for sub in agent.subagents(path) {
        let sub_lines = session::load(&sub.transcript).unwrap_or_default();
        let mut reason = None;
        for t in agent.touched(&sub_lines) {
            note_skills(&t, home, &mut used_skills);
            if let Some(why) = judge(&t, root, home, filters, &mut files, &mut None) {
                if why.contains("sensitive") {
                    learn_secrets(&t, &mut echoes);
                }
                reason.get_or_insert(why);
            }
        }
        if let Some(why) = reason {
            skipped.insert(plain(&format!("subagent: {}", sub.description)), why.clone());
            briefly.insert(sub.tool_use_id.clone(), ("a helper agent's summary".into(), why.clone()));
            withhold.insert(sub.tool_use_id, format!("subagent {why}"));
        }
    }
    // Files that arrived in a pod travel on when this folder is shared again.
    let received = fs::read(root.join(RECEIVED)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    for rel in received.iter().flat_map(|r| r["files"].as_array().into_iter().flatten()).filter_map(Value::as_str) {
        let p = root.join(rel);
        if !p.is_file() {
            continue;
        }
        match check(&p, root, home, filters) {
            Ok(f) => {
                files.insert(f.rel.clone(), f);
            }
            Err(skip @ Skip::Sensitive(_)) => {
                skipped.insert(show(&p, root, home), skip.reason());
            }
            Err(_) => {}
        }
    }
    // Project manifests, so the receiver can build and test: at the root and in every
    // folder above a shared file.
    let mut dirs: BTreeSet<PathBuf> = [PathBuf::new()].into();
    for rel in files.keys() {
        dirs.extend(rel.ancestors().skip(1).map(Path::to_path_buf));
    }
    for dir in dirs {
        for name in MANIFESTS {
            let p = root.join(&dir).join(name);
            if p.is_file() {
                if let Ok(f) = check(&p, root, home, filters) {
                    files.insert(f.rel.clone(), f);
                }
            }
        }
    }
    // The project's own agent instructions and skills travel with it.
    let (mut instructions, mut skills) = (Vec::new(), Vec::new());
    // From the folder the session ran in up to the project root: agents load those too.
    let folders: Vec<&Path> = cwd.ancestors().take_while(|d| under(d, root)).collect();
    let folders = if folders.is_empty() { vec![root] } else { folders };
    let extras: Vec<PathBuf> = folders
        .iter()
        .flat_map(|d| ["CLAUDE.md", "AGENTS.md"].map(|f| d.join(f)).into_iter().chain(walk(&d.join(".claude/skills"))).chain(walk(&d.join(".agents/skills"))))
        .collect();
    for p in extras {
        match check(&p, root, home, filters) {
            Ok(f) => {
                if f.rel.starts_with(".claude") || f.rel.starts_with(".agents") { &mut skills } else { &mut instructions }.push(f.rel.clone());
                files.insert(f.rel.clone(), f);
            }
            Err(skip @ Skip::Sensitive(_)) => {
                skipped.insert(show(&p, root, home), skip.reason());
            }
            Err(_) => {}
        }
    }
    // Skills the chat used from outside the project: the sender's own, or a plugin's.
    // They go along (the summary names them; `c` or --no-skills leaves them out) and land
    // as project skills on the other side.
    let have: BTreeSet<String> = skills.iter().filter_map(|r| r.iter().nth(2).map(|n| n.to_string_lossy().into_owned())).collect();
    let mut outside_skills = Vec::new();
    for dir in used_skills.iter().filter(|d| !under(d, root)) {
        let name = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        // podshare's own share/receive skills are no use to the other person.
        if name.is_empty() || have.contains(&name) || dir.components().any(|c| c.as_os_str() == "podshare") {
            continue;
        }
        outside_skills.push(name.clone());
        if filters.no_skills {
            continue;
        }
        for file in walk(dir) {
            let rel = Path::new(".claude/skills").join(&name).join(file.strip_prefix(dir).unwrap_or(&file));
            let shown = format!("skill {name}: {}", file.strip_prefix(dir).unwrap_or(&file).display());
            if filters.excluded.contains(&rel) {
                continue;
            }
            let bytes = match fs::metadata(&file) {
                _ if scan::credential_path(&file).is_some() => Err(Skip::Sensitive("secrets file".into())),
                Ok(m) if m.len() > MAX_FILE => Err(Skip::TooBig),
                Ok(_) => fs::read(&file).map_err(|_| Skip::Missing),
                Err(_) => Err(Skip::Missing),
            };
            match bytes.and_then(|b| vet(rel.clone(), b, filters)) {
                Ok(f) => {
                    skills.push(rel.clone());
                    files.insert(rel, f);
                }
                Err(Skip::Missing) => {}
                Err(skip) => {
                    skipped.insert(shown, skip.reason());
                }
            }
        }
    }
    let personal = files.values().filter(|f| mentions_sender(&f.bytes, home, identity)).map(|f| f.rel.clone()).collect();

    // Values blanked in shared files are blanked where the agent quoted them, too.
    for f in files.values().filter(|f| f.redacted > 0) {
        if let Ok(bytes) = fs::read(root.join(&f.rel)) {
            // Short values (like "admin") would blank ordinary words everywhere.
            echoes.extend(scan::redacted_values(&scan::text_of(&bytes)).into_iter().filter(|v| v.chars().count() >= 8));
        }
    }
    // Longest first, so a value that contains another is redacted whole.
    let mut echoes: Vec<String> = echoes.into_iter().collect();
    echoes.sort_by_key(|e| std::cmp::Reverse(e.len()));
    let agent_version = agent.version(&lines);
    let cleaned = agent.clean(lines, &withhold, root, home, identity, &echoes, filters);
    let neutral = agent.to_neutral(&cleaned.lines);
    let messages = neutral.iter().filter(|l| l["type"] == "text").count();
    let tokens = agent.estimate_tokens(&cleaned.lines);
    // What the summary says was left out: each file once, and commands counted.
    let mut left_out: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (what, why) in briefly.into_values() {
        *left_out.entry((brief(&why).to_string(), what)).or_default() += 1;
    }
    for (what, why) in &skipped {
        if !what.contains(": ") && !what.starts_with("attachment") {
            left_out.entry((brief(why).to_string(), what.clone())).or_insert(1);
        }
    }
    Ok(Plan { files, skipped, left_out, instructions, skills, outside_skills, personal, cleaned, messages, tokens, agent_version })
}

/// The skill folder a path points into, if any: `…/skills/<name>/SKILL.md`, or the folder itself.
fn skill_dir(p: &Path) -> Option<PathBuf> {
    let dir = if p.file_name()?.eq_ignore_ascii_case("SKILL.md") { p.parent()? } else { p };
    let in_skills = dir.parent()?.file_name().is_some_and(|n| n == "skills");
    (in_skills && dir.join("SKILL.md").is_file()).then(|| dir.to_path_buf())
}

/// Skill folders Claude Code announced when it loaded them ("Base directory for this skill: …").
fn skills_announced(v: &Value, found: &mut BTreeSet<PathBuf>) {
    match v {
        Value::String(s) => {
            for (_, rest) in s.match_indices("Base directory for this skill: ").map(|(i, m)| (i, &s[i + m.len()..])) {
                let dir = rest.lines().next().unwrap_or("").trim();
                found.extend(skill_dir(Path::new(dir)));
            }
        }
        Value::Array(items) => items.iter().for_each(|x| skills_announced(x, found)),
        Value::Object(map) => map.values().for_each(|x| skills_announced(x, found)),
        _ => {}
    }
}

/// Notes the skill folders a tool call or attachment used (Claude Code logs "Base directory
/// for this skill: …"; Codex reads the `SKILL.md`).
fn note_skills(t: &Touch, home: &Path, found: &mut BTreeSet<PathBuf>) {
    let named = t.inputs.iter().flat_map(|s| session::paths_in(s, &t.cwd, home));
    found.extend(t.file.iter().cloned().chain(named).filter_map(|p| skill_dir(&p)));
}

/// Secret values in a withheld call's text, and in the file it read (as it is on disk).
fn learn_secrets(t: &Touch, echoes: &mut BTreeSet<String>) {
    for text in t.inputs.iter().chain(&t.outputs) {
        echoes.extend(scan::secret_values(text));
    }
    let file = t.file.as_ref().filter(|f| fs::metadata(f).is_ok_and(|m| m.is_file() && m.len() <= MAX_FILE));
    if let Some(bytes) = file.and_then(|f| fs::read(f).ok()) {
        echoes.extend(scan::secret_values(&scan::text_of(&bytes)));
    }
}

fn mentions_sender(bytes: &[u8], home: &Path, identity: &Identity) -> bool {
    let text = scan::text_of(bytes).to_lowercase();
    let words: Vec<&str> = text.split(|c: char| !c.is_alphanumeric()).collect();
    text.contains(&home.to_string_lossy().to_lowercase())
        || identity.iter().filter(|(w, _)| session::distinctive(w)).any(|(w, _)| {
            let w = w.to_lowercase();
            if w.contains(|c: char| !c.is_alphanumeric()) { text.contains(&w) } else { words.contains(&w.as_str()) }
        })
        || scan::mask_emails(&text).1 > 0
}

/// "1 file", "2 files".
fn count(n: usize, one: &str) -> String {
    if n == 1 { format!("1 {one}") } else { format!("{n} {one}s") }
}

fn list<T: AsRef<str>>(items: &[T]) -> String {
    let first = items.iter().take(3).map(|i| short(i.as_ref(), 48)).collect::<Vec<_>>().join(", ");
    let more = if items.len() > 3 { format!(", +{}", items.len() - 3) } else { String::new() };
    format!("{first}{more}")
}

const COMMAND: &str = "command";
const CONNECTED: &str = "connected tool";
const CONTEXT: &str = "context note";

/// A withholding reason in two or three words.
fn brief(why: &str) -> &str {
    match why {
        w if w.contains("personal folder") => "personal",
        w if w.starts_with("sensitive") || w.contains("sensitive") => "secrets",
        w if w.contains("outside the project") => "outside the project",
        w if w.contains("gitignored") => "gitignored",
        w if w.contains("unchecked") => "can't check",
        w if w.contains("connected tool") => "connected tool",
        w if w.contains("unticked") || w.contains("excluded") => "you unticked it",
        w if w.contains("over 10 MB") => "over 10 MB",
        w if w.contains("over 1 GB") => "over 1 GB",
        w => w,
    }
}

/// The summary shown before sending: what goes, what stays, and anything to worry about.
fn print_plan(p: &Plan, filters: &Filters, doing: &str) {
    let bytes: usize = p.files.values().map(|f| f.bytes.len()).sum();
    println!(
        "  ✓ {doing} {} ({}) · {} · ~{} tokens",
        count(p.files.len(), "file"),
        size(bytes as u64),
        count(p.messages, "message"),
        convert::short_count(p.tokens)
    );
    // Name them when there are few: that's the point.
    if p.files.len() <= 8 {
        p.files.keys().for_each(|r| println!("      {}", plain(&r.display().to_string())));
    }
    if !p.instructions.is_empty() || !p.skills.is_empty() {
        let parts: Vec<String> = [(p.instructions.len(), "instruction file"), (p.skills.len(), "skill file")]
            .into_iter()
            .filter(|(n, _)| *n > 0)
            .map(|(n, what)| count(n, what))
            .collect();
        let verb = if p.instructions.len() + p.skills.len() == 1 { "steers" } else { "steer" };
        println!("      incl. {} that {verb} the agent", parts.join(" and "));
    }
    if p.tokens > HUGE {
        println!("  ! that's more than any agent can load at once; the receiver won't be able to resume it as it is");
    } else if p.tokens > LARGE {
        println!("  ! that's a lot of context: the receiving agent may summarise the oldest parts");
    }
    // Secrets first: they matter most.
    let mut order: Vec<_> = p.left_out.iter().collect();
    order.sort_by_key(|((why, _), _)| why != "secrets");
    let items: Vec<String> = order
        .into_iter()
        .map(|((why, what), n)| match what.as_str() {
            COMMAND | CONNECTED | CONTEXT => format!("{} ({why})", count(*n, what)),
            _ => format!("{} ({why})", short(what, 60)),
        })
        .collect();
    match items.len() {
        0 => {}
        n if n <= 4 => println!("  ✗ left out: {}", items.join(", ")),
        _ => {
            let mut by_why: BTreeMap<&str, usize> = BTreeMap::new();
            p.left_out.iter().for_each(|((why, _), k)| *by_why.entry(why).or_default() += k);
            let mut by_why: Vec<_> = by_why.into_iter().collect();
            by_why.sort_by_key(|(why, k)| (*why != "secrets", std::cmp::Reverse(*k)));
            let total: usize = by_why.iter().map(|(_, k)| k).sum();
            let counts: Vec<String> = by_why.iter().map(|(why, k)| format!("{k} {why}")).collect();
            println!("  ✗ left out {total}: {} · d lists them", counts.join(", "));
        }
    }
    if !p.outside_skills.is_empty() {
        let state = if filters.no_skills { "left out: --no-skills" } else { "included; c to untick" };
        println!("  ✓ skills this chat used from your own setup: {} ({state})", list(&p.outside_skills));
    }
    let redacted: Vec<String> = p.files.values().filter(|f| f.redacted > 0).map(|f| f.rel.display().to_string()).collect();
    if !redacted.is_empty() {
        println!("  ~ secrets blanked inside {}", list(&redacted));
    }
    let c = &p.cleaned;
    if c.secrets + c.emails > 0 {
        println!("  ~ blanked in the chat: {}, {}", count(c.secrets, "secret"), count(c.emails, "email"));
    }
    if !p.personal.is_empty() {
        let names: Vec<String> = p.personal.iter().map(|r| r.display().to_string()).collect();
        println!("  ! these mention your name, email or home folder and go as they are: {}", list(&names));
    }
    match filters.off().as_slice() {
        [] => println!("  · all safety checks on · d = full report\n"),
        off => println!("  ⚠ safety filters OFF: {} (the receiver will be told) · d = full report\n", off.join(", ")),
    }
}

/// The full report, shown with `d` and on a dry run.
fn print_report(p: &Plan, filters: &Filters) {
    println!("  Full report:");
    let bytes: usize = p.files.values().map(|f| f.bytes.len()).sum();
    let steering = match (p.instructions.len(), p.skills.len()) {
        (0, 0) => String::new(),
        (i, s) => format!(", incl. {} and {}", count(i, "instruction file"), count(s, "skill file")),
    };
    println!("  ✓ {} ({}{steering})", count(p.files.len(), "file"), size(bytes as u64));
    println!("  ✓ transcript: {} messages, about {} tokens to resume", p.messages, convert::short_count(p.tokens));
    if p.tokens > HUGE {
        println!("  ! that's more than any agent can load at once; the receiver won't be able to resume it as it is");
    } else if p.tokens > LARGE {
        println!("  ! that's a lot of context: the receiving agent may summarise the oldest parts");
    }
    let mut by_reason: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (what, why) in &p.skipped {
        by_reason.entry(why).or_default().push(what);
    }
    if !by_reason.is_empty() {
        println!("  ✗ left out (the transcript shows [withheld by podshare …] in their place):");
        for (why, whats) in &by_reason {
            println!("      {} {why}: {}", whats.len(), list(whats));
        }
    }
    let redacted: Vec<String> = p.files.values().filter(|f| f.redacted > 0).map(|f| f.rel.display().to_string()).collect();
    if !redacted.is_empty() {
        let n: usize = p.files.values().map(|f| f.redacted).sum();
        println!("  ~ {} redacted in {}: {}", count(n, "secret"), count(redacted.len(), "shared file"), list(&redacted));
    }
    if !p.personal.is_empty() {
        let names: Vec<String> = p.personal.iter().map(|r| r.display().to_string()).collect();
        println!("  ! {} shared files mention your home folder, name or an email: {}", names.len(), list(&names));
        println!("    they are shared as they are; edit or `git rm` them first if that matters");
    }
    let c = &p.cleaned;
    println!(
        "  ~ transcript cleaned: {} redacted, {} masked, {} withheld,\n    {} and {} removed",
        count(c.secrets, "secret"), count(c.emails, "email"), count(c.withheld, "tool call"), count(c.images, "pasted image"), count(c.thinking, "thinking block")
    );
    match filters.off().as_slice() {
        [] => println!("  · all safety filters on"),
        off => println!("  ⚠ safety filters OFF: {} (the receiver will be told)", off.join(", ")),
    }
    println!("  · never included: hooks, MCP servers, settings, memory, account and permission records");
    println!("  · not checkable: the agent's own words, subagent summaries, and what scripts or make targets read inside\n");
}

pub fn size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1 << 20) as f64),
        b if b >= 1 << 10 => format!("{} KB", b >> 10),
        b => format!("{b} B"),
    }
}

/// A checklist of every file the pod would hold. Unticked files, and every tool call
/// that read them, stay out.
fn choose_files(p: &Plan, root: &Path, filters: &mut Filters) -> Result<()> {
    let mut rels: Vec<PathBuf> = p.files.keys().chain(&filters.excluded).cloned().collect();
    rels.sort();
    rels.dedup();
    let width = rels.iter().map(|r| r.display().to_string().chars().count()).max().unwrap_or(0).min(60);
    let labels: Vec<String> = rels
        .iter()
        .map(|r| {
            let bytes = p.files.get(r).map_or_else(|| fs::metadata(root.join(r)).map_or(0, |m| m.len()), |f| f.bytes.len() as u64);
            let mut note = String::new();
            if p.personal.contains(r) {
                note += "  ! mentions you";
            }
            if let Some(n) = p.files.get(r).map(|f| f.redacted).filter(|&n| n > 0) {
                note += &format!("  ~ {n} secrets redacted");
            }
            format!("{:<width$} {:>8}{note}", short(&r.display().to_string(), 60), size(bytes))
        })
        .collect();
    let ticked: Vec<bool> = rels.iter().map(|r| !filters.excluded.contains(r)).collect();
    if !p.skipped.is_empty() {
        println!("\n  Withheld (change these with f=filters):");
        for (what, why) in &p.skipped {
            println!("    - {}  ({})", short(what, 56), short(why, 48));
        }
    }
    println!();
    let chosen = dialoguer::MultiSelect::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Files to share (↑↓ move, space toggle, a all, enter done, esc cancel)")
        .items(&labels)
        .defaults(&ticked)
        .max_length(20)
        .interact_opt()
        .context("the checklist needs an interactive terminal; use --exclude <path> instead")?;
    if let Some(chosen) = chosen {
        filters.excluded = rels.into_iter().enumerate().filter(|(i, _)| !chosen.contains(i)).map(|(_, r)| r).collect();
    }
    println!();
    Ok(())
}

/// Every file that goes in (+) and every call that is withheld (-), one per line.
fn print_details(p: &Plan) {
    p.files.keys().for_each(|r| println!("  + {}", plain(&r.display().to_string())));
    p.skipped.iter().for_each(|(what, why)| println!("  - {what} ({why})"));
}

fn edit_filters(filters: &mut Filters) -> Result<()> {
    loop {
        println!("\n  Safety filters (all on is safest):");
        for (i, f) in ALL.iter().enumerate() {
            let state = if filters.on(*f) { "on " } else { "OFF" };
            println!("  {:>2} [{state}] {:<19} {}", i + 1, f.name(), f.about());
        }
        let answer = ask("Toggle which? (numbers, Enter when done)")?;
        if answer.is_empty() {
            println!();
            return Ok(());
        }
        for n in answer.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()) {
            match n.parse::<usize>().ok().and_then(|i| ALL.get(i.wrapping_sub(1))) {
                Some(&f) => filters.toggle(f),
                None => println!("  there is no filter {n}"),
            }
        }
    }
}

/// Where a finished pod goes: a file on disk, straight to someone over a wormhole, or
/// nowhere (a dry run that only shows the plan).
enum Dest {
    File(Option<PathBuf>),
    Wormhole,
    Nowhere,
}

fn share(session: Option<String>, agent: Option<Agent>, dest: Dest, mut filters: Filters, yes: bool) -> Result<()> {
    let start = env::current_dir()?;
    let (agent, path) = match session {
        Some(id) => agent::find(agent, &start, Some(&id))?,
        None => choose_session(&start, agent, yes)?,
    };
    // The session id ends the file name (Codex puts the time before it).
    let stem = path.file_stem().unwrap().to_string_lossy().into_owned();
    let id = stem.get(stem.len().saturating_sub(36)..).filter(|t| uuid::Uuid::parse_str(t).is_ok()).map_or(stem.clone(), String::from);
    let short: String = id.chars().take(8).collect();
    let cwd = agent.cwd(&session::load(&path)?).unwrap_or_else(|| start.clone());
    let root = project_root(&cwd)?;
    let home = session::canonical(&session::home())?;
    ensure!(
        !home.starts_with(&root),
        "this session ran in {}, your home folder or above it, so there is no project folder to share; \
         start the session inside a project",
        root.display()
    );
    const PERSONAL: &[&str] = &["Documents", "Desktop", "Downloads", "Pictures", "Movies", "Music", "Library"];
    ensure!(
        !(root.parent() == Some(&home) && root.file_name().is_some_and(|n| PERSONAL.contains(&&*n.to_string_lossy()))),
        "this session ran in {}, a personal folder rather than a project; start the session inside a project",
        root.display()
    );
    let name = root.file_name().map_or("pod".into(), |n| n.to_string_lossy().into_owned());
    let identity = identity(&root, &home);
    // --exclude paths are relative to where you are, like any other path you type.
    let here = env::current_dir()?;
    filters.excluded = std::mem::take(&mut filters.excluded)
        .into_iter()
        .map(|p| {
            let abs = session::normalize(&here.join(&p));
            let rel = abs.strip_prefix(&root).map(Path::to_path_buf).map_err(|_| anyhow::anyhow!("--exclude {} is outside the project {}", p.display(), root.display()))?;
            ensure!(abs.exists(), "--exclude {}: no such file in the project", p.display());
            Ok(rel)
        })
        .collect::<Result<_>>()?;
    if !on_path("git") && filters.on(Filter::Gitignored) && repo_of(&cwd).is_some() {
        bail!("git isn't installed, so podshare can't tell which files are gitignored; install git, or pass --allow gitignored");
    }

    let place = root.strip_prefix(&home).map_or(root.display().to_string(), |r| format!("~/{}", r.display()));
    println!("podshare · {} session {short} · {place}\n", agent.label());
    let doing = match dest {
        Dest::Wormhole => "sending",
        Dest::File(_) => "packing",
        Dest::Nowhere => "would send",
    };
    let mut p = plan(agent, &path, &cwd, &root, &home, &identity, &filters)?;
    print_plan(&p, &filters, doing);
    if matches!(dest, Dest::Nowhere) {
        print_report(&p, &filters);
        print_details(&p);
        return Ok(());
    }
    // Large files are left out unless the sender says otherwise: ask rather than drop them silently.
    let large: Vec<(String, u64)> = p
        .left_out
        .keys()
        .filter(|(why, _)| why == "over 10 MB")
        .filter_map(|(_, what)| fs::metadata(root.join(what)).ok().map(|m| (what.clone(), m.len())))
        .collect();
    if !yes && !large.is_empty() && filters.on(Filter::LargeFiles) {
        let total: u64 = large.iter().map(|(_, n)| n).sum();
        let names: Vec<&str> = large.iter().map(|(w, _)| w.as_str()).collect();
        let question = format!("Include {} over 10 MB ({}: {})? They're still checked for secrets. [y/N]", count(large.len(), "file"), size(total), list(&names));
        if matches!(ask(&question)?.as_str(), "y" | "yes") {
            filters.toggle(Filter::LargeFiles);
            p = plan(agent, &path, &cwd, &root, &home, &identity, &filters)?;
            print_plan(&p, &filters, doing);
        }
    }
    if !yes {
        loop {
            let verb = if matches!(dest, Dest::Wormhole) { "Send" } else { "Create" };
            match ask(&format!("{verb}? [y/N, c=choose files, d=details, f=filters]"))?.as_str() {
                "y" | "yes" => break,
                "d" => {
                    print_report(&p, &filters);
                    print_details(&p);
                    println!();
                }
                "c" => {
                    choose_files(&p, &root, &mut filters)?;
                    p = plan(agent, &path, &cwd, &root, &home, &identity, &filters)?;
                    print_plan(&p, &filters, doing);
                }
                "f" => {
                    edit_filters(&mut filters)?;
                    p = plan(agent, &path, &cwd, &root, &home, &identity, &filters)?;
                    print_plan(&p, &filters, doing);
                }
                _ => bail!("cancelled; nothing was written"),
            }
        }
    }

    let manifest = json!({
        "format": 2,
        "agent": agent.name(),
        "agent_version": p.agent_version,
        "name": name,
        "session": id,
        "messages": p.messages,
        "tokens": p.tokens,
        "instructions": p.instructions.iter().map(|r| portable(r)).collect::<Vec<_>>(),
        "skills": p.skills.iter().map(|r| portable(r)).collect::<Vec<_>>(),
        "filters_off": filters.off(),
        "files_left_out_by_sender": filters.excluded.len(),
    });
    let transcript = p.cleaned.lines.iter().map(|l| l.to_string() + "\n").collect::<String>().into_bytes();
    let conversation = agent.to_neutral(&p.cleaned.lines).iter().map(|l| l.to_string() + "\n").collect::<String>().into_bytes();
    let files_count = p.files.len();
    let pod = bundle::Pod { manifest, transcript, conversation, files: p.files.into_values().map(|f| (f.rel, f.bytes)).collect() };
    let (sealed, key) = bundle::seal(&pod)?;
    let file_name = format!("{name}-{short}.pod");
    let out: PathBuf = match dest {
        Dest::Wormhole => {
            println!("✓ packed {}, encrypted", size(sealed.len() as u64));
            let summary = json!({ "name": name, "agent": agent.label(), "messages": p.messages, "tokens": p.tokens,
                "files": files_count, "bytes": sealed.len() });
            return wormhole::send(&file_name, sealed, &key, &summary);
        }
        // A folder given with -o gets the usual file name inside it.
        Dest::File(Some(dir)) if dir.is_dir() => dir.join(&file_name),
        Dest::File(out) => out.unwrap_or_else(|| PathBuf::from(&file_name)),
        Dest::Nowhere => unreachable!("dry runs stop after the plan"),
    };
    fs::write(&out, &sealed).with_context(|| format!("writing {}", out.display()))?;
    println!("✓ wrote {} ({}, encrypted)", out.display(), size(sealed.len() as u64));
    println!("  Anyone with this line can open it; share it only with the person you mean to:\n");
    println!("  podshare open {}", shell_quote(&format!("{}#k={key}", out.display())));
    Ok(())
}

/// The session to share from `cwd`: the only one, the most recent (when not asked), or the
/// one the user picks from a list.
fn choose_session(cwd: &Path, only: Option<Agent>, yes: bool) -> Result<(Agent, PathBuf)> {
    use std::io::IsTerminal;
    let mut found = agent::list(cwd, only);
    let who = only.map_or("Claude Code or Codex".to_string(), |a| a.label().to_string());
    ensure!(!found.is_empty(), "no {who} sessions for {}; run podshare in the folder you used the agent in", cwd.display());
    if found.len() == 1 || yes || !io::stdin().is_terminal() {
        let f = found.remove(0);
        return Ok((f.agent, f.path));
    }
    if found.len() > 20 {
        println!("  Showing the 20 most recent of {}. `podshare list` shows them all; pick one with --session <id>.\n", found.len());
        found.truncate(20);
    }
    let items: Vec<String> = found
        .iter()
        .map(|f| format!("{:<11}  {:>11}  {}", f.agent.label(), ago(f.modified), convert::short_line(&plain(&f.title), 70)))
        .collect();
    let chosen = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
        .with_prompt("Which session? (↑↓ move, enter choose, esc cancel)")
        .items(&items)
        .default(0)
        .interact_opt()?
        .context("cancelled; nothing was shared")?;
    let f = found.swap_remove(chosen);
    println!();
    Ok((f.agent, f.path))
}

/// How long ago, the way people say it.
fn ago(t: std::time::SystemTime) -> String {
    let s = std::time::SystemTime::now().duration_since(t).map_or(0, |d| d.as_secs());
    match s {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", s / 60),
        3600..=86_399 => format!("{} h ago", s / 3600),
        86_400..=172_799 => "1 day ago".into(),
        172_800..=2_591_999 => format!("{} days ago", s / 86_400),
        2_592_000..=5_183_999 => "1 month ago".into(),
        _ => format!("{} months ago", s / 2_592_000),
    }
}

/// Shows what a sender is offering, before anything downloads, and asks to accept it.
/// Whether `dir` is taken: a file, or a folder with something in it.
fn busy(dir: &Path) -> bool {
    dir.is_file() || dir.is_symlink() || dir.read_dir().is_ok_and(|mut d| d.next().is_some())
}

/// `name`, or `name-2`, `name-3`… if that is taken.
fn free_dir(name: &str) -> PathBuf {
    (1..).map(|i| if i == 1 { PathBuf::from(name) } else { PathBuf::from(format!("{name}-{i}")) }).find(|d| !busy(d)).unwrap()
}

fn incoming(summary: &Value, size: u64, yes: bool) -> Result<bool> {
    let text = |k: &str| summary[k].as_str().map(plain);
    let count = |k: &str| summary[k].as_u64();
    let mut parts: Vec<String> = vec![];
    parts.extend(text("name"));
    parts.extend(text("agent").map(|a| format!("{a} session")));
    parts.extend(count("messages").map(|n| format!("{n} messages")));
    parts.extend(count("tokens").map(|n| format!("about {} tokens", convert::short_count(n as usize))));
    parts.extend(count("files").map(|n| format!("{n} files")));
    parts.push(self::size(size));
    println!("Incoming (as the sender describes it; checked again after download):\n  {}\n", parts.join(" · "));
    Ok(yes || matches!(ask("Accept? [Y/n]")?.as_str(), "" | "y" | "yes"))
}

fn open(target: &str, into: Option<PathBuf>, agent: Option<Agent>, yes: bool, launch: bool) -> Result<()> {
    let (file, key) = target.rsplit_once("#k=").context("expected <file>.pod#k=<key>, as `podshare pack` printed it")?;
    let data = fs::read(file).with_context(|| format!("reading {file}"))?;
    open_pod(&data, key, into, agent, yes, launch)
}

/// A received skill without `allowed-tools` in its frontmatter: a skill from someone else
/// shouldn't run tools without asking.
fn without_tool_grants(bytes: &[u8]) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(bytes) else { return bytes.to_vec() };
    let Some(rest) = text.strip_prefix("---\n").or_else(|| text.strip_prefix("---\r\n")) else { return bytes.to_vec() };
    let Some(end) = rest.find("\n---") else { return bytes.to_vec() };
    let mut out = String::from("---\n");
    let mut grant = false;
    for line in rest[..end].lines() {
        // A grant can continue on indented lines (a YAML list).
        if grant && (line.starts_with([' ', '\t']) || line.trim().is_empty()) {
            continue;
        }
        grant = line.to_lowercase().starts_with("allowed-tools") || line.to_lowercase().starts_with("allowed_tools");
        if !grant {
            out.push_str(line);
            out.push('\n');
        }
    }
    out.push_str(rest[end..].trim_start_matches(['\r', '\n']));
    out.into_bytes()
}

fn open_pod(data: &[u8], key: &str, into: Option<PathBuf>, target: Option<Agent>, yes: bool, launch: bool) -> Result<()> {
    let pod = bundle::unseal(data, key, bundle::Limits { total: 2 << 30, file: HARD_MAX_FILE })?;
    let m = &pod.manifest;
    let from = m["agent"].as_str().unwrap_or("claude-code");
    let source = Agent::from_name(from).with_context(|| format!("this pod comes from {}, which this podshare can't resume; try updating podshare", plain(from)))?;
    // The name comes from the sender: use it only if it is a plain folder name.
    let name = m["name"].as_str().filter(|n| {
        plain(n) == *n && matches!(Path::new(n).components().collect::<Vec<_>>()[..], [Component::Normal(_)])
    });
    // A folder you name must be free; otherwise the project's name, or name-2 if that's taken.
    let dir = match into {
        Some(dir) => {
            ensure!(!busy(&dir), "{} already exists and isn't empty; pick a new folder for --into", dir.display());
            dir
        }
        None => free_dir(name.unwrap_or("pod")),
    };

    let messages = m["messages"].as_u64().unwrap_or(0);
    println!(
        "podshare open · {} · {} session · {} files · {messages} messages\n",
        name.unwrap_or("pod"),
        source.label(),
        pod.files.len()
    );
    // Continue in the agent asked for; if the session's own agent isn't installed but the
    // other one is, offer that.
    let mut agent = target.unwrap_or(source);
    let both = on_path(source.program()) && on_path(source.other().program());
    if target.is_none() && both && !yes && !pod.conversation.is_empty() && std::io::IsTerminal::is_terminal(&io::stdin()) {
        let other = source.other();
        let items = [format!("{:<12} (what they used)", source.label()), other.label().to_string()];
        let chosen = dialoguer::Select::with_theme(&dialoguer::theme::ColorfulTheme::default())
            .with_prompt("Continue in?")
            .items(&items)
            .default(0)
            .interact_opt()?
            .context("cancelled")?;
        if chosen == 1 {
            agent = other;
        }
    } else if target.is_none() && !on_path(source.program()) && on_path(source.other().program()) {
        let other = source.other();
        let question = format!("{} isn't installed here. Continue this session in {} instead? [Y/n]", source.label(), other.label());
        if yes || matches!(ask(&question)?.as_str(), "" | "y" | "yes") {
            agent = other;
        }
    }
    let carried = agent != source;
    ensure!(!carried || !pod.conversation.is_empty(), "this pod has no portable conversation; open it in {}", source.label());
    // Counted here from what arrived, not taken from the sender's manifest.
    let neutral: Vec<Value> = std::str::from_utf8(&pod.conversation)
        .unwrap_or("")
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let tokens = if carried {
        agent.text_tokens(convert::turns_chars(&convert::turns(&neutral, source.label())))
    } else {
        let lines: Vec<Value> = std::str::from_utf8(&pod.transcript).unwrap_or("").lines().filter_map(|l| serde_json::from_str(l).ok()).collect();
        source.estimate_tokens(&lines)
    };
    if carried {
        // Long tool results are trimmed on the way across, so this is usually less than the sender saw.
        println!("  About {} tokens for {} to read when it resumes (long tool results are trimmed).", convert::short_count(tokens), agent.label());
    } else {
        println!("  About {} tokens of conversation for {} to read when it resumes.", convert::short_count(tokens), agent.label());
    }
    if tokens > LARGE {
        println!("  ! That's a lot of context: {} may summarise the oldest parts.", agent.label());
    }
    if carried {
        println!("  Continuing a {} session in {}: its tool calls come across as text.", source.label(), agent.label());
    }
    println!();
    let listed = |key: &str| m[key].as_array().into_iter().flatten().filter_map(Value::as_str).map(plain).collect::<Vec<_>>();
    let steering = [listed("instructions"), listed("skills")].concat();
    if !steering.is_empty() {
        println!("  These files steer the agent. Read them if you don't trust the sender:");
        steering.iter().for_each(|p| println!("    {p}"));
    }
    let off = listed("filters_off");
    if !off.is_empty() {
        println!("  ⚠ The sender turned off these safety filters: {}", off.join(", "));
    }
    println!("  Pods never carry hooks, MCP servers or settings; podshare refuses any that do.");
    println!("  Treat the files like a repo from a stranger: read before you run them.\n");
    if !yes && !matches!(ask(&format!("Unpack into {}? [Y/n]", dir.display()))?.as_str(), "" | "y" | "yes") {
        bail!("cancelled; nothing was written");
    }

    fs::create_dir_all(&dir)?;
    let dir = session::canonical(&dir)?;
    // Build the transcript before writing anything, so a broken pod leaves no files behind.
    let (id, transcript) = if carried {
        let mut neutral = vec![];
        for line in std::str::from_utf8(&pod.conversation).context("conversation is not text")?.lines() {
            let mut v: Value = serde_json::from_str(line).context("conversation line is not JSON")?;
            session::replace_strings(&mut v, session::ROOT_URL, &session::url_path(&dir.to_string_lossy()));
            session::replace_strings(&mut v, session::ROOT, &dir.to_string_lossy());
            neutral.push(v);
        }
        agent.from_turns(&convert::turns(&neutral, source.label()), &dir, RESUME_NOTE)
    } else {
        agent.prepare(&pod.transcript, &dir, RESUME_NOTE)?
    };
    let written = pod.files.iter().try_for_each(|(rel, bytes)| {
        let path = dir.join(rel);
        fs::create_dir_all(path.parent().unwrap())?;
        if rel.starts_with(".claude/skills") || rel.starts_with(".agents/skills") {
            fs::write(&path, without_tool_grants(bytes))?;
            // Each agent loads skills from its own folder: put a copy where this one looks.
            let (from, to) = match agent {
                Agent::Codex => (".claude/skills", ".agents/skills"),
                Agent::ClaudeCode => (".agents/skills", ".claude/skills"),
            };
            if let Ok(inner) = rel.strip_prefix(from) {
                let copy = dir.join(to).join(inner);
                if !copy.exists() {
                    fs::create_dir_all(copy.parent().unwrap())?;
                    fs::write(&copy, without_tool_grants(bytes))?;
                }
            }
            Ok(())
        } else {
            fs::write(&path, bytes)
        }
    });
    if let Err(e) = written {
        // The folder was empty or new, so removing it leaves things as they were.
        let _ = fs::remove_dir_all(&dir);
        return Err(e).context("unpacking failed; nothing was kept");
    }
    // Remember what arrived, so sharing this folder again passes the files on even when the
    // session no longer records them as tool calls (a session carried over between agents).
    let received: Vec<String> = pod.files.iter().map(|(rel, _)| portable(rel)).collect();
    fs::create_dir_all(dir.join(RECEIVED).parent().unwrap())?;
    fs::write(dir.join(RECEIVED), serde_json::to_vec_pretty(&json!({ "files": received }))?)?;
    agent.install(&dir, &id, &transcript)?;
    println!("✓ unpacked into {}", dir.display());

    let (program, args) = agent.resume_command(&id, RESUME_NOTE);
    let quoted: Vec<String> = args.iter().map(|a| shell_quote(a)).collect();
    let then = if cfg!(windows) { ";" } else { " &&" };
    let resume = format!("cd {}{then} {program} {}", shell_quote(&dir.to_string_lossy()), quoted.join(" "));
    if !on_path(program) {
        println!("  {} isn't installed here. Get it from {}, then resume with:\n  {resume}", agent.label(), agent.homepage());
    } else if launch && (yes || matches!(ask(&format!("Start {} there now, {}? [Y/n]", agent.label(), agent.safe_mode()))?.as_str(), "" | "y" | "yes")) {
        println!("  {} will ask whether you trust this folder: say yes to continue.\n", agent.label());
        let exe = find_program(program).unwrap_or_else(|| PathBuf::from(program));
        Command::new(exe).args(&args).current_dir(&dir).status().with_context(|| format!("starting {program}"))?;
    } else {
        println!("  resume with: {resume}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn received_skills_lose_their_tool_grants() {
        let skill = "---\nname: deploy\nallowed-tools:\n  - Bash\n  - Write\ndescription: ships it\n---\nRun the deploy.\n";
        let out = String::from_utf8(without_tool_grants(skill.as_bytes())).unwrap();
        assert_eq!(out, "---\nname: deploy\ndescription: ships it\n---\nRun the deploy.\n");
        assert_eq!(without_tool_grants(b"no frontmatter"), b"no frontmatter");
    }
}
