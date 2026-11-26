//! Files, processes and the server state the entrypoint leaves in /run/sftp.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};
use serde::Serialize;
use sftp_webui::proto::{Actor, AuditEntry};
use sftp_webui::timefmt;

pub const ENTRYPOINT: &str = "/usr/local/bin/entrypoint";
pub const RUN_DIR: &str = "/run/sftp";
pub const USERS_CONF: &str = "/config/sshd/users.conf";
pub const GROUPS_CONF: &str = "/config/sshd/groups.conf";
pub const SETTINGS_CONF: &str = "/config/sshd/settings.conf";
pub const USER_KEYS: &str = "/config/userkeys";
pub const WEBUI_JAIL: &str = "/config/fail2ban/jail.d/00-webui.local";
pub const AUDIT_DIR: &str = "/config/audit";
pub const AUDIT_LOG: &str = "/config/audit/webui.log";
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub fn log(msg: &str) {
    println!("{} sftp-helper: {msg}", timefmt::iso(timefmt::now()));
}

/// The result of a request: data for a read, and what apply said.
#[derive(Default)]
pub struct Outcome {
    pub data: serde_json::Value,
    pub messages: Vec<String>,
}

impl Outcome {
    pub fn data<T: Serialize>(value: T) -> std::result::Result<Outcome, Failure> {
        match serde_json::to_value(value) {
            Ok(data) => Ok(Outcome { data, messages: Vec::new() }),
            Err(e) => Err(Failure::new(format!("cannot encode the reply: {e}"))),
        }
    }

    pub fn messages(messages: Vec<String>) -> Outcome {
        Outcome { data: serde_json::Value::Null, messages }
    }
}

/// Why a request failed, with what apply said when it ran.
pub struct Failure {
    pub error: String,
    pub messages: Vec<String>,
}

impl Failure {
    pub fn new(error: impl Into<String>) -> Failure {
        Failure { error: error.into(), messages: Vec::new() }
    }
}

impl From<anyhow::Error> for Failure {
    fn from(e: anyhow::Error) -> Failure {
        Failure::new(format!("{e:#}"))
    }
}

impl From<String> for Failure {
    fn from(e: String) -> Failure {
        Failure::new(e)
    }
}

/// The uid and gid of a user in /etc/passwd.
pub fn ids_of(name: &str) -> Result<(u32, u32)> {
    match passwd_entry(name)? {
        Some(entry) => Ok((entry.uid, entry.gid)),
        None => bail!("there is no user {name}"),
    }
}

pub struct PasswdEntry {
    pub uid: u32,
    pub gid: u32,
    pub gecos: String,
}

pub fn passwd_entry(name: &str) -> Result<Option<PasswdEntry>> {
    let text = fs::read_to_string("/etc/passwd").context("cannot read /etc/passwd")?;
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0] != name {
            continue;
        }
        let uid = f[2].parse().with_context(|| format!("bad uid for {name} in /etc/passwd"))?;
        let gid = f[3].parse().with_context(|| format!("bad gid for {name} in /etc/passwd"))?;
        return Ok(Some(PasswdEntry { uid, gid, gecos: f[4].to_string() }));
    }
    Ok(None)
}

/// Reads a file, or None when it does not exist.
pub fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

pub fn read_text(path: &Path) -> Result<String> {
    match read_optional(path)? {
        Some(b) => String::from_utf8(b).with_context(|| format!("{} is not UTF-8 text", path.display())),
        None => Ok(String::new()),
    }
}

pub fn remove_file(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("cannot remove {}", path.display())),
    }
}

/// Replaces a file in one rename, so no reader sees half of it. The new
/// file keeps the old one's mode and owner, or gets `mode` and root.
pub fn write_atomic(path: &Path, content: &[u8], mode: u32) -> Result<()> {
    let dir = match path.parent() {
        Some(d) => d,
        None => bail!("{} has no directory", path.display()),
    };
    let (mode, uid, gid) = match fs::metadata(path) {
        Ok(m) => (m.permissions().mode() & 0o7777, m.uid(), m.gid()),
        Err(e) if e.kind() == ErrorKind::NotFound => (mode, 0, 0),
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
    };
    let name = match path.file_name() {
        Some(n) => n.to_string_lossy().into_owned(),
        None => bail!("{} has no file name", path.display()),
    };
    let tmp = dir.join(format!(".{name}.webui-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("cannot create {}", tmp.display()))?;
    let written = file
        .write_all(content)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::os::unix::fs::fchown(&file, Some(uid), Some(gid)))
        .and_then(|()| file.set_permissions(fs::Permissions::from_mode(mode)));
    if let Err(e) = written {
        remove_file(&tmp)?;
        return Err(e).with_context(|| format!("cannot write {}", tmp.display()));
    }
    fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
}

/// A file as it was before a change, to put back if the change fails.
pub struct Backup {
    path: PathBuf,
    content: Option<Vec<u8>>,
    mode: u32,
}

impl Backup {
    pub fn of(path: &Path) -> Result<Backup> {
        let content = read_optional(path)?;
        let mode = match fs::metadata(path) {
            Ok(m) => m.permissions().mode() & 0o7777,
            Err(e) if e.kind() == ErrorKind::NotFound => 0o600,
            Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", path.display())),
        };
        Ok(Backup { path: path.to_path_buf(), content, mode })
    }

    pub fn content(&self) -> Option<&[u8]> {
        self.content.as_deref()
    }

    pub fn restore(&self) -> Result<()> {
        match &self.content {
            Some(c) => {
                if let Some(dir) = self.path.parent() {
                    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
                }
                write_atomic(&self.path, c, self.mode)
            }
            None => remove_file(&self.path),
        }
    }
}

/// Runs `entrypoint apply` and returns what it said, line by line.
pub fn apply() -> std::result::Result<Vec<String>, Vec<String>> {
    let (mut reader, writer) = match std::io::pipe() {
        Ok(p) => p,
        Err(e) => return Err(vec![format!("cannot start entrypoint apply: {e}")]),
    };
    let child = {
        let writer2 = match writer.try_clone() {
            Ok(w) => w,
            Err(e) => return Err(vec![format!("cannot start entrypoint apply: {e}")]),
        };
        let mut cmd = Command::new(ENTRYPOINT);
        cmd.arg("apply")
            .env_clear()
            .env("PATH", PATH)
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(writer2);
        cmd.spawn()
    };
    let mut child = match child {
        Ok(c) => c,
        Err(e) => return Err(vec![format!("cannot start entrypoint apply: {e}")]),
    };
    let mut out = String::new();
    let read = reader.read_to_string(&mut out);
    let status = child.wait();
    let mut lines: Vec<String> = out.lines().map(strip_timestamp).filter(|l| !l.is_empty()).collect();
    if let Err(e) = read {
        lines.push(format!("cannot read what entrypoint apply said: {e}"));
        return Err(lines);
    }
    match status {
        Ok(s) if s.success() => Ok(lines),
        Ok(s) => {
            lines.push(format!("entrypoint apply exited with {s}"));
            Err(lines)
        }
        Err(e) => {
            lines.push(format!("cannot wait for entrypoint apply: {e}"));
            Err(lines)
        }
    }
}

fn strip_timestamp(line: &str) -> String {
    match line.split_once(" entrypoint: ") {
        Some((_, rest)) => rest.to_string(),
        None => line.to_string(),
    }
}

/// Applies the configuration; if apply refuses it, puts every file back as
/// it was and applies that, so the server keeps its previous state.
pub fn apply_or_restore(backups: &[Backup]) -> std::result::Result<Outcome, Failure> {
    match apply() {
        Ok(messages) => Ok(Outcome::messages(messages)),
        Err(messages) => {
            let mut failure = Failure {
                error: "the server refused the change, so nothing was changed".into(),
                messages,
            };
            for b in backups {
                if let Err(e) = b.restore() {
                    failure.messages.push(format!("cannot restore {}: {e:#}", b.path.display()));
                }
            }
            if let Err(again) = apply() {
                failure.messages.push("applying the previous configuration failed too:".into());
                failure.messages.extend(again);
            }
            Err(failure)
        }
    }
}

/// An account as the entrypoint applied it, from /run/sftp/accounts.
pub struct StateAccount {
    pub name: String,
    pub source: String,
    pub uid: u32,
    pub gid: u32,
    pub dirs: Vec<String>,
    pub options: String,
    pub password: bool,
    pub rsync_from_env: bool,
    pub rsync_ready: bool,
}

pub fn read_state() -> Result<Vec<StateAccount>> {
    let text = read_text(&Path::new(RUN_DIR).join("accounts"))?;
    let mut accounts = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 9 {
            bail!("unexpected line in {RUN_DIR}/accounts: {line}");
        }
        let dirs = f[4].split(',').filter(|d| !d.is_empty()).map(str::to_string).collect();
        accounts.push(StateAccount {
            name: f[0].to_string(),
            source: f[1].to_string(),
            uid: f[2].parse().with_context(|| format!("bad uid in {RUN_DIR}/accounts: {line}"))?,
            gid: f[3].parse().with_context(|| format!("bad gid in {RUN_DIR}/accounts: {line}"))?,
            dirs,
            options: f[5].to_string(),
            password: f[6] == "set",
            rsync_from_env: f[7] == "yes",
            rsync_ready: f[8] == "yes",
        });
    }
    Ok(accounts)
}

/// The variables the container started with, without SFTP_USERS, which
/// holds passwords.
pub fn saved_environment() -> Result<Vec<(String, String)>> {
    let raw = match read_optional(&Path::new(RUN_DIR).join("env"))? {
        Some(r) => r,
        None => return Ok(Vec::new()),
    };
    let mut vars = Vec::new();
    for item in raw.split(|b| *b == 0) {
        if item.is_empty() {
            continue;
        }
        let text = String::from_utf8_lossy(item);
        if let Some((k, v)) = text.split_once('=')
            && k != "SFTP_USERS"
        {
            vars.push((k.to_string(), v.to_string()));
        }
    }
    Ok(vars)
}

/// Hashes a password with yescrypt, as `mkpasswd -m yescrypt` does.
pub fn mkpasswd(password: &str) -> Result<String> {
    let mut child = Command::new("/usr/bin/mkpasswd")
        .args(["--method=yescrypt", "--stdin"])
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run mkpasswd")?;
    match child.stdin.take() {
        Some(mut stdin) => stdin
            .write_all(format!("{password}\n").as_bytes())
            .context("cannot hand the password to mkpasswd")?,
        None => bail!("mkpasswd has no input"),
    }
    let out = child.wait_with_output().context("mkpasswd failed")?;
    if !out.status.success() {
        bail!("mkpasswd failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    let hash = String::from_utf8(out.stdout).context("mkpasswd printed something that is not text")?;
    let hash = hash.trim().to_string();
    if !hash.starts_with("$y$") || hash.contains(':') || hash.chars().any(char::is_whitespace) {
        return Err(anyhow!("mkpasswd printed an unexpected hash"));
    }
    Ok(hash)
}

/// Runs nft with `args`, writing `script` to its standard input when one is
/// given: its standard output, or the first line of what it said when it
/// failed.
pub fn nft(args: &[&str], script: Option<&str>) -> Result<String, String> {
    let mut child = Command::new("/usr/sbin/nft")
        .args(args)
        .env_clear()
        .env("PATH", PATH)
        .stdin(if script.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run nft: {e}"))?;
    if let Some(text) = script {
        match child.stdin.take() {
            Some(mut stdin) => stdin.write_all(text.as_bytes()).map_err(|e| format!("cannot hand nft its rules: {e}"))?,
            None => return Err("nft has no input".into()),
        }
    }
    let out = child.wait_with_output().map_err(|e| format!("nft failed: {e}"))?;
    if out.status.success() {
        return String::from_utf8(out.stdout).map_err(|e| format!("nft printed something that is not text: {e}"));
    }
    let said = String::from_utf8_lossy(&out.stderr);
    Err(match said.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(line) => line.to_string(),
        None => format!("nft failed with {}", out.status),
    })
}

/// Runs a command and returns its standard output.
pub fn run(program: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(program)
        .args(args)
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("cannot run {program}"))?;
    if !out.status.success() {
        bail!("{program} {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr).trim());
    }
    String::from_utf8(out.stdout).with_context(|| format!("{program} printed something that is not text"))
}

/// Appends one entry to the audit log and copies it to the container log.
pub fn audit(actor: &Actor, action: &str, target: &str, outcome: &str) -> Result<()> {
    for text in [&actor.admin, &actor.address, &action.to_string(), &target.to_string(), &outcome.to_string()] {
        if text.chars().any(char::is_control) {
            bail!("an audit entry may not contain control characters");
        }
    }
    let entry = AuditEntry {
        time: timefmt::now(),
        admin: actor.admin.clone(),
        address: actor.address.clone(),
        action: action.to_string(),
        target: target.to_string(),
        outcome: outcome.to_string(),
    };
    let mut line = serde_json::to_vec(&entry).context("cannot encode the audit entry")?;
    line.push(b'\n');
    fs::create_dir_all(AUDIT_DIR).with_context(|| format!("cannot create {AUDIT_DIR}"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(AUDIT_LOG)
        .with_context(|| format!("cannot open {AUDIT_LOG}"))?;
    file.write_all(&line).with_context(|| format!("cannot write {AUDIT_LOG}"))?;
    log(&format!(
        "audit: {} from {}: {action} {target}: {outcome}",
        actor.admin, actor.address
    ));
    Ok(())
}

/// A text file edited line by line: lines nobody touched are written back
/// byte for byte, and new lines take the file's own line ending.
pub struct TextFile {
    pub lines: Vec<String>,
    crlf: bool,
}

impl TextFile {
    pub fn parse(text: &str) -> TextFile {
        let crlf = text.contains("\r\n");
        let lines = text.split_inclusive('\n').map(str::to_string).collect();
        TextFile { lines, crlf }
    }

    pub fn ending(&self) -> &'static str {
        if self.crlf { "\r\n" } else { "\n" }
    }

    /// The text of a line without its ending and trailing white space.
    pub fn content(line: &str) -> &str {
        line.trim_end()
    }

    pub fn push(&mut self, text: &str) {
        let ending = self.ending();
        if let Some(last) = self.lines.last_mut()
            && !last.ends_with('\n')
        {
            last.push_str(ending);
        }
        self.lines.push(format!("{text}{ending}"));
    }

    pub fn replace(&mut self, index: usize, text: &str) {
        let ending = if self.lines[index].ends_with('\n') { self.ending() } else { "" };
        self.lines[index] = format!("{text}{ending}");
    }

    pub fn render(&self) -> String {
        self.lines.concat()
    }
}
