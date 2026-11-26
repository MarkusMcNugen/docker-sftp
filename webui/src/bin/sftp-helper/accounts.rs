//! Accounts and their public keys. The web UI edits only accounts defined
//! in /config/sshd/users.conf, line by line, keeping every other line as it
//! was; keys live in /config/userkeys whichever file defines the account.

use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sftp_webui::proto::{AccountInput, AccountView, Accounts, KeyView, PasswordChange};
use sftp_webui::spec::{self, Line};
use sftp_webui::sshkey::PublicKey;
use sftp_webui::timefmt;

use crate::runtime;
use crate::system::{self, Backup, Failure, Outcome, StateAccount, TextFile};

/// The file keys added in the web UI go to, in the account's key directory.
const WEBUI_KEYS: &str = "webui.pub";

/// True for a line that defines something: not blank, not a comment.
pub(crate) fn is_spec(line: &str) -> bool {
    let t = TextFile::content(line).trim_start();
    !t.is_empty() && !t.starts_with('#')
}

/// The name a definition line starts with, before its first colon.
pub(crate) fn name_of(line: &str) -> &str {
    let t = TextFile::content(line).trim_start();
    match t.split_once(':') {
        Some((n, _)) => n,
        None => t,
    }
}

/// The first line of users.conf that defines the account, parsed.
fn find(conf: &TextFile, name: &str) -> Result<Option<(usize, Line)>, String> {
    for (i, line) in conf.lines.iter().enumerate() {
        if is_spec(line) && name_of(line) == name {
            return spec::parse_line(TextFile::content(line).trim_start()).map(|l| Some((i, l)));
        }
    }
    Ok(None)
}

fn password_state(line: &Line) -> &'static str {
    if line.password.is_empty() {
        "none"
    } else if line.encrypted {
        "hashed"
    } else {
        "plain"
    }
}

fn locked(opts: &spec::Options) -> bool {
    if opts.disabled {
        return true;
    }
    match &opts.expires {
        Some(date) => timefmt::days_of(date) <= (timefmt::now() / 86_400) as i64,
        None => false,
    }
}

pub fn list() -> Result<Accounts> {
    let state = system::read_state()?;
    let conf = TextFile::parse(&system::read_text(Path::new(system::USERS_CONF))?);
    let sessions = runtime::sessions()?;
    let mut by_name: HashMap<&str, Vec<sftp_webui::proto::SessionInfo>> = HashMap::new();
    for s in &sessions {
        by_name.entry(s.account.as_str()).or_default().push(s.clone());
    }
    let mut out = Accounts::default();
    for account in &state {
        let options = spec::parse_options(&account.options)
            .map_err(|e| anyhow::anyhow!("account {}: {e}", account.name))?;
        let editable = account.source == "users.conf";
        let mut own = None;
        let mut own_gid = None;
        let password = if editable {
            match find(&conf, &account.name) {
                Ok(Some((_, line))) => {
                    if password_state(&line) == "plain" {
                        out.plain_passwords += 1;
                    }
                    let state = password_state(&line).to_string();
                    own_gid = line.gid;
                    own = Some(line.options);
                    state
                }
                Ok(None) => "none".to_string(),
                Err(e) => return Err(anyhow::anyhow!("users.conf: {e}")),
            }
        } else if account.password {
            "set".to_string()
        } else {
            "none".to_string()
        };
        let sessions = match by_name.get(account.name.as_str()) {
            Some(list) => list.clone(),
            None => Vec::new(),
        };
        out.accounts.push(AccountView {
            name: account.name.clone(),
            source: account.source.clone(),
            editable,
            uid: account.uid,
            gid: account.gid,
            dirs: account.dirs.clone(),
            expired: locked(&options),
            options,
            own,
            own_gid,
            password,
            rsync_from_env: account.rsync_from_env,
            rsync_ready: account.rsync_ready,
            keys: list_keys(&account.name)?,
            sessions,
        });
    }
    Ok(out)
}

fn effective<'a>(state: &'a [StateAccount], name: &str) -> Option<&'a StateAccount> {
    state.iter().find(|a| a.name == name)
}

fn source_label(source: &str) -> &'static str {
    match source {
        "legacy" => "/etc/sftp-users.conf",
        "users-file" => "the file SFTP_USERS_FILE names",
        "arguments" => "the container's arguments",
        "environment" => "SFTP_USERS",
        _ => "users.conf",
    }
}

fn require_editable(state: &[StateAccount], name: &str) -> Result<(), Failure> {
    match effective(state, name) {
        Some(a) if a.source == "users.conf" => Ok(()),
        Some(a) => Err(Failure::new(format!(
            "{name} is defined in {}, which the web UI does not change",
            source_label(&a.source)
        ))),
        None => Err(Failure::new(format!("there is no account named {name}"))),
    }
}

fn users_conf() -> PathBuf {
    PathBuf::from(system::USERS_CONF)
}

fn backup_file() -> PathBuf {
    PathBuf::from(format!("{}.bak", system::USERS_CONF))
}

/// Writes users.conf, keeping the previous version as users.conf.bak, then
/// applies it; when the entrypoint refuses, users.conf and every file in
/// `extra` are put back.
pub(crate) fn save_users_conf(conf: &TextFile, extra: Vec<Backup>) -> Result<Outcome, Failure> {
    let path = users_conf();
    let original = Backup::of(&path)?;
    let bak = Backup::of(&backup_file())?;
    if let Some(previous) = original.content() {
        system::write_atomic(&backup_file(), previous, 0o600)?;
    }
    system::write_atomic(&path, conf.render().as_bytes(), 0o600)?;
    let mut backups = vec![original, bak];
    backups.extend(extra);
    system::apply_or_restore(&backups)
}

pub fn put(create: bool, input: AccountInput) -> Result<Outcome, Failure> {
    spec::validate_name(&input.name)?;
    let name = input.name.clone();
    if let Some(entry) = system::passwd_entry(&name)?
        && entry.gecos != "sftp-managed"
    {
        return Err(Failure::new(format!("{name} is a system account of the image; choose another name")));
    }
    let state = system::read_state()?;
    let mut conf = TextFile::parse(&system::read_text(&users_conf())?);
    let existing = find(&conf, &name)?;
    if create {
        if effective(&state, &name).is_some() || existing.is_some() {
            return Err(Failure::new(format!("an account named {name} already exists")));
        }
    } else {
        require_editable(&state, &name)?;
        if existing.is_none() {
            return Err(Failure::new(format!("{name} is not in users.conf")));
        }
    }
    let (password, encrypted) = match input.password {
        PasswordChange::Keep => match &existing {
            Some((_, line)) => (line.password.clone(), line.encrypted),
            None => return Err(Failure::new("a new account needs a password, or public-key login only")),
        },
        PasswordChange::Clear => (String::new(), false),
        PasswordChange::Set { value } => {
            if value.is_empty() {
                return Err(Failure::new("the password is empty"));
            }
            if value.chars().any(char::is_control) {
                return Err(Failure::new("the password may not contain control characters"));
            }
            (system::mkpasswd(&value)?, true)
        }
    };
    let uid = match input.uid {
        Some(v) => Some(spec::check_id(u64::from(v), "uid")?),
        None => None,
    };
    let gid = match input.gid {
        Some(v) => Some(spec::check_id(u64::from(v), "gid")?),
        None => None,
    };
    let mut dirs = Vec::new();
    for dir in input.dirs {
        let dir = dir.trim().trim_matches('/').to_string();
        if dir.is_empty() {
            continue;
        }
        spec::validate_dir(&dir)?;
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    let mut options = input.options;
    options.normalize()?;
    // Full access is what an account without groups has anyway, so its line
    // leaves it out and reads back without it.
    if options.groups.is_empty() && spec::preset_of(&options.perms) == "full" {
        options.perms_set = false;
    }
    let line = Line { name: name.clone(), password, encrypted, uid, gid, dirs, options };
    let text = spec::format_line(&line);
    if spec::parse_line(&text)? != line {
        return Err(Failure::new("the account line does not read back as written"));
    }
    match existing {
        Some((index, _)) => conf.replace(index, &text),
        None => conf.push(&text),
    }
    save_users_conf(&conf, Vec::new())
}

pub fn delete(name: &str, delete_keys: bool) -> Result<Outcome, Failure> {
    let state = system::read_state()?;
    require_editable(&state, name)?;
    if state.len() <= 1 {
        return Err(Failure::new(
            "this is the only account, and the container needs one to start",
        ));
    }
    let mut conf = TextFile::parse(&system::read_text(&users_conf())?);
    conf.lines.retain(|line| !(is_spec(line) && name_of(line) == name));
    let mut extra = Vec::new();
    if delete_keys {
        for file in key_files(name)? {
            extra.push(Backup::of(&file)?);
            system::remove_file(&file)?;
        }
        let dir = Path::new(system::USER_KEYS).join(name);
        match fs::remove_dir(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound || e.kind() == ErrorKind::DirectoryNotEmpty => {}
            Err(e) => return Err(Failure::new(format!("cannot remove {}: {e}", dir.display()))),
        }
    }
    save_users_conf(&conf, extra)
}

pub fn hash_passwords() -> Result<Outcome, Failure> {
    let mut conf = TextFile::parse(&system::read_text(&users_conf())?);
    let mut changed = 0;
    for i in 0..conf.lines.len() {
        if !is_spec(&conf.lines[i]) {
            continue;
        }
        let mut line = spec::parse_line(TextFile::content(&conf.lines[i]).trim_start())?;
        if line.password.is_empty() || line.encrypted {
            continue;
        }
        line.password = system::mkpasswd(&line.password)?;
        line.encrypted = true;
        conf.replace(i, &spec::format_line(&line));
        changed += 1;
    }
    if changed == 0 {
        return Ok(Outcome::messages(vec!["users.conf holds no plain-text password".into()]));
    }
    let mut outcome = save_users_conf(&conf, Vec::new())?;
    outcome.messages.insert(0, format!("hashed {changed} plain-text password(s) with yescrypt"));
    Ok(outcome)
}

/// /config/userkeys/<name>.pub and /config/userkeys/<name>/*.pub, the files
/// the entrypoint reads.
fn key_files(name: &str) -> Result<Vec<PathBuf>> {
    let base = Path::new(system::USER_KEYS);
    let mut files = Vec::new();
    let single = base.join(format!("{name}.pub"));
    if single.is_file() {
        files.push(single);
    }
    let dir = base.join(name);
    let entries = match fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(files),
        Err(e) => return Err(e).with_context(|| format!("cannot list {}", dir.display())),
    };
    let mut more = Vec::new();
    for entry in entries {
        let path = entry.with_context(|| format!("cannot list {}", dir.display()))?.path();
        if path.extension().is_some_and(|x| x == "pub") && path.is_file() {
            more.push(path);
        }
    }
    more.sort();
    files.extend(more);
    Ok(files)
}

fn key_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
}

pub fn list_keys(name: &str) -> Result<Vec<KeyView>> {
    let mut keys = Vec::new();
    for file in key_files(name)? {
        let text = system::read_text(&file)?;
        let shown = file.display().to_string();
        for line in key_lines(&text) {
            keys.push(match PublicKey::parse(line) {
                Ok(k) => KeyView {
                    fingerprint: k.fingerprint(),
                    kind: k.kind.clone(),
                    bits: k.bits,
                    comment: k.comment.clone(),
                    file: shown.clone(),
                },
                Err(e) => KeyView {
                    fingerprint: String::new(),
                    kind: "unreadable".into(),
                    bits: 0,
                    comment: e,
                    file: shown.clone(),
                },
            });
        }
    }
    Ok(keys)
}

pub fn add_key(name: &str, text: &str) -> Result<Outcome, Failure> {
    let state = system::read_state()?;
    if effective(&state, name).is_none() {
        return Err(Failure::new(format!("there is no account named {name}")));
    }
    let key = PublicKey::parse(text)?;
    let fingerprint = key.fingerprint();
    if list_keys(name)?.iter().any(|k| k.fingerprint == fingerprint) {
        return Err(Failure::new(format!("{name} already has the key {fingerprint}")));
    }
    let dir = Path::new(system::USER_KEYS).join(name);
    fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let path = dir.join(WEBUI_KEYS);
    let backup = Backup::of(&path)?;
    let mut file = TextFile::parse(&system::read_text(&path)?);
    file.push(&key.line());
    system::write_atomic(&path, file.render().as_bytes(), 0o644)?;
    let mut outcome = system::apply_or_restore(&[backup])?;
    outcome.messages.insert(0, format!("added {} {fingerprint}", key.kind));
    Ok(outcome)
}

pub fn delete_key(name: &str, fingerprint: &str) -> Result<Outcome, Failure> {
    let mut backups = Vec::new();
    let mut removed = 0;
    for path in key_files(name)? {
        let text = system::read_text(&path)?;
        let mut file = TextFile::parse(&text);
        let before = file.lines.len();
        // A line that is not a key, such as a comment, cannot carry the
        // fingerprint and stays.
        file.lines.retain(|line| !PublicKey::parse(line).is_ok_and(|k| k.fingerprint() == fingerprint));
        if file.lines.len() == before {
            continue;
        }
        removed += before - file.lines.len();
        backups.push(Backup::of(&path)?);
        if key_lines(&file.render()).next().is_none() {
            system::remove_file(&path)?;
        } else {
            system::write_atomic(&path, file.render().as_bytes(), 0o644)?;
        }
    }
    if removed == 0 {
        return Err(Failure::new(format!("{name} has no key {fingerprint}")));
    }
    system::apply_or_restore(&backups)
}
