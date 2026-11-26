//! The file browser's share links. A link's token is shown to its maker
//! once and kept here only as its SHA-256, in /config/files/shares.json,
//! root-only, with the file it leads to, when it ends, its password's
//! argon2id hash when it has one, and whether it is claimed or spent. A link
//! is spent by one completed download; a download that fails gives it back.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sftp_webui::proto::{Secret, ShareMade, SharePolicy, ShareTarget, ShareView};
use sftp_webui::{auth, spec, sshkey, timefmt};

use crate::files;
use crate::settings;
use crate::system::{self, Failure, Outcome};

const STORE: &str = "/config/files/shares.json";
const DAY: u64 = 86_400;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    links: Vec<Link>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Link {
    id: String,
    sha256: String,
    /// The account whose file it is, and the account that made it.
    account: String,
    by: String,
    path: String,
    created: u64,
    expires: u64,
    /// The password's argon2id hash; empty for none.
    password: String,
    claimed: bool,
    used: Option<u64>,
}

/// Held while the store is read and written back.
static HELD: Mutex<()> = Mutex::new(());

fn held() -> MutexGuard<'static, ()> {
    match HELD.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn load() -> Result<Store> {
    let text = system::read_text(Path::new(STORE))?;
    if text.trim().is_empty() {
        return Ok(Store::default());
    }
    serde_json::from_str(&text).with_context(|| format!("{STORE} cannot be read"))
}

fn save(store: &Store) -> Result<()> {
    let text = serde_json::to_vec_pretty(store).context("cannot write the share links")?;
    system::write_atomic(Path::new(STORE), &text, 0o600)
}

/// What the server allows of share links: the Settings page's values, or
/// the approved defaults.
struct Policy {
    allowed: bool,
    default_days: u32,
    max_days: u32,
    password_required: bool,
}

fn yes(value: &str) -> bool {
    matches!(value.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on")
}

fn days(value: &str, key: &str) -> Result<u32, Failure> {
    match value.trim().parse::<u32>() {
        Ok(n) if n >= 1 => Ok(n),
        Ok(_) => Err(Failure::new(format!("{key} must be at least 1"))),
        Err(e) => Err(Failure::new(format!("{key}={value} is not a number of days: {e}"))),
    }
}

fn policy() -> Result<Policy, Failure> {
    Ok(Policy {
        allowed: yes(&settings::current("FILES_SHARE", "true")?),
        default_days: days(&settings::current("FILES_SHARE_DAYS", "7")?, "FILES_SHARE_DAYS")?,
        max_days: days(&settings::current("FILES_SHARE_MAX_DAYS", "30")?, "FILES_SHARE_MAX_DAYS")?,
        password_required: yes(&settings::current("FILES_SHARE_PASSWORD", "false")?),
    })
}

/// The policy for share links that `by` makes to files of `account`: the
/// Settings page's, tightened by every share link limit of both accounts as
/// the entrypoint resolved them from their own lines and their groups.
fn policy_of(by: &str, account: &str) -> Result<Policy, Failure> {
    let mut rules = policy()?;
    let state = system::read_state()?;
    for name in [by, account] {
        let Some(found) = state.iter().find(|a| a.name == name) else {
            return Err(Failure::new(format!("there is no account {name}")));
        };
        let options = spec::parse_options(&found.options)?;
        rules.allowed &= !options.noshare;
        if let Some(days) = options.share_days {
            rules.max_days = rules.max_days.min(days);
        }
        rules.password_required |= options.share_password;
    }
    rules.default_days = rules.default_days.min(rules.max_days);
    Ok(rules)
}

/// A path as the file browser sends it: absolute, with no empty, . or ..
/// part and no control character.
fn plain_path(path: &str) -> Result<(), Failure> {
    let Some(rest) = path.strip_prefix('/') else { return Err(Failure::new("a shared path starts with /")) };
    if rest.is_empty() || rest.split('/').any(|p| p.is_empty() || p == "." || p == "..") || path.chars().any(char::is_control) {
        return Err(Failure::new(format!("{path} is not a file's path")));
    }
    Ok(())
}

pub fn create(session: &str, acting: Option<&str>, path: &str, want_days: u32, password: &str) -> Result<Outcome, Failure> {
    let by = files::live(session)?;
    if files::eligible(&by)?.is_none() {
        return Err(Failure::new("this account may no longer use the file browser"));
    }
    files::may_act_as(&by, acting)?;
    let account = match acting {
        Some(other) => other.to_string(),
        None => by.clone(),
    };
    plain_path(path)?;
    let rules = policy_of(&by, &account)?;
    if !rules.allowed {
        return Err(Failure::new("share links are off for these files"));
    }
    if want_days == 0 || want_days > rules.max_days {
        return Err(Failure::new(format!("a share link lasts from 1 to {} days here", rules.max_days)));
    }
    if rules.password_required && password.is_empty() {
        return Err(Failure::new("a share link needs a password here"));
    }
    let hash = if password.is_empty() { String::new() } else { files::state()?.hasher.hash(password)? };
    let token = auth::token()?;
    let now = timefmt::now();
    let expires = now + u64::from(want_days) * DAY;
    let id = auth::sha256_hex(auth::token()?.as_bytes())[..16].to_string();
    {
        let _held = held();
        let mut store = load()?;
        store.links.push(Link {
            id,
            sha256: auth::sha256_hex(token.as_bytes()),
            account: account.clone(),
            by: by.clone(),
            path: path.to_string(),
            created: now,
            expires,
            password: hash,
            claimed: false,
            used: None,
        });
        save(&store)?;
    }
    system::log(&format!("files: {by} made a share link to {path} of {account}, for {want_days} days"));
    Outcome::data(ShareMade { token: Secret(token), expires })
}

/// The policy for a live session's pages of its own files, or with `acting`
/// of the files of an account it manages; the default length is offered
/// within the longest allowed.
pub fn policy_for(session: &str, acting: Option<&str>) -> Result<Outcome, Failure> {
    let by = files::live(session)?;
    files::may_act_as(&by, acting)?;
    let account = match acting {
        Some(other) => other.to_string(),
        None => by.clone(),
    };
    let rules = policy_of(&by, &account)?;
    Outcome::data(SharePolicy {
        allowed: rules.allowed,
        default_days: rules.default_days,
        max_days: rules.max_days,
        password_required: rules.password_required,
    })
}

pub fn list(session: &str) -> Result<Outcome, Failure> {
    let by = files::live(session)?;
    let store = load()?;
    let mut views: Vec<ShareView> = store
        .links
        .iter()
        .filter(|l| l.by == by)
        .map(|l| ShareView {
            id: l.id.clone(),
            account: l.account.clone(),
            path: l.path.clone(),
            created: l.created,
            expires: l.expires,
            used: l.used,
            password: !l.password.is_empty(),
        })
        .collect();
    views.sort_by_key(|v| std::cmp::Reverse(v.created));
    Outcome::data(views)
}

pub fn revoke(session: &str, id: &str) -> Result<Outcome, Failure> {
    let by = files::live(session)?;
    let _held = held();
    let mut store = load()?;
    let before = store.links.len();
    store.links.retain(|l| !(l.by == by && l.id == id));
    if store.links.len() == before {
        return Err(Failure::new("there is no such link of yours"));
    }
    save(&store)?;
    system::log(&format!("files: {by} ended share link {id}"));
    Ok(Outcome::messages(Vec::new()))
}

/// Why a link cannot be used now, if it cannot.
fn unusable(l: &Link, now: u64) -> Option<&'static str> {
    if l.used.is_some() {
        Some("this link was used")
    } else if l.expires <= now {
        Some("this link has expired")
    } else {
        None
    }
}

fn target(l: &Link, certificate: String) -> ShareTarget {
    ShareTarget {
        account: l.account.clone(),
        path: l.path.clone(),
        expires: l.expires,
        password: !l.password.is_empty(),
        certificate,
    }
}

/// Every failure to find a usable link reads the same, so a guess learns
/// nothing about which links exist.
fn not_found() -> Failure {
    Failure::new("this link does not work: it was used, it expired, or it is wrong")
}

pub fn info(token: &str) -> Result<Outcome, Failure> {
    let sha = auth::sha256_hex(token.as_bytes());
    let store = load()?;
    let now = timefmt::now();
    match store.links.iter().find(|l| auth::same(l.sha256.as_bytes(), sha.as_bytes())) {
        Some(l) if unusable(l, now).is_none() => Outcome::data(target(l, String::new())),
        Some(_) | None => Err(not_found()),
    }
}

pub fn claim(token: &str, password: &str, address: &str, public_key: &str) -> Result<Outcome, Failure> {
    let sha = auth::sha256_hex(token.as_bytes());
    let now = timefmt::now();
    let (account, id, hash) = {
        let store = load()?;
        let Some(l) = store.links.iter().find(|l| auth::same(l.sha256.as_bytes(), sha.as_bytes())) else { return Err(not_found()) };
        if unusable(l, now).is_some() {
            return Err(not_found());
        }
        (l.account.clone(), l.id.clone(), l.password.clone())
    };
    if !hash.is_empty() && !files::check_password(files::state()?, Some(&hash), password)? {
        system::log(&format!("files: wrong password for share link {id} from {address}"));
        return Err(Failure::new("wrong password"));
    }
    let key = sshkey::PublicKey::parse(public_key).map_err(Failure::new)?;
    if key.kind != "ssh-ed25519" {
        return Err(Failure::new("the file browser's keys are ed25519"));
    }
    let found = {
        let _held = held();
        let mut store = load()?;
        let found = match store.links.iter_mut().find(|l| l.id == id) {
            Some(l) if l.claimed => Err(Failure::new("this link is being downloaded now; try again once that ends")),
            Some(l) if unusable(l, timefmt::now()).is_some() => Err(not_found()),
            Some(l) => {
                l.claimed = true;
                Ok(target(l, String::new()))
            }
            None => Err(not_found()),
        };
        if found.is_ok() {
            save(&store)?;
        }
        found
    };
    let mut found = found?;
    found.certificate = files::sign(&account, &format!("share-{id}"), &key)?;
    system::log(&format!("files: share link {id} to {} of {account} opened from {address}", found.path));
    Outcome::data(found)
}

pub fn done(token: &str, complete: bool) -> Result<Outcome, Failure> {
    let sha = auth::sha256_hex(token.as_bytes());
    let _held = held();
    let mut store = load()?;
    let Some(l) = store.links.iter_mut().find(|l| auth::same(l.sha256.as_bytes(), sha.as_bytes())) else { return Err(not_found()) };
    l.claimed = false;
    if complete {
        l.used = Some(timefmt::now());
        system::log(&format!("files: share link {} was used", l.id));
    }
    save(&store)?;
    Ok(Outcome::messages(Vec::new()))
}

pub fn reset() -> Result<Outcome, Failure> {
    let _held = held();
    let mut store = load()?;
    if store.links.iter().any(|l| l.claimed) {
        store.links.iter_mut().for_each(|l| l.claimed = false);
        save(&store)?;
    }
    Ok(Outcome::messages(Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shares_only_plain_absolute_paths() {
        assert!(plain_path("/up/a.txt").is_ok());
        for bad in ["up/a.txt", "/", "/up/../etc", "/up//a", "/up/./a", "/a\nb"] {
            assert!(plain_path(bad).is_err(), "{bad:?}");
        }
    }
}
