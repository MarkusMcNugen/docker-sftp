//! The file browser's sign-ins. Web passwords and second factors are kept
//! here, root-only, in /config/files/logins.json, never by the file browser
//! itself: it hands over what a person types and gets a session back, and a
//! certificate for its sftp session only while that session lives.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sftp_webui::net::{self, Network};
use sftp_webui::proto::{FilesInvite, FilesLogin, FilesRequest, Reply, SignedIn};
use sftp_webui::{auth, spec, sshkey, timefmt};

use crate::system::{self, Failure, Outcome};

const STORE: &str = "/config/files/logins.json";
/// The file browser's certificate authority, which only its sshd trusts.
const CA: &str = "/config/sshd/keys/files_ca";
/// Where certificates are signed, one directory per request.
const SIGNING: &str = "/run/sftp/certificates";
/// A sign-in link works for a day, as an admin's invite does.
const INVITE_LIFE: u64 = 24 * 60 * 60;
/// A session ends after half an hour unused, or twelve hours in all.
const SESSION_IDLE: u64 = 30 * 60;
const SESSION_MAX: u64 = 12 * 60 * 60;
/// Password checks that run at once; each holds 64 MiB.
const CHECKS_AT_ONCE: usize = 2;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    accounts: BTreeMap<String, Login>,
    invites: Vec<Invite>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    /// argon2id.
    hash: String,
    /// The TOTP secret, base32.
    totp: String,
    /// The TOTP step last used, so that each code works once.
    last_step: u64,
    last_sign_in: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invite {
    account: String,
    sha256: String,
    expires: u64,
}

struct Session {
    account: String,
    started: u64,
    used: u64,
}

pub(crate) struct State {
    pub(crate) hasher: auth::Hasher,
    sessions: Mutex<HashMap<String, Session>>,
    /// Password checks running now.
    checks: Mutex<usize>,
    check_done: Condvar,
    /// Held while the store is read and written back.
    store: Mutex<()>,
}

static STATE: OnceLock<State> = OnceLock::new();

pub(crate) fn state() -> Result<&'static State> {
    if let Some(s) = STATE.get() {
        return Ok(s);
    }
    let fresh = State {
        hasher: auth::Hasher::new()?,
        sessions: Mutex::new(HashMap::new()),
        checks: Mutex::new(0),
        check_done: Condvar::new(),
        store: Mutex::new(()),
    };
    Ok(STATE.get_or_init(|| fresh))
}

/// Locks a mutex whose holder may have panicked; what it guards is written
/// whole or not at all.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
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
    let path = Path::new(STORE);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot set the mode of {}", dir.display()))?;
    }
    let text = serde_json::to_vec_pretty(store).context("cannot write the sign-in store")?;
    system::write_atomic(path, &text, 0o600)
}

/// An account's options when it may use the file browser today: it exists,
/// has web access, and is neither disabled nor past its end date.
pub(crate) fn eligible(account: &str) -> Result<Option<spec::Options>> {
    let Some(found) = system::read_state()?.into_iter().find(|a| a.name == account) else {
        return Ok(None);
    };
    let options = spec::parse_options(&found.options).map_err(anyhow::Error::msg)?;
    let today = i64::try_from(timefmt::now() / 86_400).context("the clock is out of range")?;
    let ended = options.expires.as_deref().is_some_and(|d| timefmt::days_of(d) < today);
    Ok(if options.web && !options.disabled && !ended { Some(options) } else { None })
}

/// Checks a password with at most CHECKS_AT_ONCE checks running; `hash`
/// None takes as long and fails, so an unknown name costs the same.
pub(crate) fn check_password(s: &State, hash: Option<&str>, password: &str) -> Result<bool> {
    {
        let mut running = lock(&s.checks);
        while *running >= CHECKS_AT_ONCE {
            running = match s.check_done.wait(running) {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
        *running += 1;
    }
    let result = s.hasher.verify_blocking(hash, password);
    *lock(&s.checks) -= 1;
    s.check_done.notify_one();
    result
}

/// The networks from which no second factor is asked: WEBUI_TRUSTED_NETWORKS.
fn trusted_networks() -> Result<Vec<Network>> {
    let env = system::saved_environment()?;
    match env.iter().find(|(k, _)| k == "WEBUI_TRUSTED_NETWORKS") {
        Some((_, text)) => net::parse_list(text).map_err(anyhow::Error::msg),
        None => Ok(Vec::new()),
    }
}

/// The account a sign-in link is for, while it works.
fn invite_account(token: &str) -> Result<String, Failure> {
    let store = load()?;
    let digest = auth::sha256_hex(token.as_bytes());
    let now = timefmt::now();
    match store.invites.iter().find(|i| i.expires > now && auth::same(i.sha256.as_bytes(), digest.as_bytes())) {
        Some(i) => Ok(i.account.clone()),
        None => Err(Failure::new("this sign-in link no longer works; ask an admin for a new one")),
    }
}

/// Sets an account's web password and second factor with its sign-in link,
/// which is then used up.
fn enroll(token: &str, password: &str, totp_secret: &str, code: &str) -> Result<Outcome, Failure> {
    let s = state()?;
    let _held = lock(&s.store);
    let mut store = load()?;
    let now = timefmt::now();
    store.invites.retain(|i| i.expires > now);
    let digest = auth::sha256_hex(token.as_bytes());
    let Some(at) = store.invites.iter().position(|i| auth::same(i.sha256.as_bytes(), digest.as_bytes())) else {
        return Err(Failure::new("this sign-in link no longer works; ask an admin for a new one"));
    };
    let account = store.invites[at].account.clone();
    if eligible(&account)?.is_none() {
        return Err(Failure::new("this account may not use the file browser"));
    }
    auth::check_password_rules(password).map_err(Failure::new)?;
    let secret = match totp_rs::Secret::try_from_base32(totp_secret) {
        Ok(bytes) if bytes.len() >= 16 => bytes.to_vec(),
        Ok(short) => return Err(Failure::new(format!("the second-factor secret is too short ({} bytes)", short.len()))),
        Err(e) => return Err(Failure::new(format!("the second-factor secret cannot be read: {e}"))),
    };
    let totp = auth::totp(&secret, &account)?;
    let Some(step) = auth::check_code(&totp, code, 0, now) else {
        return Err(Failure::new("the code does not match; check the authenticator app's clock and try the next one"));
    };
    let hash = s.hasher.hash(password)?;
    store.accounts.insert(account.clone(), Login { hash, totp: totp_secret.to_string(), last_step: step, last_sign_in: None });
    store.invites.remove(at);
    save(&store)?;
    system::log(&format!("files: {account} set a web password and second factor"));
    Ok(Outcome::messages(Vec::new()))
}

fn address_of(address: &str) -> Result<IpAddr, Failure> {
    match address.parse() {
        Ok(ip) => Ok(net::canonical(ip)),
        Err(e) => Err(Failure::new(format!("{address} is not an address: {e}"))),
    }
}

/// Refuses `ip` when the account's from= networks leave it out, as sshd
/// refuses it on the sftp port.
fn from_allowed(account: &str, options: &spec::Options, ip: IpAddr) -> Result<(), Failure> {
    if options.from.is_empty() {
        return Ok(());
    }
    let nets = net::parse_list(&options.from.join(",")).map_err(Failure::new)?;
    if net::any_contains(&nets, ip) {
        return Ok(());
    }
    system::log(&format!("files: {account} may not connect from {ip}"));
    Err(Failure::new(format!("this account may not connect from {ip}")))
}

/// Checks a sign-in from `address`. The same work is done whether or not
/// the name exists, and every refusal of the name or password reads the
/// same, so it tells nothing about the account.
fn sign_in(account: &str, password: &str, code: &str, address: &str) -> Result<SignedIn, Failure> {
    let s = state()?;
    let ip = address_of(address)?;
    let hash = {
        let _held = lock(&s.store);
        load()?.accounts.get(account).map(|l| l.hash.clone())
    };
    let right = check_password(s, hash.as_deref(), password)?;
    let options = eligible(account)?;
    let refused = || {
        system::log(&format!("files: failed sign-in for {account} from {ip}"));
        Failure::new("wrong name or password")
    };
    let (true, Some(options)) = (right, options) else { return Err(refused()) };
    from_allowed(account, &options, ip)?;
    let _held = lock(&s.store);
    let mut store = load()?;
    let Some(login) = store.accounts.get_mut(account) else { return Err(refused()) };
    if !net::any_contains(&trusted_networks()?, ip) {
        if code.trim().is_empty() {
            return Err(Failure::new("enter the code from the authenticator app"));
        }
        let secret = match totp_rs::Secret::try_from_base32(&login.totp) {
            Ok(bytes) => bytes.to_vec(),
            Err(e) => return Err(Failure::new(format!("the stored second factor cannot be read: {e}"))),
        };
        let totp = auth::totp(&secret, account)?;
        let Some(step) = auth::check_code(&totp, code, login.last_step, timefmt::now()) else {
            system::log(&format!("files: wrong code for {account} from {ip}"));
            return Err(Failure::new("wrong code"));
        };
        login.last_step = step;
    }
    let now = timefmt::now();
    login.last_sign_in = Some(now);
    save(&store)?;
    let session = auth::token()?;
    lock(&s.sessions).insert(session.clone(), Session { account: account.to_string(), started: now, used: now });
    system::log(&format!("files: {account} signed in from {ip}"));
    Ok(SignedIn { session, account: account.to_string() })
}

/// The account of a live session, which counts as used now.
pub(crate) fn live(session: &str) -> Result<String, Failure> {
    let s = state()?;
    let now = timefmt::now();
    let mut sessions = lock(&s.sessions);
    sessions.retain(|_, v| now.saturating_sub(v.used) < SESSION_IDLE && now.saturating_sub(v.started) < SESSION_MAX);
    match sessions.get_mut(session) {
        Some(v) => {
            v.used = now;
            Ok(v.account.clone())
        }
        None => Err(Failure::new("the session has ended; sign in again")),
    }
}

/// The accounts `account` manages, as the entrypoint resolved its manage=
/// grants: the accounts it names and the members of the groups it names,
/// never itself.
fn managed_by(account: &str) -> Result<Vec<String>> {
    let state = system::read_state()?;
    let Some(me) = state.iter().find(|a| a.name == account) else { return Ok(Vec::new()) };
    let options = spec::parse_options(&me.options).map_err(anyhow::Error::msg)?;
    let mut out = Vec::new();
    for target in &options.manage {
        match target.strip_prefix('@') {
            Some(group) => {
                for a in &state {
                    let theirs = spec::parse_options(&a.options).map_err(anyhow::Error::msg)?;
                    if theirs.groups.iter().any(|g| g == group) {
                        out.push(a.name.clone());
                    }
                }
            }
            None => {
                if state.iter().any(|a| a.name == *target) {
                    out.push(target.clone());
                }
            }
        }
    }
    out.retain(|name| name != account);
    out.sort();
    out.dedup();
    Ok(out)
}

/// Refuses `acting` unless it is `account` or an account `account` manages.
pub(crate) fn may_act_as(account: &str, acting: Option<&str>) -> Result<(), Failure> {
    match acting {
        Some(other) if other != account => {
            if managed_by(account)?.iter().any(|m| m == other) {
                Ok(())
            } else {
                system::log(&format!("files: {account} may not open the files of {other}"));
                Err(Failure::new(format!("this account may not open the files of {other}")))
            }
        }
        Some(_) | None => Ok(()),
    }
}

/// The history of a path in the files of a live session's account, or of
/// an account it manages as `acting`.
fn file_history(session: &str, acting: Option<&str>, path: &str, before: Option<i64>) -> Result<Outcome, Failure> {
    let by = live(session)?;
    may_act_as(&by, acting)?;
    let account = match acting {
        Some(other) => other,
        None => by.as_str(),
    };
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(Failure::new(format!("{path} is not a path in the file browser")));
    }
    Outcome::data(crate::history::file_history(account, path, before)?)
}

/// The account of a session that may go on from `address`, acting as
/// itself or as `acting`. A session that may not go on is ended: its
/// account lacks web access, is disabled or past its end date, or the
/// address is outside its from= networks. Acting as an account it does not
/// manage is refused, and the session goes on.
fn check(session: &str, address: &str, acting: Option<&str>) -> Result<String, Failure> {
    let account = live(session)?;
    let ip = address_of(address)?;
    let allowed = match eligible(&account)? {
        Some(options) => from_allowed(&account, &options, ip),
        None => Err(Failure::new("this account may no longer use the file browser")),
    };
    if let Err(e) = allowed {
        lock(&state()?.sessions).remove(session);
        return Err(e);
    }
    may_act_as(&account, acting)?;
    Ok(account)
}

/// A directory that is removed when this value is dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            system::log(&format!("files: cannot remove {}: {e}", self.0.display()));
        }
    }
}

/// Signs `key` for `account` with the file browser's authority: valid five
/// minutes, from loopback only, with no extension, so no terminal or
/// forwarding. Its key ID names the account signed in, `by`, which sshd
/// logs with the account the key is for.
pub(crate) fn sign(account: &str, by: &str, key: &sshkey::PublicKey) -> Result<String> {
    let dir = Path::new(SIGNING).join(auth::token()?);
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let scratch = Scratch(dir);
    std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot set the mode of {}", scratch.0.display()))?;
    let bare = sshkey::PublicKey { comment: String::new(), ..key.clone() };
    let public = scratch.0.join("key.pub");
    std::fs::write(&public, format!("{}\n", bare.line())).with_context(|| format!("cannot write {}", public.display()))?;
    let id = format!("files:{by}:{account}:{}", timefmt::now());
    let public_text = public.to_string_lossy().to_string();
    system::run(
        "/usr/bin/ssh-keygen",
        &["-q", "-s", CA, "-I", &id, "-n", account, "-V", "+5m", "-O", "clear", "-O", "source-address=127.0.0.1", &public_text],
    )?;
    let cert = std::fs::read_to_string(scratch.0.join("key-cert.pub")).context("ssh-keygen wrote no certificate")?;
    Ok(cert.trim().to_string())
}

/// A certificate for the account of a live session that may still use the
/// file browser, or for an account it manages.
fn certificate(session: &str, public_key: &str, acting: Option<&str>) -> Result<Outcome, Failure> {
    let account = live(session)?;
    if eligible(&account)?.is_none() {
        lock(&state()?.sessions).remove(session);
        return Err(Failure::new("this account may no longer use the file browser"));
    }
    may_act_as(&account, acting)?;
    let key = sshkey::PublicKey::parse(public_key).map_err(Failure::new)?;
    if key.kind != "ssh-ed25519" {
        return Err(Failure::new("the file browser's keys are ed25519"));
    }
    let principal = match acting {
        Some(other) if other != account => {
            system::log(&format!("files: {account} opened the files of {other}"));
            other.to_string()
        }
        Some(_) | None => account.clone(),
    };
    Outcome::data(sign(&principal, &account, &key)?)
}

/// Answers a request from the file browser's own socket.
pub fn dispatch(request: FilesRequest) -> Reply {
    let result = match request {
        FilesRequest::Invite { token } => invite_account(&token.0).and_then(Outcome::data),
        FilesRequest::Enroll { token, password, totp_secret, code } => enroll(&token.0, &password.0, &totp_secret.0, &code),
        FilesRequest::SignIn { account, password, code, address } => {
            sign_in(&account, &password.0, &code, &address).and_then(Outcome::data)
        }
        FilesRequest::SignOut { session } => match state() {
            Ok(s) => {
                lock(&s.sessions).remove(&session.0);
                Ok(Outcome::messages(Vec::new()))
            }
            Err(e) => Err(Failure::from(e)),
        },
        FilesRequest::Check { session, address, acting } => {
            check(&session.0, &address, acting.as_deref()).and_then(Outcome::data)
        }
        FilesRequest::Certificate { session, public_key, acting } => {
            certificate(&session.0, &public_key, acting.as_deref())
        }
        FilesRequest::ShareCreate { session, acting, path, days, password } => {
            crate::shares::create(&session.0, acting.as_deref(), &path, days, &password.0)
        }
        FilesRequest::ShareList { session } => crate::shares::list(&session.0),
        FilesRequest::ShareRevoke { session, id } => crate::shares::revoke(&session.0, &id),
        FilesRequest::ShareInfo { token } => crate::shares::info(&token.0),
        FilesRequest::ShareClaim { token, password, address, public_key } => {
            crate::shares::claim(&token.0, &password.0, &address, &public_key)
        }
        FilesRequest::ShareDone { token, done } => crate::shares::done(&token.0, done),
        FilesRequest::ShareReset => crate::shares::reset(),
        FilesRequest::SharePolicy { session, acting } => crate::shares::policy_for(&session.0, acting.as_deref()),
        FilesRequest::FileHistory { session, acting, path, before } => file_history(&session.0, acting.as_deref(), &path, before),
        FilesRequest::Managed { session } => match live(&session.0) {
            Ok(account) => managed_by(&account).map_err(Failure::from).and_then(Outcome::data),
            Err(e) => Err(e),
        },
    };
    match result {
        Ok(o) => Reply { ok: true, error: String::new(), messages: o.messages, data: o.data },
        Err(f) => Reply { ok: false, error: f.error, messages: f.messages, data: serde_json::Value::Null },
    }
}

/// A sign-in link for an account that may use the file browser; it replaces
/// any link the account still has.
pub fn invite(account: &str) -> Result<Outcome, Failure> {
    if eligible(account)?.is_none() {
        return Err(Failure::new(format!(
            "{account} may not use the file browser: give it web access, and it must be neither disabled nor past its end date"
        )));
    }
    let s = state()?;
    let token = auth::token()?;
    let now = timefmt::now();
    let expires = now + INVITE_LIFE;
    let _held = lock(&s.store);
    let mut store = load()?;
    store.invites.retain(|i| i.expires > now && i.account != account);
    store.invites.push(Invite { account: account.into(), sha256: auth::sha256_hex(token.as_bytes()), expires });
    save(&store)?;
    Outcome::data(FilesInvite { token, expires })
}

/// Removes an account's web password and second factor and its sign-in
/// link, and ends its sessions.
pub fn reset(account: &str) -> Result<Outcome, Failure> {
    let s = state()?;
    {
        let _held = lock(&s.store);
        let mut store = load()?;
        store.accounts.remove(account);
        store.invites.retain(|i| i.account != account);
        save(&store)?;
    }
    lock(&s.sessions).retain(|_, v| v.account != account);
    Ok(Outcome::messages(vec![format!("{account} must be sent a new sign-in link to use the file browser")]))
}

/// The sign-in state of every account that has web access or a stored
/// sign-in.
pub fn logins() -> Result<Vec<FilesLogin>> {
    let store = load()?;
    let now = timefmt::now();
    let mut out = Vec::new();
    for a in system::read_state()? {
        let web = spec::parse_options(&a.options).map_err(anyhow::Error::msg)?.web;
        let login = store.accounts.get(&a.name);
        if !web && login.is_none() {
            continue;
        }
        out.push(FilesLogin {
            enrolled: login.is_some(),
            invite_expires: store.invites.iter().filter(|i| i.account == a.name && i.expires > now).map(|i| i.expires).max(),
            last_sign_in: login.and_then(|l| l.last_sign_in),
            account: a.name,
        });
    }
    Ok(out)
}
