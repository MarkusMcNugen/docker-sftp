//! Root helper of the admin web UI. Listens on /run/sftp-webui/helper.sock,
//! accepts connections only from the web UI's system account, and carries
//! out the fixed list of requests in `sftp_webui::proto`: reading the
//! server's state, and changing users.conf, settings.conf, public keys and
//! the fail2ban settings, each change applied with `entrypoint apply` and
//! recorded in the audit log.

mod accounts;
mod files;
mod geoip;
mod groups;
mod history;
mod logs;
mod runtime;
mod settings;
mod shares;
mod system;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sftp_webui::proto::{self, Reply, Request};

use crate::system::{Failure, Outcome, log};

/// As many requests at once as the web server holds connections.
const MAX_ACTIVE: usize = 256;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("country-rules") {
        return match country_rules(&args[1..]) {
            Ok(Load::Done) => ExitCode::SUCCESS,
            Ok(Load::Refused(why)) => {
                println!("{why}");
                ExitCode::from(4)
            }
            Err(e) => {
                eprintln!("country rules: {e:#}");
                ExitCode::FAILURE
            }
        };
    }
    // `geoip-update [--if-missing|--force]`, for the entrypoint: exits 0,
    // saying what it did if anything, 3 with a warning, or 1 with why the
    // download failed.
    if args.first().map(String::as_str) == Some("geoip-update") {
        let when = match args.get(1).map(String::as_str) {
            None => geoip::When::Stale,
            Some("--if-missing") => geoip::When::Missing,
            Some("--force") => geoip::When::Always,
            Some(other) => {
                eprintln!("geoip-update takes --if-missing or --force, not {other}");
                return ExitCode::FAILURE;
            }
        };
        return match geoip::update(when) {
            Ok(geoip::Said::Nothing) => ExitCode::SUCCESS,
            Ok(geoip::Said::Done(said)) => {
                println!("{said}");
                ExitCode::SUCCESS
            }
            Ok(geoip::Said::Warning(said)) => {
                println!("{said}");
                ExitCode::from(3)
            }
            Err(e) => {
                eprintln!("{e:#}");
                ExitCode::FAILURE
            }
        };
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            log(&format!("fatal: {e:#}"));
            ExitCode::FAILURE
        }
    }
}

/// How loading the country rules ended.
enum Load {
    /// The firewall enforces them.
    Done,
    /// The firewall refused them, for the reason nft gave.
    Refused(String),
}

/// `country-rules <block|allow> <countries> <ports> <trusted networks>
/// <never-ban list>`, for the entrypoint: loads the rules into the nftables
/// table sftp_countries with the countries' networks from the country
/// database, and says on standard error which never-ban entries it cannot
/// exempt. Lists are separated by commas or spaces; `geo::rule_input` says
/// how each is read. Exits 0 once the rules are in force, 4 with nft's
/// reason on standard output when the firewall refuses them, and 1 when the
/// rules or the database cannot be read.
fn country_rules(args: &[String]) -> Result<Load> {
    use sftp_webui::geo;
    let [rule, codes, ports, trusted, never_ban] = args else {
        bail!("usage: sftp-helper country-rules <block|allow> <countries> <ports> <trusted networks> <never-ban list>");
    };
    let input = geo::rule_input(rule, codes, ports, trusted, never_ban)?;
    for why in &input.skipped {
        eprintln!("country rules: cannot exempt a never-ban entry: {why}");
    }
    let (v4, v6) = if input.codes.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        let (v4, v6) = geo::Countries::open(geo::database_path())?.networks(&input.codes)?;
        (geo::ranges(&v4)?, geo::ranges(&v6)?)
    };
    let tables = match system::nft(&["list", "tables", "inet"], None) {
        Ok(text) => text,
        Err(why) => return Ok(Load::Refused(why)),
    };
    let loaded = if tables.lines().any(|l| l.trim() == "table inet sftp_countries") {
        match system::nft(&["-t", "list", "table", "inet", "sftp_countries"], None) {
            Ok(listing) => geo::read_listing(&listing),
            Err(why) => return Ok(Load::Refused(why)),
        }
    } else {
        geo::Loaded::default()
    };
    for script in geo::nft_loads(&input, &v4, &v6, &loaded) {
        if let Err(why) = system::nft(&["-f", "-"], Some(&script)) {
            return Ok(Load::Refused(why));
        }
    }
    Ok(Load::Done)
}

/// What answers the requests of one socket.
type Handler = Arc<dyn Fn(&[u8]) -> Reply + Send + Sync>;

/// A socket for `group`, read and written by root and that group alone.
fn listen(path: &str, group: u32) -> Result<UnixListener> {
    let path = std::path::Path::new(path);
    system::remove_file(path)?;
    let listener = UnixListener::bind(path).with_context(|| format!("cannot listen on {}", path.display()))?;
    std::os::unix::fs::chown(path, Some(0), Some(group)).with_context(|| format!("cannot hand {} to its group", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
        .with_context(|| format!("cannot set the mode of {}", path.display()))?;
    Ok(listener)
}

/// Serves a socket's connections, each on its own thread, from `uid` only.
fn accept(listener: UnixListener, uid: u32, active: Arc<AtomicUsize>, handler: Handler) {
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log(&format!("accept failed: {e}"));
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_ACTIVE {
            active.fetch_sub(1, Ordering::SeqCst);
            log("refused a connection: too many requests at once");
            continue;
        }
        let active = Arc::clone(&active);
        let handler = Arc::clone(&handler);
        std::thread::spawn(move || {
            if let Err(e) = serve(stream, uid, handler.as_ref()) {
                log(&format!("request failed: {e:#}"));
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn run() -> Result<()> {
    let (webui_uid, webui_gid) = system::ids_of("sftp-webui")?;
    let admin = listen(proto::SOCKET, webui_gid)?;
    let active = Arc::new(AtomicUsize::new(0));
    // The file browser's socket exists only while it is on; its directory
    // is the entrypoint's sign.
    if std::path::Path::new(proto::FILES_SOCKET).parent().is_some_and(std::path::Path::exists) {
        let (files_uid, files_gid) = system::ids_of("sftp-files")?;
        let listener = listen(proto::FILES_SOCKET, files_gid)?;
        let handler: Handler = Arc::new(|line: &[u8]| match serde_json::from_slice::<proto::FilesRequest>(line) {
            Ok(request) => files::dispatch(request),
            Err(e) => failed(Failure::new(format!("malformed request: {e}"))),
        });
        let active = Arc::clone(&active);
        std::thread::spawn(move || accept(listener, files_uid, active, handler));
    }
    let lock = Arc::new(Mutex::new(()));
    let handler: Handler = Arc::new(move |line: &[u8]| match serde_json::from_slice::<Request>(line) {
        Ok(request) => dispatch(request, &lock),
        Err(e) => failed(Failure::new(format!("malformed request: {e}"))),
    });
    std::thread::spawn(history::collect);
    log("listening");
    accept(admin, webui_uid, active, handler);
    Ok(())
}

fn serve(stream: UnixStream, uid: u32, handle: &(dyn Fn(&[u8]) -> Reply + Send + Sync)) -> Result<()> {
    let cred = rustix::net::sockopt::socket_peercred(&stream).context("cannot read the peer's credentials")?;
    if cred.uid.as_raw() != uid {
        bail!("refused a connection from uid {}", cred.uid.as_raw());
    }
    // The web UI writes its request in one go.
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut line = Vec::new();
    let mut reader = BufReader::new(stream.try_clone()?).take(proto::MAX_REQUEST as u64 + 1);
    reader.read_until(b'\n', &mut line).context("cannot read the request")?;
    let reply = if line.len() > proto::MAX_REQUEST { failed(Failure::new("the request is too large")) } else { handle(&line) };
    let mut out = serde_json::to_vec(&reply)?;
    out.push(b'\n');
    (&stream).write_all(&out).context("cannot send the reply")?;
    Ok(())
}

fn failed(f: Failure) -> Reply {
    Reply {
        ok: false,
        error: f.error,
        messages: f.messages,
        data: serde_json::Value::Null,
    }
}

/// What a change does, for the audit log.
fn describe(request: &Request) -> (String, String) {
    match request {
        Request::AccountPut { create, account, .. } => {
            let action = if *create { "account created" } else { "account changed" };
            (action.into(), account.name.clone())
        }
        Request::AccountDelete { name, delete_keys, .. } => {
            let action = if *delete_keys { "account and keys deleted" } else { "account deleted" };
            (action.into(), name.clone())
        }
        Request::KeyAdd { name, .. } => ("key added".into(), name.clone()),
        Request::KeyDelete { name, fingerprint, .. } => ("key removed".into(), format!("{name} {fingerprint}")),
        Request::HashPasswords { .. } => ("plain-text passwords hashed".into(), "users.conf".into()),
        Request::SessionEnd { pid, .. } => ("session ended".into(), format!("pid {pid}")),
        Request::SettingsPut { values, .. } => {
            let keys: Vec<&str> = values.iter().map(|v| v.key.as_str()).collect();
            ("settings changed".into(), keys.join(", "))
        }
        Request::Ban { address, .. } => ("address banned".into(), address.clone()),
        Request::Unban { jail, address, .. } => ("address unbanned".into(), format!("{address} ({jail})")),
        Request::Fail2banPut { .. } => ("ban rules changed".into(), "fail2ban".into()),
        Request::Audit { action, target, .. } => (action.clone(), target.clone()),
        Request::GroupPut { create, group, .. } => {
            let action = if *create { "group created" } else { "group changed" };
            (action.into(), group.group.name.clone())
        }
        Request::GroupDelete { name, .. } => ("group deleted".into(), name.clone()),
        Request::MaxmindPut { account_id, .. } => ("MaxMind key saved".into(), format!("account {account_id}")),
        Request::MaxmindDelete { .. } => ("MaxMind key removed".into(), "GeoLite2".into()),
        Request::FilesInvite { account, .. } => ("file browser sign-in link made".into(), account.clone()),
        Request::FilesReset { account, .. } => ("file browser sign-in reset".into(), account.clone()),
        Request::Status
        | Request::Accounts
        | Request::SettingsGet
        | Request::Bans
        | Request::Log { .. }
        | Request::AuditLog { .. }
        | Request::Groups
        | Request::HistorySeries { .. }
        | Request::Events { .. }
        | Request::BanHistory { .. }
        | Request::People { .. }
        | Request::NamesTried { .. }
        | Request::LoginsByCountry { .. }
        | Request::FilesLogins => (String::new(), String::new()),
    }
}

fn dispatch(request: Request, lock: &Mutex<()>) -> Reply {
    let actor = request.actor().cloned();
    let (action, target) = describe(&request);
    let result: std::result::Result<Outcome, Failure> = match request {
        Request::Status => runtime::status().map_err(Failure::from).and_then(Outcome::data),
        Request::Accounts => accounts::list().map_err(Failure::from).and_then(Outcome::data),
        Request::SettingsGet => settings::get().map_err(Failure::from).and_then(Outcome::data),
        Request::Bans => settings::bans().map_err(Failure::from).and_then(Outcome::data),
        Request::Groups => groups::list().map_err(Failure::from).and_then(Outcome::data),
        Request::HistorySeries { from, to, size } => {
            history::series(from, to, size).map_err(Failure::from).and_then(Outcome::data)
        }
        Request::Events { account, after, before } => {
            history::events(&account, after, before).map_err(Failure::from).and_then(Outcome::data)
        }
        Request::BanHistory { before } => history::bans(before).map_err(Failure::from).and_then(Outcome::data),
        Request::People { since } => history::people(since).map_err(Failure::from).and_then(Outcome::data),
        Request::NamesTried { since } => history::names_tried(since).map_err(Failure::from).and_then(Outcome::data),
        Request::LoginsByCountry { since } => {
            history::logins_by_country(since).map_err(Failure::from).and_then(Outcome::data)
        }
        Request::FilesLogins => files::logins().map_err(Failure::from).and_then(Outcome::data),
        Request::Log { query, before } => logs::auth_page(&query, before).map_err(Failure::from).and_then(Outcome::data),
        Request::AuditLog { query, before } => {
            logs::audit_page(&query, before).map_err(Failure::from).and_then(Outcome::data)
        }
        Request::Audit { action, target, outcome, .. } => {
            let Some(actor) = &actor else {
                return failed(Failure::new("an audit entry needs an actor"));
            };
            return match system::audit(actor, &action, &target, &outcome) {
                Ok(()) => Reply { ok: true, ..Reply::default() },
                Err(e) => failed(Failure::from(e)),
            };
        }
        change => {
            let guard = match lock.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            let result = match change {
                Request::AccountPut { create, account, .. } => accounts::put(create, account),
                Request::AccountDelete { name, delete_keys, .. } => accounts::delete(&name, delete_keys),
                Request::KeyAdd { name, key, .. } => accounts::add_key(&name, &key),
                Request::KeyDelete { name, fingerprint, .. } => accounts::delete_key(&name, &fingerprint),
                Request::HashPasswords { .. } => accounts::hash_passwords(),
                Request::SessionEnd { pid, .. } => runtime::end_session(pid),
                Request::SettingsPut { values, .. } => settings::put(&values),
                Request::Ban { address, .. } => settings::ban(&address),
                Request::Unban { jail, address, .. } => settings::unban(&jail, &address),
                Request::Fail2banPut { rules, .. } => settings::put_rules(&rules),
                Request::GroupPut { create, group, .. } => groups::put(create, group),
                Request::GroupDelete { name, .. } => groups::delete(&name),
                Request::MaxmindPut { account_id, license_key, .. } => geoip::put(&account_id, &license_key.0),
                Request::MaxmindDelete { .. } => geoip::delete(),
                Request::FilesInvite { account, .. } => files::invite(&account),
                Request::FilesReset { account, .. } => files::reset(&account),
                Request::Status
                | Request::Accounts
                | Request::SettingsGet
                | Request::Bans
                | Request::Log { .. }
                | Request::AuditLog { .. }
                | Request::Audit { .. }
                | Request::Groups
                | Request::HistorySeries { .. }
                | Request::Events { .. }
                | Request::BanHistory { .. }
                | Request::People { .. }
                | Request::NamesTried { .. }
                | Request::LoginsByCountry { .. }
                | Request::FilesLogins => Err(Failure::new("not a change")),
            };
            drop(guard);
            result
        }
    };
    if let Some(actor) = &actor {
        let outcome = match &result {
            Ok(_) => "ok".to_string(),
            Err(f) => format!("failed: {}", f.error),
        };
        if let Err(e) = system::audit(actor, &action, &target, &outcome) {
            log(&format!("cannot write the audit log: {e:#}"));
        }
    }
    match result {
        Ok(o) => Reply {
            ok: true,
            error: String::new(),
            messages: o.messages,
            data: o.data,
        },
        Err(f) => failed(f),
    }
}
