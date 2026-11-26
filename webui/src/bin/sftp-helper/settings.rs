//! settings.conf, the settings the web UI may change, and fail2ban: bans
//! and the rules in /config/fail2ban/jail.d/00-webui.local.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use sftp_webui::net::{self, Network};
use sftp_webui::proto::{BanRules, BanView, Bans, CountryRules, JailView, SettingValue, SettingView, Settings};
use sftp_webui::{geo, spec};

use crate::system::{self, Backup, Failure, Outcome, TextFile};

/// The settings settings.conf may hold, with the value each has when unset.
pub const EDITABLE: [(&str, &str); 9] = [
    ("SFTP_PORT", "22"),
    ("SFTP_LOG_TRANSFERS", "false"),
    ("SFTP_UMASK", "022"),
    ("SFTP_CRYPTO_POLICY", "modern"),
    ("SFTP_AUTH_LOG_MAX_BYTES", "10485760"),
    ("FILES_SHARE", "true"),
    ("FILES_SHARE_DAYS", "7"),
    ("FILES_SHARE_MAX_DAYS", "30"),
    ("FILES_SHARE_PASSWORD", "false"),
];

/// The country rules' settings, which settings.conf may hold too; the Bans
/// page shows them instead of the Settings page.
const COUNTRY_KEYS: [(&str, &str); 2] = [("SFTP_COUNTRY_RULE", "off"), ("SFTP_COUNTRIES", "CN IN BR RU VN")];

/// Settings shown but changed only in the container's environment.
const FIXED: [(&str, &str); 9] = [
    ("FAIL2BAN_ENABLED", "true"),
    ("TZ", "UTC"),
    ("SFTP_RSYNC_USERS", ""),
    ("SFTP_USERS_FILE", ""),
    ("WEBUI_PORT", "8443"),
    ("WEBUI_PLAIN_HTTP", "false"),
    ("WEBUI_TRUSTED_PROXIES", ""),
    ("WEBUI_TRUSTED_NETWORKS", ""),
    ("WEBUI_ADMIN_FILE", ""),
];

const BOOLEANS: [&str; 8] = ["1", "true", "yes", "on", "0", "false", "no", "off"];

fn setting_line(line: &str) -> Option<(&str, &str)> {
    let t = TextFile::content(line).trim_start();
    if t.is_empty() || t.starts_with('#') {
        return None;
    }
    t.split_once('=')
}

/// Each key's value: the container environment's, which wins, else
/// settings.conf's, else its default.
fn views(keys: &[(&str, &str)], env: &[(String, String)], conf: &TextFile) -> Vec<SettingView> {
    let mut out = Vec::new();
    for &(key, default) in keys {
        let from_env = env.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        let in_file = conf.lines.iter().filter_map(|l| setting_line(l)).find(|(k, _)| *k == key);
        out.push(if let Some(value) = from_env {
            SettingView { key: key.into(), value, source: "environment".into(), locked: true }
        } else if let Some((_, value)) = in_file {
            SettingView { key: key.into(), value: value.into(), source: "settings.conf".into(), locked: false }
        } else {
            SettingView { key: key.into(), value: default.into(), source: "default".into(), locked: false }
        });
    }
    out
}

/// One setting as it is in force: the environment's value, else
/// settings.conf's, else `default`.
pub fn current(key: &str, default: &str) -> Result<String> {
    let env = system::saved_environment()?;
    let conf = TextFile::parse(&system::read_text(Path::new(system::SETTINGS_CONF))?);
    Ok(match views(&[(key, default)], &env, &conf).into_iter().next() {
        Some(view) => view.value,
        None => default.to_string(),
    })
}

pub fn get() -> Result<Settings> {
    let env = system::saved_environment()?;
    let conf = TextFile::parse(&system::read_text(Path::new(system::SETTINGS_CONF))?);
    let mut out = Settings { settings: views(&EDITABLE, &env, &conf), fixed: Vec::new(), locations: crate::geoip::locations()? };
    for (key, default) in FIXED {
        let (value, source) = match env.iter().find(|(k, _)| k == key) {
            Some((_, v)) => (v.clone(), "environment"),
            None => (default.to_string(), "default"),
        };
        out.fixed.push(SettingView { key: key.into(), value, source: source.into(), locked: true });
    }
    Ok(out)
}

/// The country rules' two settings, and what the entrypoint last loaded
/// from them. A record that cannot be read leaves the state "unknown".
fn country_rules() -> Result<CountryRules> {
    let env = system::saved_environment()?;
    let conf = TextFile::parse(&system::read_text(Path::new(system::SETTINGS_CONF))?);
    let mut found = views(&COUNTRY_KEYS, &env, &conf);
    let countries = found.pop().context("no view of SFTP_COUNTRIES")?;
    let rule = found.pop().context("no view of SFTP_COUNTRY_RULE")?;
    let mut out = CountryRules { rule, countries, state: "off".into(), ..CountryRules::default() };
    match geo::read_state(Path::new(geo::STATE_FILE)) {
        Ok(None) => {}
        Ok(Some(applied)) => {
            out.state = match (&applied.refused, applied.input.rule) {
                (Some(_), _) => "refused".into(),
                (None, geo::Rule::Block) => "blocking".into(),
                (None, geo::Rule::Allow) => "allowing".into(),
            };
            if let Some(why) = applied.refused {
                out.refused = why;
            }
            out.applied = applied.input.codes;
            out.ports = applied.input.ports;
            out.skipped = applied.input.skipped;
        }
        Err(e) => {
            out.state = "unknown".into();
            out.refused = format!("{e:#}");
        }
    }
    Ok(out)
}

/// SFTP_COUNTRIES as the entrypoint writes it: each code once, in capitals,
/// separated by spaces.
fn country_list(value: &str) -> Result<String, Failure> {
    let mut codes: Vec<String> = Vec::new();
    for word in value.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
        if !geo::valid_code(word) {
            return Err(Failure::new(format!("SFTP_COUNTRIES: {word} is not a two-letter country code")));
        }
        let code = word.to_ascii_uppercase();
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    Ok(codes.join(" "))
}

fn webui_port() -> Result<Option<u16>> {
    let text = system::read_text(&Path::new(system::RUN_DIR).join("webui-port"))?;
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    Ok(Some(text.parse().context("bad port in /run/sftp/webui-port")?))
}

fn validate(key: &str, value: &str) -> Result<String, Failure> {
    let value = value.trim();
    let ok = match key {
        "SFTP_PORT" => {
            if value.is_empty() || value.len() > 5 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Failure::new(format!("SFTP_PORT: {value} is not a port number")));
            }
            let port: u32 = value.parse().map_err(|e| Failure::new(format!("SFTP_PORT: {value}: {e}")))?;
            if !(1..=65535).contains(&port) {
                return Err(Failure::new(format!("SFTP_PORT: {value} is not a port number")));
            }
            if webui_port()?.is_some_and(|w| u32::from(w) == port) {
                return Err(Failure::new(format!("SFTP_PORT: {port} is the web UI's port")));
            }
            true
        }
        "SFTP_LOG_TRANSFERS" => BOOLEANS.contains(&value.to_lowercase().as_str()),
        "SFTP_UMASK" => spec::valid_umask(value),
        "SFTP_CRYPTO_POLICY" => value == "modern" || value == "strict",
        "SFTP_AUTH_LOG_MAX_BYTES" => !value.is_empty() && value.len() <= 15 && value.bytes().all(|b| b.is_ascii_digit()),
        "FILES_SHARE" | "FILES_SHARE_PASSWORD" => BOOLEANS.contains(&value.to_lowercase().as_str()),
        "FILES_SHARE_DAYS" | "FILES_SHARE_MAX_DAYS" => {
            (1..=9).contains(&value.len()) && !value.starts_with('0') && value.bytes().all(|b| b.is_ascii_digit())
        }
        "SFTP_COUNTRY_RULE" => matches!(value, "off" | "block" | "allow"),
        "SFTP_COUNTRIES" => return country_list(value),
        _ => return Err(Failure::new(format!("{key} cannot be set in the web UI"))),
    };
    if !ok {
        return Err(Failure::new(format!("{key}: {value} is not a valid value")));
    }
    Ok(value.to_string())
}

/// Saves and applies settings from the Settings page or the Bans page's
/// country rules. A value left empty returns a setting to its default,
/// except SFTP_COUNTRIES, where empty means no countries.
pub fn put(values: &[SettingValue]) -> Result<Outcome, Failure> {
    let env = system::saved_environment()?;
    let path = Path::new(system::SETTINGS_CONF);
    let mut conf = TextFile::parse(&system::read_text(path)?);
    let keys: Vec<(&str, &str)> = EDITABLE.iter().chain(COUNTRY_KEYS.iter()).copied().collect();
    let current = views(&keys, &env, &conf);
    let mut chosen: HashMap<String, String> = current.iter().map(|v| (v.key.clone(), v.value.clone())).collect();
    for item in values {
        let Some(view) = current.iter().find(|s| s.key == item.key) else {
            return Err(Failure::new(format!("{} cannot be set in the web UI", item.key)));
        };
        if view.locked {
            if item.value.trim() == view.value {
                continue;
            }
            return Err(Failure::new(format!("{} is set in the container's environment, which wins", item.key)));
        }
        let default = keys.iter().find(|(k, _)| *k == item.key).map_or("", |(_, d)| *d);
        let empty_is_a_value = item.key == "SFTP_COUNTRIES";
        let value = if item.value.trim().is_empty() { String::new() } else { validate(&item.key, &item.value)? };
        let effective = if value.is_empty() && !empty_is_a_value { default.to_string() } else { value.clone() };
        chosen.insert(item.key.clone(), effective);
        let index = conf.lines.iter().position(|l| setting_line(l).is_some_and(|(k, _)| k == item.key));
        conf.lines.retain(|l| !setting_line(l).is_some_and(|(k, _)| k == item.key));
        if (value.is_empty() && !empty_is_a_value) || value == default {
            continue;
        }
        let text = format!("{}={value}", item.key);
        match index {
            Some(i) if i <= conf.lines.len() => {
                let ending = conf.ending();
                conf.lines.insert(i, format!("{text}{ending}"));
            }
            _ => conf.push(&text),
        }
    }
    let rule = chosen.get("SFTP_COUNTRY_RULE").map(String::as_str);
    if rule == Some("allow") && chosen.get("SFTP_COUNTRIES").is_some_and(|c| c.trim().is_empty()) {
        return Err(Failure::new("allowing only listed countries needs at least one country"));
    }
    let backup = Backup::of(path)?;
    system::write_atomic(path, conf.render().as_bytes(), 0o644)?;
    system::apply_or_restore(&[backup])
}

pub(crate) fn fail2ban_running() -> bool {
    Path::new(system::RUN_DIR).join("fail2ban-enabled").exists() && Path::new("/run/fail2ban/fail2ban.sock").exists()
}

fn client(args: &[&str]) -> Result<String> {
    system::run("/usr/bin/fail2ban-client", args)
}

fn jails() -> Result<Vec<String>> {
    let out = client(&["status"])?;
    for line in out.lines() {
        if let Some((_, list)) = line.split_once("Jail list:") {
            return Ok(list.split(',').map(str::trim).filter(|j| !j.is_empty()).map(str::to_string).collect());
        }
    }
    anyhow::bail!("unexpected fail2ban status: {out}")
}

/// "Currently banned:\t3" and the like, from `fail2ban-client status <jail>`.
fn status_value(text: &str, label: &str) -> Result<String> {
    for line in text.lines() {
        if let Some((_, value)) = line.split_once(label) {
            return Ok(value.trim().to_string());
        }
    }
    anyhow::bail!("fail2ban's status has no \"{label}\": {text}")
}

pub fn banned_count() -> Result<usize> {
    if !fail2ban_running() {
        return Ok(0);
    }
    let mut total = 0;
    for jail in jails()? {
        let status = client(&["status", &jail])?;
        let value = status_value(&status, "Currently banned:")?;
        total += value.parse::<usize>().with_context(|| format!("unexpected fail2ban status: {value}"))?;
    }
    Ok(total)
}

/// The rules saved in 00-webui.local, or the image's defaults.
fn saved_rules() -> Result<BanRules> {
    let mut rules = BanRules {
        bantime: "1h".into(),
        findtime: "10m".into(),
        maxretry: 5,
        increment: true,
        maxtime: "1w".into(),
        ignoreip: Vec::new(),
    };
    let text = system::read_text(Path::new(system::WEBUI_JAIL))?;
    for line in text.lines() {
        let Some((key, value)) = line.split_once('=') else { continue };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "bantime" => rules.bantime = value.into(),
            "findtime" => rules.findtime = value.into(),
            "maxretry" => rules.maxretry = value.parse().with_context(|| format!("bad maxretry in {}", system::WEBUI_JAIL))?,
            "bantime.increment" => rules.increment = value == "true",
            "bantime.maxtime" => rules.maxtime = value.into(),
            "ignoreip" => {
                rules.ignoreip = value
                    .split_whitespace()
                    .filter(|a| *a != "127.0.0.1/8" && *a != "::1")
                    .map(str::to_string)
                    .collect();
            }
            _ => {}
        }
    }
    Ok(rules)
}

fn effective_rules() -> Result<BanRules> {
    let get = |what: &str| client(&["get", "sshd", what]).map(|s| s.trim().to_string());
    let ignore = get("ignoreip")?;
    let ignoreip = ignore
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("|-").or_else(|| l.trim_start().strip_prefix("`-")))
        .map(|a| a.trim().to_string())
        .filter(|a| a != "127.0.0.1/8" && a != "::1")
        .collect();
    let maxretry = get("maxretry")?;
    Ok(BanRules {
        bantime: format!("{}s", get("bantime")?),
        findtime: format!("{}s", get("findtime")?),
        maxretry: maxretry.parse().with_context(|| format!("unexpected maxretry from fail2ban: {maxretry}"))?,
        increment: false,
        maxtime: String::new(),
        ignoreip,
    })
}

/// A count from `fail2ban-client status <jail>`, such as "Total failed:\t12".
fn status_count(text: &str, label: &str) -> Result<u64> {
    let value = status_value(text, label)?;
    value.parse().with_context(|| format!("unexpected fail2ban status: {label} {value}"))
}

/// The database fail2ban keeps its bans in, or None when it keeps none.
pub(crate) fn database() -> Result<Option<String>> {
    let out = client(&["get", "dbfile"])?;
    Ok(out.lines().find_map(|l| l.trim().strip_prefix("`- ")).map(str::to_string))
}

/// An address's latest ban in a jail, from fail2ban's bips table.
struct Record {
    /// Seconds since 1970.
    since: u64,
    /// Seconds; -1 means forever.
    length: i64,
    count: u32,
    failures: Option<u32>,
}

/// Every address's latest ban, keyed by jail and address, from fail2ban's
/// database opened read-only.
fn records(db: &str) -> Result<HashMap<(String, String), Record>> {
    let conn = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("cannot open {db}"))?;
    let mut query = conn.prepare("SELECT jail, ip, timeofban, bantime, bancount, data FROM bips")?;
    let rows = query.query_map([], |row| {
        let data = crate::history::text_of(row.get_ref(5)?);
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, data))
    })?;
    let mut out = HashMap::new();
    for row in rows {
        let (jail, ip, time, length, count, data) = row?;
        let failures = match crate::history::ban_details(data.as_deref()).0 {
            Some(n) => Some(u32::try_from(n).with_context(|| format!("{n} failures recorded for {ip}"))?),
            None => None,
        };
        let since = u64::try_from(time).with_context(|| format!("ban time {time} recorded for {ip}"))?;
        let count = u32::try_from(count).with_context(|| format!("ban count {count} recorded for {ip}"))?;
        out.insert((jail, ip), Record { since, length, count, failures });
    }
    Ok(out)
}

pub fn bans() -> Result<Bans> {
    let mut out = Bans { enabled: fail2ban_running(), saved: saved_rules()?, countries: country_rules()?, ..Bans::default() };
    if !out.enabled {
        return Ok(out);
    }
    out.effective = effective_rules()?;
    let known = match database()? {
        Some(db) => match records(&db) {
            Ok(rows) => rows,
            Err(e) => {
                out.records_error = Some(format!("{e:#}"));
                HashMap::new()
            }
        },
        None => {
            out.records_error = Some("fail2ban keeps no database".into());
            HashMap::new()
        }
    };
    for jail in jails()? {
        let status = client(&["status", &jail])?;
        let banned = client(&["get", &jail, "banip"])?
            .split_whitespace()
            .map(|address| match known.get(&(jail.clone(), address.to_string())) {
                Some(r) => BanView { address: address.into(), since: Some(r.since), length: r.length, count: r.count, failures: r.failures },
                None => BanView { address: address.into(), since: None, length: 0, count: 0, failures: None },
            })
            .collect();
        out.jails.push(JailView {
            failed: status_count(&status, "Currently failed:")?,
            total_failed: status_count(&status, "Total failed:")?,
            total_banned: status_count(&status, "Total banned:")?,
            name: jail,
            banned,
        });
    }
    Ok(out)
}

fn parse_address(text: &str) -> Result<String, Failure> {
    let text = text.trim();
    match text.parse::<IpAddr>() {
        Ok(ip) => Ok(net::canonical(ip).to_string()),
        Err(e) => Err(Failure::new(format!("{text} is not an IP address: {e}"))),
    }
}

pub fn ban(address: &str) -> Result<Outcome, Failure> {
    if !fail2ban_running() {
        return Err(Failure::new("fail2ban is not running"));
    }
    let address = parse_address(address)?;
    client(&["set", "sshd", "banip", &address])?;
    Ok(Outcome::messages(vec![format!("banned {address} on every port")]))
}

pub fn unban(jail: &str, address: &str) -> Result<Outcome, Failure> {
    if !fail2ban_running() {
        return Err(Failure::new("fail2ban is not running"));
    }
    if !jails()?.iter().any(|j| j == jail) {
        return Err(Failure::new(format!("there is no jail {jail}")));
    }
    let address = parse_address(address)?;
    if let Err(e) = crate::history::import_now() {
        system::log(&format!("history: fail2ban's bans before an unban: {e:#}"));
    }
    client(&["set", jail, "unbanip", &address])?;
    Ok(Outcome::messages(vec![format!("unbanned {address} in {jail}")]))
}

/// A fail2ban time such as 3600, 10m, 1h, 2d or 1w.
fn valid_duration(text: &str) -> bool {
    let digits = text.trim_end_matches(['s', 'm', 'h', 'd', 'w']);
    let unit_len = text.len() - digits.len();
    unit_len <= 1 && !digits.is_empty() && digits.len() <= 9 && digits.bytes().all(|b| b.is_ascii_digit())
}

pub fn put_rules(rules: &BanRules) -> Result<Outcome, Failure> {
    let times = [("bantime", &rules.bantime, true), ("findtime", &rules.findtime, false), ("bantime.maxtime", &rules.maxtime, false)];
    for (name, value, forever) in times {
        if forever && value == "-1" {
            continue;
        }
        if !valid_duration(value) {
            let also = if forever { ", or -1 for forever" } else { "" };
            return Err(Failure::new(format!("{name}: {value} is not a time such as 600, 10m, 1h or 1w{also}")));
        }
    }
    if !(1..=1000).contains(&rules.maxretry) {
        return Err(Failure::new("maxretry must be from 1 to 1000"));
    }
    let mut ignore = vec!["127.0.0.1/8".to_string(), "::1".to_string()];
    for item in &rules.ignoreip {
        let net = Network::parse(item)?.to_string();
        if !ignore.contains(&net) {
            ignore.push(net);
        }
    }
    let text = format!(
        "# Written by the web UI. fail2ban reads it after jail.local.\n[DEFAULT]\nbantime = {}\nfindtime = {}\nmaxretry = {}\nbantime.increment = {}\nbantime.maxtime = {}\nignoreip = {}\n",
        rules.bantime,
        rules.findtime,
        rules.maxretry,
        rules.increment,
        rules.maxtime,
        ignore.join(" ")
    );
    let path = Path::new(system::WEBUI_JAIL);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let backup = Backup::of(path)?;
    system::write_atomic(path, text.as_bytes(), 0o644)?;
    system::apply_or_restore(&[backup])
}
