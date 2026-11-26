//! MaxMind GeoLite2 Country: the account ID and license key, from the
//! container environment or the web UI, and the download that puts
//! GeoLite2 in place of DB-IP Lite while a key is set.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use sftp_webui::geo;

use crate::system::{self, Failure, Outcome};

/// The account ID and license key saved from the web UI; root only.
pub const KEY_FILE: &str = "/config/geoip/maxmind.conf";
const URL: &str = "https://download.maxmind.com/geoip/databases/GeoLite2-Country/download?suffix=tar.gz";
/// MaxMind publishes GeoLite2 twice a week; a copy older than this is
/// downloaded again.
const MAX_AGE: Duration = Duration::from_secs(3 * 86_400);
/// MaxMind's terms let a copy be used for 30 days after a newer one is out.
const STALE: Duration = Duration::from_secs(30 * 86_400);
/// The largest download accepted; GeoLite2 Country is about a tenth of it.
const MAX_DOWNLOAD: u64 = 64 * 1024 * 1024;

/// A MaxMind account ID and license key.
pub struct Key {
    pub account: String,
    pub license: String,
    /// True when the container environment sets it, which wins over the
    /// web UI.
    pub from_env: bool,
}

/// The key in force: the container environment's, else the web UI's.
pub fn key() -> Result<Option<Key>> {
    let env = system::saved_environment()?;
    let from_env = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.trim().to_string());
    if let (Some(account), Some(license)) = (from_env("MAXMIND_ACCOUNT_ID"), from_env("MAXMIND_LICENSE_KEY"))
        && !account.is_empty()
        && !license.is_empty()
    {
        return Ok(Some(Key { account, license, from_env: true }));
    }
    let text = system::read_text(Path::new(KEY_FILE))?;
    let saved = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')))
            .map(|v| v.trim().to_string())
    };
    match (saved("MAXMIND_ACCOUNT_ID"), saved("MAXMIND_LICENSE_KEY")) {
        (Some(account), Some(license)) if !account.is_empty() && !license.is_empty() => {
            Ok(Some(Key { account, license, from_env: false }))
        }
        (Some(_) | None, Some(_) | None) => Ok(None),
    }
}

/// An account ID is a number; a license key is letters, digits and
/// underscores.
fn check_key(account: &str, license: &str) -> Result<(), Failure> {
    if account.is_empty() || account.len() > 12 || !account.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Failure::new("a MaxMind account ID is a number, such as 123456"));
    }
    if license.len() < 6 || license.len() > 128 || !license.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return Err(Failure::new("a MaxMind license key is letters, digits and underscores"));
    }
    Ok(())
}

/// GeoLite2 Country downloaded with `key` and checked, not yet installed.
/// The key goes only to MaxMind: it is not sent on to the storage host
/// MaxMind redirects the download to.
fn download(key: &Key) -> Result<Vec<u8>, Failure> {
    use base64::Engine;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .https_only(true)
        .timeout_connect(Some(Duration::from_secs(15)))
        .timeout_global(Some(Duration::from_secs(100)))
        .build()
        .into();
    let token = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", key.account, key.license));
    let mut response = match agent.get(URL).header("Authorization", format!("Basic {token}")).call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(401)) => return Err(Failure::new("MaxMind refused the account ID and license key")),
        Err(ureq::Error::StatusCode(403)) => return Err(Failure::new("MaxMind does not allow GeoLite2 downloads with this key")),
        Err(ureq::Error::StatusCode(code)) => return Err(Failure::new(format!("MaxMind answered with status {code}"))),
        Err(e) => return Err(Failure::new(format!("cannot reach MaxMind: {e}"))),
    };
    let archive = match response.body_mut().with_config().limit(MAX_DOWNLOAD).read_to_vec() {
        Ok(a) => a,
        Err(e) => return Err(Failure::new(format!("cannot read MaxMind's download: {e}"))),
    };
    let bytes = geo::mmdb_from_tar_gz(&archive)?;
    geo::check_download(bytes.clone())?;
    Ok(bytes)
}

/// Puts a checked download in place of the GeoLite2 copy, which the web UI
/// reads too.
fn install(bytes: &[u8]) -> Result<()> {
    let path = Path::new(geo::MAXMIND_DB);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    system::write_atomic(path, bytes, 0o644)
}

/// How long ago the GeoLite2 copy was written; None without one.
fn copy_age() -> Result<Option<Duration>> {
    let modified = match std::fs::metadata(geo::MAXMIND_DB) {
        Ok(m) => m.modified().with_context(|| format!("cannot read the time of {}", geo::MAXMIND_DB))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot inspect {}", geo::MAXMIND_DB)),
    };
    match modified.elapsed() {
        Ok(age) => Ok(Some(age)),
        Err(ahead) => {
            system::log(&format!("geoip: {} is dated in the future: {ahead}", geo::MAXMIND_DB));
            Ok(Some(Duration::MAX))
        }
    }
}

/// What `sftp-helper geoip-update` reports.
pub enum Said {
    Nothing,
    Done(String),
    Warning(String),
}

/// When `update` downloads.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// Only without a copy, as at start, so an old copy never delays it.
    Missing,
    /// Without a copy, or with one three days old.
    Stale,
    Always,
}

/// With a key, downloads GeoLite2 as `when` says. Without one, warns about
/// a copy over 30 days old, which nothing keeps current.
pub fn update(when: When) -> Result<Said> {
    let age = copy_age()?;
    let Some(key) = key()? else {
        return Ok(match age {
            Some(a) if a > STALE => Said::Warning(format!(
                "{} is over 30 days old and no MaxMind key keeps it current; remove it to use DB-IP Lite",
                geo::MAXMIND_DB
            )),
            Some(_) | None => Said::Nothing,
        });
    };
    let due = match (when, age) {
        (When::Always, _) | (_, None) => true,
        (When::Missing, Some(_)) => false,
        (When::Stale, Some(a)) => a >= MAX_AGE,
    };
    if !due {
        return Ok(Said::Nothing);
    }
    let bytes = download(&key).map_err(|f| anyhow::anyhow!("{}", f.error))?;
    install(&bytes)?;
    Ok(Said::Done("downloaded MaxMind GeoLite2 Country".into()))
}

/// Saves a key from the web UI once a download with it succeeds, then
/// applies the configuration so the country rules use GeoLite2.
pub fn put(account: &str, license: &str) -> Result<Outcome, Failure> {
    if key()?.is_some_and(|k| k.from_env) {
        return Err(Failure::new("the MaxMind key is set in the container's environment, which wins"));
    }
    let (account, license) = (account.trim(), license.trim());
    check_key(account, license)?;
    let key = Key { account: account.into(), license: license.into(), from_env: false };
    let bytes = download(&key)?;
    install(&bytes)?;
    // A new file takes the mode given; an old one would keep its own.
    system::remove_file(Path::new(KEY_FILE))?;
    let text = format!("# Saved by the web UI; root only.\nMAXMIND_ACCOUNT_ID={account}\nMAXMIND_LICENSE_KEY={license}\n");
    system::write_atomic(Path::new(KEY_FILE), text.as_bytes(), 0o600)?;
    let mut outcome = system::apply_or_restore(&[])?;
    outcome.messages.insert(0, "downloaded MaxMind GeoLite2 Country".into());
    Ok(outcome)
}

/// Removes the web UI's key and the GeoLite2 copy it kept current, then
/// applies the configuration so the country rules use DB-IP Lite again.
pub fn delete() -> Result<Outcome, Failure> {
    if key()?.is_some_and(|k| k.from_env) {
        return Err(Failure::new("the MaxMind key is set in the container's environment, which wins"));
    }
    system::remove_file(Path::new(KEY_FILE))?;
    system::remove_file(Path::new(geo::MAXMIND_DB))?;
    system::apply_or_restore(&[])
}

/// The country data the Settings page shows; never the license key.
pub fn locations() -> Result<sftp_webui::proto::Locations> {
    let key = key()?;
    let path = geo::database_path();
    let built = match geo::Countries::open(path) {
        Ok(db) => db.built(),
        Err(e) => {
            system::log(&format!("geoip: {e:#}"));
            0
        }
    };
    let (account_id, key_source) = match &key {
        Some(k) if k.from_env => (k.account.clone(), "environment"),
        Some(k) => (k.account.clone(), "web UI"),
        None => (String::new(), ""),
    };
    let waiting = key.is_some() && !Path::new(geo::MAXMIND_DB).exists();
    Ok(sftp_webui::proto::Locations {
        database: if path == Path::new(geo::MAXMIND_DB) { "maxmind" } else { "dbip" }.into(),
        built,
        account_id,
        key_source: key_source.into(),
        waiting,
    })
}
