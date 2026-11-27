//! The history collector: reads /var/log/sftp-events.log as rsyslog writes
//! it and keeps every login and file event in /config/webui/history.sqlite3,
//! forever. Events and the read position are stored in one transaction, so a
//! restart resumes exactly where the last pass stopped. After a rotation it
//! first finishes the copy the file was rotated into.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, ErrorKind, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Transaction, params};
use sftp_webui::events::{self, Kind};
use sftp_webui::proto::{BanPage, BanRecord, Bucket, CountryCount, EventPage, EventView, NameCount, Person, Series};
use sftp_webui::{geo, net};

use crate::settings;

use crate::system::log;

pub const DB: &str = "/config/webui/history.sqlite3";
const LOG: &str = "/var/log/sftp-events.log";
const ROTATED: &str = "/var/log/sftp-events.log.1";

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    time INTEGER NOT NULL,
    door TEXT NOT NULL,
    kind TEXT NOT NULL,
    account TEXT NOT NULL,
    address TEXT NOT NULL,
    path TEXT NOT NULL,
    other TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    actor TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS events_by_time ON events (time);
CREATE INDEX IF NOT EXISTS events_by_account ON events (account, time);
CREATE TABLE IF NOT EXISTS position (source TEXT PRIMARY KEY, inode INTEGER NOT NULL, offset INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (pid INTEGER PRIMARY KEY, account TEXT NOT NULL, address TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS logins (pid INTEGER PRIMARY KEY, time INTEGER NOT NULL, account TEXT NOT NULL, address TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS holds (
    id INTEGER PRIMARY KEY,
    time INTEGER NOT NULL,
    account TEXT NOT NULL,
    address TEXT NOT NULL,
    place TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    decided INTEGER
);
CREATE INDEX IF NOT EXISTS holds_by_account ON holds (account, state);
CREATE UNIQUE INDEX IF NOT EXISTS holds_pending ON holds (account, address) WHERE state = 'pending';
CREATE TABLE IF NOT EXISTS lifts (account TEXT PRIMARY KEY, time INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS bans (
    jail TEXT NOT NULL,
    address TEXT NOT NULL,
    time INTEGER NOT NULL,
    length INTEGER NOT NULL,
    count INTEGER NOT NULL,
    failures INTEGER,
    names TEXT NOT NULL,
    PRIMARY KEY (jail, address, time)
);
CREATE INDEX IF NOT EXISTS bans_by_time ON bans (time);
";

pub fn open() -> Result<Connection> {
    let path = Path::new(DB);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let db = Connection::open(path).with_context(|| format!("cannot open {DB}"))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("cannot set the mode of {DB}"))?;
    db.execute_batch(SCHEMA).context("cannot create the history tables")?;
    let has_actor: bool = db
        .query_row("SELECT COUNT(*) > 0 FROM pragma_table_info('events') WHERE name = 'actor'", [], |row| row.get(0))
        .context("cannot read the history's columns")?;
    if !has_actor {
        db.execute_batch("ALTER TABLE events ADD COLUMN actor TEXT NOT NULL DEFAULT ''")
            .context("cannot add the actor column to the history")?;
    }
    Ok(db)
}

/// The address an sshd-session monitor logged its login from: the login
/// recorded for `pid` no earlier than the process, which started at `since`,
/// or an empty string until the collector has read it. The second of slack
/// covers /proc/stat's boot time, which is rounded down to the second.
pub fn login_address(db: &Connection, pid: u32, since: u64) -> Result<String> {
    db.query_row(
        "SELECT COALESCE(MAX(address), '') FROM logins WHERE pid = ?1 AND time + 1 >= ?2",
        params![pid, int(since, "start time")?],
        |row| row.get(0),
    )
    .context("cannot read the logins")
}

/// Forgets the logins of processes that have ended. A process id the
/// system reuses needs no forgetting: login_address() takes only a login
/// no earlier than the process.
fn forget_ended_logins(db: &Connection) -> Result<()> {
    let pids: Vec<i64> = db
        .prepare("SELECT pid FROM logins")?
        .query_map([], |row| row.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    for pid in pids {
        if !Path::new(&format!("/proc/{pid}")).exists() {
            db.execute("DELETE FROM logins WHERE pid = ?1", params![pid])?;
        }
    }
    Ok(())
}

/// A time the store keeps as a signed integer, as the unsigned seconds the
/// rest of the code uses.
fn unsigned(value: i64, what: &str) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("{what} {value} is negative"))
}

fn times_and_addresses(db: &Connection, sql: &str, values: impl rusqlite::Params) -> Result<Vec<(u64, String)>> {
    let mut statement = db.prepare(sql)?;
    let rows = statement.query_map(values, |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)))?;
    let mut out = Vec::new();
    for row in rows {
        let (time, address) = row?;
        out.push((unsigned(time, "time")?, address));
    }
    Ok(out)
}

/// An account's approved sign-ins, oldest first, as time and address: its
/// successful sign-ins over SFTP and the file browser, and its held sign-ins
/// an admin approved.
pub fn approved_signins(db: &Connection, account: &str) -> Result<Vec<(u64, String)>> {
    times_and_addresses(
        db,
        "SELECT time, address FROM events WHERE account = ?1 AND kind = 'login_ok' AND address != '' \
         UNION ALL SELECT time, address FROM holds WHERE account = ?1 AND state = 'approved' ORDER BY 1",
        params![account],
    )
    .context("cannot read the account's sign-ins")
}

/// An account's failed sign-ins from `since` on, oldest first.
pub fn failed_signins(db: &Connection, account: &str, since: u64) -> Result<Vec<(u64, String)>> {
    times_and_addresses(
        db,
        "SELECT time, address FROM events \
         WHERE account = ?1 AND kind = 'login_failed' AND address != '' AND time >= ?2 ORDER BY time",
        params![account, int(since, "time")?],
    )
    .context("cannot read the account's failed sign-ins")
}

/// When an admin last lifted the account's lockdown, if ever.
pub fn lifted(db: &Connection, account: &str) -> Result<Option<u64>> {
    let time: Option<i64> = db
        .query_row("SELECT time FROM lifts WHERE account = ?1", params![account], |row| row.get(0))
        .optional()
        .context("cannot read the account's lockdown lifts")?;
    time.map(|t| unsigned(t, "lift time")).transpose()
}

/// Records a sign-in held for an admin's approval, and returns its id. A
/// retry from the same address while that hold is pending refreshes it.
pub fn record_hold(db: &Connection, time: u64, account: &str, address: &str, place: &str, reason: &str) -> Result<i64> {
    db.query_row(
        "INSERT INTO holds (time, account, address, place, reason) VALUES (?1, ?2, ?3, ?4, ?5) \
         ON CONFLICT (account, address) WHERE state = 'pending' \
         DO UPDATE SET time = excluded.time, place = excluded.place, reason = excluded.reason RETURNING id",
        params![int(time, "time")?, account, address, place, reason],
        |r| r.get(0),
    )
    .context("cannot record a held sign-in")
}

/// Passes between two copies of fail2ban's bans, about half a minute.
const PASSES_PER_BAN_IMPORT: u32 = 30;

/// Runs for the life of the helper: reads the event log every second, and
/// every PASSES_PER_BAN_IMPORT passes copies fail2ban's new bans and forgets
/// the logins of ended processes. A failed pass is logged, and the store is
/// opened again after a pause; a failed ban copy or forgetting is logged and
/// tried again at the next turn.
pub fn collect() {
    loop {
        match open() {
            Ok(mut db) => {
                let mut passes = 0;
                loop {
                    if let Err(e) = pass(&mut db) {
                        log(&format!("history: {e:#}"));
                        break;
                    }
                    if passes % PASSES_PER_BAN_IMPORT == 0 {
                        if let Err(e) = import_bans(&mut db) {
                            log(&format!("history: fail2ban's bans: {e:#}"));
                        }
                        if let Err(e) = forget_ended_logins(&db) {
                            log(&format!("history: logins: {e:#}"));
                        }
                    }
                    passes = passes.wrapping_add(1);
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            Err(e) => log(&format!("history: {e:#}")),
        }
        std::thread::sleep(Duration::from_secs(10));
    }
}

/// The failed logins behind a ban and the account names tried in them,
/// from the data fail2ban keeps with it: its failure count and the log
/// lines that matched. Data that does not read as JSON is reported, and the
/// ban is kept with neither.
pub(crate) fn ban_details(data: Option<&str>) -> (Option<i64>, Vec<String>) {
    let Some(text) = data else { return (None, Vec::new()) };
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            log(&format!("history: ban data from fail2ban is not JSON: {e}"));
            return (None, Vec::new());
        }
    };
    let failures = value.get("failures").and_then(serde_json::Value::as_i64);
    let mut names: Vec<String> = Vec::new();
    if let Some(matches) = value.get("matches").and_then(serde_json::Value::as_array) {
        for m in matches {
            let line = match m {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Array(parts) => parts.iter().filter_map(serde_json::Value::as_str).collect(),
                _ => continue,
            };
            let Some((_, message)) = line.split_once("]: ") else { continue };
            if let Some(h) = events::happening("sshd", message.trim_end())
                && h.kind == Kind::LoginFailed
                && !names.contains(&h.account)
            {
                names.push(h.account);
            }
        }
    }
    (failures, names)
}

/// The text of fail2ban's data column, stored as text or as a blob; None
/// when it holds neither.
pub(crate) fn text_of(value: ValueRef) -> Option<String> {
    match value {
        ValueRef::Text(b) | ValueRef::Blob(b) => Some(String::from_utf8_lossy(b).into_owned()),
        ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) => None,
    }
}

/// Copies the bans fail2ban recorded since the last copy into the
/// permanent store; fail2ban drops its own after dbpurgeage. A copy is
/// keyed by jail, address and time, so copying one twice keeps one.
fn import_bans(db: &mut Connection) -> Result<()> {
    if !settings::fail2ban_running() {
        return Ok(());
    }
    let Some(path) = settings::database()? else { return Ok(()) };
    let source = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("cannot open {path}"))?;
    let tx = db.transaction()?;
    let since: i64 =
        tx.query_row("SELECT COALESCE(MAX(offset), 0) FROM position WHERE source = 'fail2ban'", [], |row| row.get(0))?;
    let mut query =
        source.prepare("SELECT jail, ip, timeofban, bantime, bancount, data FROM bans WHERE timeofban >= ?1 ORDER BY timeofban")?;
    let rows = query.query_map(params![since], |row| {
        let data = text_of(row.get_ref(5)?);
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?, data))
    })?;
    let mut latest = since;
    for row in rows {
        let (jail, address, time, length, count, data) = row?;
        let (failures, names) = ban_details(data.as_deref());
        tx.execute(
            "INSERT OR IGNORE INTO bans (jail, address, time, length, count, failures, names) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![jail, address, time, length, count, failures, names.join(",")],
        )?;
        latest = latest.max(time);
    }
    tx.execute("INSERT OR REPLACE INTO position (source, inode, offset) VALUES ('fail2ban', 0, ?1)", params![latest])?;
    tx.commit()?;
    Ok(())
}

/// Every account active since `since`, most recently active first, with
/// its three latest actions and its totals since then.
pub fn people(since: u64) -> Result<Vec<Person>> {
    let db = open()?;
    let since = int(since, "since")?;
    let mut active =
        db.prepare("SELECT account, MAX(time) FROM events WHERE account != '' AND time >= ?1 GROUP BY account ORDER BY 2 DESC")?;
    let accounts = active
        .query_map(params![since], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut recent = db.prepare(
        "SELECT id, time, door, kind, account, address, path, other, bytes, actor FROM events \
         WHERE account = ?1 AND kind NOT IN ('session_opened', 'session_closed') ORDER BY id DESC LIMIT 3",
    )?;
    let mut totals = db.prepare("SELECT kind, COUNT(*), SUM(bytes) FROM events WHERE account = ?1 AND time >= ?2 GROUP BY kind")?;
    let mut out = Vec::new();
    for (account, last) in accounts {
        let latest = recent.query_map(params![account], event_of)?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut person = Person { last: last.unsigned_abs(), recent: latest, ..Person::default() };
        let sums = totals.query_map(params![account, since], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.unsigned_abs(), row.get::<_, i64>(2)?.unsigned_abs()))
        })?;
        for sum in sums {
            let (kind, count, bytes) = sum?;
            match kind.as_str() {
                "login_ok" => person.logins += count,
                "login_failed" => person.failed += count,
                "upload" => {
                    person.uploads += count;
                    person.bytes_in += bytes;
                }
                "download" => {
                    person.downloads += count;
                    person.bytes_out += bytes;
                }
                _ => {}
            }
        }
        person.account = account;
        out.push(person);
    }
    Ok(out)
}

/// Every name tried in failed sign-ins since `since`, most tried first, and
/// whether each is an account of this server.
pub fn names_tried(since: u64) -> Result<Vec<NameCount>> {
    let accounts: Vec<String> = crate::system::read_state()?.into_iter().map(|a| a.name).collect();
    let db = open()?;
    let mut query = db.prepare(
        "SELECT account, COUNT(*) FROM events WHERE kind = 'login_failed' AND account != '' AND time >= ?1 \
         GROUP BY account ORDER BY 2 DESC, 1",
    )?;
    let names = query
        .query_map(params![int(since, "since")?], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.unsigned_abs())))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(names.into_iter().map(|(name, count)| NameCount { known: accounts.contains(&name), name, count }).collect())
}

/// Failed and successful logins since `since` by the country of their
/// address, most failed first. An address in no country, or sshd's
/// UNKNOWN, counts under no code.
pub fn logins_by_country(since: u64) -> Result<Vec<CountryCount>> {
    let db = open()?;
    let countries = geo::Countries::open(geo::database_path())?;
    let mut query = db.prepare(
        "SELECT address, SUM(kind = 'login_failed'), SUM(kind = 'login_ok') FROM events \
         WHERE kind IN ('login_failed', 'login_ok') AND address != '' AND time >= ?1 GROUP BY address",
    )?;
    let rows = query
        .query_map(params![int(since, "since")?], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.unsigned_abs(), row.get::<_, i64>(2)?.unsigned_abs()))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut by_code: HashMap<Option<String>, CountryCount> = HashMap::new();
    for (address, failed, ok) in rows {
        let code = match address.parse::<IpAddr>() {
            Ok(ip) => countries.lookup(net::canonical(ip))?,
            Err(not_an_address) => {
                log(&format!("history: {address} counts as no country: {not_an_address}"));
                None
            }
        };
        let entry = by_code.entry(code.clone()).or_insert_with(|| CountryCount { code, ..CountryCount::default() });
        entry.failed += failed;
        entry.ok += ok;
    }
    let mut out: Vec<CountryCount> = by_code.into_values().collect();
    out.sort_by(|a, b| b.failed.cmp(&a.failed).then(b.ok.cmp(&a.ok)).then(a.code.cmp(&b.code)));
    Ok(out)
}

/// Copies fail2ban's bans now. An unban calls it first, because fail2ban
/// deletes the address's bans from its own database when it lifts one.
pub fn import_now() -> Result<()> {
    let mut db = open()?;
    import_bans(&mut db)
}

/// Bans from the permanent store newest first, a page at a time.
pub fn bans(before: Option<i64>) -> Result<BanPage> {
    let db = open()?;
    let mut query = db.prepare(
        "SELECT rowid, jail, address, time, length, count, failures, names FROM bans \
         WHERE (?1 IS NULL OR rowid < ?1) ORDER BY rowid DESC LIMIT ?2",
    )?;
    let mut bans = query
        .query_map(params![before, PAGE + 1], |row| {
            let names: String = row.get(7)?;
            Ok(BanRecord {
                id: row.get(0)?,
                jail: row.get(1)?,
                address: row.get(2)?,
                time: row.get::<_, i64>(3)?.unsigned_abs(),
                length: row.get(4)?,
                count: row.get(5)?,
                failures: row.get(6)?,
                names: names.split(',').filter(|n| !n.is_empty()).map(str::to_string).collect(),
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let page = PAGE.unsigned_abs() as usize;
    let older = if bans.len() > page { bans.get(page - 1).map(|b| b.id) } else { None };
    bans.truncate(page);
    Ok(BanPage { bans, older })
}

/// Events on one page of the Activity log; the page before it is one click away.
const PAGE: i64 = 100;

/// Totals from `from` up to `to` in buckets of `size` seconds; a bucket
/// with nothing in it is all zeros.
pub fn series(from: u64, to: u64, size: u64) -> Result<Series> {
    if size == 0 || to <= from {
        anyhow::bail!("a series needs a bucket size and a range that ends after it starts");
    }
    let mut buckets: Vec<Bucket> = (0..(to - from).div_ceil(size)).map(|i| Bucket { start: from + i * size, ..Bucket::default() }).collect();
    let db = open()?;
    let mut query = db.prepare(
        "SELECT (time - ?1) / ?3, kind, COUNT(*), SUM(bytes) FROM events WHERE time >= ?1 AND time < ?2 GROUP BY 1, 2",
    )?;
    let rows = query.query_map(params![int(from, "from")?, int(to, "to")?, int(size, "size")?], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?))
    })?;
    for row in rows {
        let (index, kind, count, bytes) = row?;
        let b = slot(&mut buckets, index)?;
        let (count, bytes) = (count.unsigned_abs(), bytes.unsigned_abs());
        match kind.as_str() {
            "login_ok" => b.logins += count,
            "login_failed" => b.failed += count,
            "upload" => {
                b.uploads += count;
                b.bytes_in += bytes;
            }
            "download" => {
                b.downloads += count;
                b.bytes_out += bytes;
            }
            _ => {}
        }
    }
    let mut query =
        db.prepare("SELECT (time - ?1) / ?3, COUNT(*) FROM bans WHERE time >= ?1 AND time < ?2 GROUP BY 1")?;
    let rows = query.query_map(params![int(from, "from")?, int(to, "to")?, int(size, "size")?], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
    })?;
    for row in rows {
        let (index, count) = row?;
        slot(&mut buckets, index)?.bans += count.unsigned_abs();
    }
    Ok(Series { size, buckets })
}

/// The bucket a query's bucket number names.
fn slot(buckets: &mut [Bucket], index: i64) -> Result<&mut Bucket> {
    let found = match usize::try_from(index) {
        Ok(i) => buckets.get_mut(i),
        Err(e) => anyhow::bail!("bucket {index}: {e}"),
    };
    match found {
        Some(b) => Ok(b),
        None => anyhow::bail!("bucket {index} is outside the range asked for"),
    }
}

fn event_of(row: &rusqlite::Row) -> rusqlite::Result<EventView> {
    Ok(EventView {
        id: row.get(0)?,
        time: row.get::<_, i64>(1)?.unsigned_abs(),
        door: row.get(2)?,
        kind: row.get(3)?,
        account: row.get(4)?,
        address: row.get(5)?,
        path: row.get(6)?,
        other: row.get(7)?,
        bytes: row.get::<_, i64>(8)?.unsigned_abs(),
        actor: row.get(9)?,
    })
}

/// Events of one account, or of all when `account` is empty: every one
/// newer than `after` when given, else a page newest first from `before`.
pub fn events(account: &str, after: Option<i64>, before: Option<i64>) -> Result<EventPage> {
    let db = open()?;
    const COLUMNS: &str = "SELECT id, time, door, kind, account, address, path, other, bytes, actor FROM events";
    if let Some(after) = after {
        let mut query = db.prepare(&format!("{COLUMNS} WHERE id > ?1 AND (?2 = '' OR account = ?2) ORDER BY id DESC"))?;
        let events = query.query_map(params![after, account], event_of)?.collect::<rusqlite::Result<Vec<_>>>()?;
        return Ok(EventPage { events, older: None });
    }
    let mut query = db.prepare(&format!(
        "{COLUMNS} WHERE (?1 IS NULL OR id < ?1) AND (?2 = '' OR account = ?2) ORDER BY id DESC LIMIT ?3"
    ))?;
    let mut events = query.query_map(params![before, account, PAGE + 1], event_of)?.collect::<rusqlite::Result<Vec<_>>>()?;
    let more = events.len() > PAGE.unsigned_abs() as usize;
    events.truncate(PAGE.unsigned_abs() as usize);
    let older = if more { events.last().map(|e| e.id) } else { None };
    Ok(EventPage { events, older })
}

/// The history of `path` in `account`'s files: the latest upload, rename
/// to the path or folder made there, and every event that names the path,
/// a page newest first from `before`.
pub fn file_history(account: &str, path: &str, before: Option<i64>) -> Result<sftp_webui::proto::FileHistory> {
    let db = open()?;
    const COLUMNS: &str = "SELECT id, time, door, kind, account, address, path, other, bytes, actor FROM events";
    let added = db
        .query_row(
            &format!(
                "{COLUMNS} WHERE account = ?1 AND ((kind IN ('upload', 'mkdir', 'copy') AND path = ?2) OR (kind = 'rename' AND other = ?2)) \
                 ORDER BY id DESC LIMIT 1"
            ),
            params![account, path],
            event_of,
        )
        .optional()?;
    let mut query = db.prepare(&format!(
        "{COLUMNS} WHERE account = ?1 AND (path = ?2 OR other = ?2) AND (?3 IS NULL OR id < ?3) ORDER BY id DESC LIMIT ?4"
    ))?;
    let mut events = query.query_map(params![account, path, before, PAGE + 1], event_of)?.collect::<rusqlite::Result<Vec<_>>>()?;
    let more = events.len() > PAGE.unsigned_abs() as usize;
    events.truncate(PAGE.unsigned_abs() as usize);
    let older = if more { events.last().map(|e| e.id) } else { None };
    Ok(sftp_webui::proto::FileHistory { added, events, older })
}

fn int(value: u64, what: &str) -> Result<i64> {
    i64::try_from(value).with_context(|| format!("{what} {value} is too large to store"))
}

/// Reads what rsyslog wrote since the last pass.
fn pass(db: &mut Connection) -> Result<()> {
    let meta = match std::fs::metadata(LOG) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("cannot read {LOG}")),
    };
    let tx = db.transaction()?;
    let saved: Option<(i64, i64)> = tx
        .query_row("SELECT inode, offset FROM position WHERE source = 'events'", [], |row| Ok((row.get(0)?, row.get(1)?)))
        .optional()?;
    let inode = int(meta.ino(), "inode")?;
    let len = int(meta.len(), "size")?;
    let mut offset = match saved {
        Some((saved_inode, saved_offset)) if saved_inode == inode => saved_offset,
        Some(_) | None => 0,
    };
    if len < offset {
        read_from(&tx, Path::new(ROTATED), offset)?;
        offset = 0;
    }
    if len > offset {
        offset = read_from(&tx, Path::new(LOG), offset)?;
    }
    if saved != Some((inode, offset)) {
        tx.execute(
            "INSERT OR REPLACE INTO position (source, inode, offset) VALUES ('events', ?1, ?2)",
            params![inode, offset],
        )?;
    }
    tx.commit()?;
    Ok(())
}

/// Records every complete line from `offset` on, and returns the offset
/// after the last complete line; a line still being written waits.
fn read_from(tx: &Transaction, path: &Path, offset: i64) -> Result<i64> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(offset),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    file.seek(SeekFrom::Start(offset.unsigned_abs())).with_context(|| format!("cannot seek in {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut position = offset;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = reader.read_until(b'\n', &mut buf).with_context(|| format!("cannot read {}", path.display()))?;
        if n == 0 || buf.last() != Some(&b'\n') {
            return Ok(position);
        }
        position += int(n as u64, "line length")?;
        record_line(tx, String::from_utf8_lossy(&buf).trim_end())?;
    }
}

fn record_line(tx: &Transaction, line: &str) -> Result<()> {
    let Some(r) = events::record(line) else { return Ok(()) };
    let time = int(r.time, "time")?;
    if r.program == "sftp-webui" {
        match events::web_happening(r.message) {
            None => {}
            Some(Ok(h)) => insert(tx, time, "web", &h, &h.account, &h.address)?,
            Some(Err(why)) => crate::system::log(&format!("history: {why}")),
        }
        return Ok(());
    }
    let Some(h) = events::happening(r.program, r.message) else { return Ok(()) };
    let pid = int(r.pid, "pid")?;
    let h = match h.kind {
        Kind::LoginFailed => {
            match crate::signin_check::excused(std::path::Path::new(crate::signin_check::NOTES), r.pid, &h.account, &h.address) {
                Ok(Some(kind)) => events::Happening { kind, ..h },
                Ok(None) => h,
                Err(e) => {
                    crate::system::log(&format!("history: {e:#}"));
                    h
                }
            }
        }
        _ => h,
    };
    let (account, address) = match h.kind {
        Kind::SessionOpened => {
            tx.execute(
                "INSERT OR REPLACE INTO sessions (pid, account, address) VALUES (?1, ?2, ?3)",
                params![pid, h.account, h.address],
            )?;
            (h.account.clone(), h.address.clone())
        }
        Kind::LoginOk => {
            tx.execute(
                "INSERT OR REPLACE INTO logins (pid, time, account, address) VALUES (?1, ?2, ?3, ?4)",
                params![pid, time, h.account, h.address],
            )?;
            (h.account.clone(), h.address.clone())
        }
        Kind::LoginFailed | Kind::LoginHeld | Kind::LoginRefused | Kind::SessionClosed => (h.account.clone(), h.address.clone()),
        _ => {
            let known: Option<(String, String)> = tx
                .query_row("SELECT account, address FROM sessions WHERE pid = ?1", params![pid], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .optional()?;
            match known {
                Some((account, address)) => (account, address),
                None => (String::new(), String::new()),
            }
        }
    };
    if h.kind == Kind::SessionClosed {
        tx.execute("DELETE FROM sessions WHERE pid = ?1", params![pid])?;
    }
    // Sessions from loopback are the file browser's own, and it records
    // what they do itself, with who acted and from where.
    if address.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback()) {
        return Ok(());
    }
    insert(tx, time, "ssh", &h, &account, &address)
}

fn insert(tx: &Transaction, time: i64, door: &str, h: &events::Happening, account: &str, address: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO events (time, door, kind, account, address, path, other, bytes, actor) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![time, door, h.kind.name(), account, address, h.path, h.other, int(h.bytes, "bytes")?, h.actor],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> Connection {
        let db = Connection::open_in_memory().expect("an in-memory store");
        db.execute_batch(SCHEMA).expect("the history tables");
        db
    }

    #[test]
    fn keeps_where_each_session_logged_in_from() {
        let mut db = store();
        let tx = db.transaction().expect("a transaction");
        for line in [
            "2026-11-26T01:00:00.123456+01:00 sftp sshd-session[42]: Accepted password for alice from 203.0.113.24 port 51234 ssh2",
            "2026-11-26T01:00:05.000000+01:00 sftp sshd-session[43]: Failed password for bob from 198.51.100.9 port 4242 ssh2",
        ] {
            record_line(&tx, line).expect("the line");
        }
        tx.commit().expect("the commit");
        let time: i64 = db.query_row("SELECT time FROM logins WHERE pid = 42", [], |row| row.get(0)).expect("the login");
        let time = u64::try_from(time).expect("a time after 1970");
        assert_eq!(login_address(&db, 42, time).expect("a lookup"), "203.0.113.24");
        assert_eq!(login_address(&db, 42, time + 1).expect("a lookup"), "203.0.113.24");
        assert_eq!(login_address(&db, 42, time + 2).expect("a lookup"), "", "a later process with the same id");
        assert_eq!(login_address(&db, 43, time).expect("a lookup"), "", "a failed login opens no session");
    }

    #[test]
    fn reads_an_accounts_sign_ins_holds_and_lifts() {
        let db = store();
        for (time, kind, account, address) in [
            (10, "login_ok", "alice", "203.0.113.24"),
            (20, "login_failed", "alice", "192.0.2.1"),
            (30, "login_ok", "bob", "198.51.100.42"),
            (40, "login_failed", "alice", "192.0.2.2"),
            (50, "login_ok", "alice", ""),
        ] {
            db.execute(
                "INSERT INTO events (time, door, kind, account, address, path, other, bytes) VALUES (?1, 'ssh', ?2, ?3, ?4, '', '', 0)",
                params![time, kind, account, address],
            )
            .expect("an event");
        }
        let approved = record_hold(&db, 60, "alice", "198.51.100.9", "RU", "New place").expect("a hold");
        db.execute("UPDATE holds SET state = 'approved' WHERE id = ?1", params![approved]).expect("an approval");
        let pending = record_hold(&db, 70, "alice", "198.51.100.10", "RU", "New place").expect("a pending hold");
        let retried = record_hold(&db, 75, "alice", "198.51.100.10", "RU", "New place").expect("a retry");
        assert_eq!(retried, pending, "a retry from the same address refreshes the pending hold");
        let again = record_hold(&db, 76, "alice", "198.51.100.9", "RU", "New place").expect("a hold after an approval");
        assert_ne!(again, approved, "a decided hold is never reopened");
        let times: Vec<i64> = db
            .prepare("SELECT time FROM holds WHERE state = 'pending' ORDER BY time")
            .expect("a query")
            .query_map([], |r| r.get(0))
            .expect("the holds")
            .collect::<rusqlite::Result<_>>()
            .expect("the times");
        assert_eq!(times, vec![75, 76]);
        let signins = approved_signins(&db, "alice").expect("the sign-ins");
        assert_eq!(signins, vec![(10, "203.0.113.24".to_string()), (60, "198.51.100.9".to_string())]);
        assert_eq!(failed_signins(&db, "alice", 25).expect("the failures"), vec![(40, "192.0.2.2".to_string())]);
        assert_eq!(lifted(&db, "alice").expect("no lift"), None);
        db.execute("INSERT INTO lifts (account, time) VALUES ('alice', 80)", []).expect("a lift");
        assert_eq!(lifted(&db, "alice").expect("the lift"), Some(80));
    }

    #[test]
    fn forgets_the_logins_of_ended_processes() {
        let db = store();
        let alive = std::process::id();
        for pid in [alive, 999_999_999] {
            db.execute("INSERT INTO logins (pid, time, account, address) VALUES (?1, 0, 'a', '192.0.2.1')", params![pid])
                .expect("a login");
        }
        forget_ended_logins(&db).expect("the forgetting");
        let left: Vec<i64> = db
            .prepare("SELECT pid FROM logins")
            .expect("a query")
            .query_map([], |row| row.get(0))
            .expect("the rows")
            .collect::<rusqlite::Result<_>>()
            .expect("the ids");
        assert_eq!(left, vec![i64::from(alive)]);
    }
}
