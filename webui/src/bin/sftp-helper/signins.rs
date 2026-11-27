//! Held sign-ins and locked-down accounts, for the admin web UI: listing
//! them, approving or rejecting a held sign-in, and lifting a lockdown.

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{OptionalExtension, params};
use sftp_webui::net::canonical;
use sftp_webui::proto::{HoldView, LockdownView, Signins};
use sftp_webui::signin;

use crate::system::{Failure, Outcome};
use crate::{history, settings, signin_check};

fn now() -> Result<i64> {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).context("the clock is before 1970")?.as_secs();
    i64::try_from(secs).context("the clock is past what the store holds")
}

fn unsigned(value: i64) -> Result<u64> {
    u64::try_from(value).with_context(|| format!("time {value} is negative"))
}

/// The pending held sign-ins, newest first, and the accounts locked down now.
pub fn list() -> Result<Signins> {
    let db = history::open()?;
    let mut holds = Vec::new();
    let mut statement = db
        .prepare("SELECT id, time, account, address, place, reason FROM holds WHERE state = 'pending' ORDER BY time DESC")?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, i64>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, String>(3)?,
            r.get::<_, String>(4)?,
            r.get::<_, String>(5)?,
        ))
    })?;
    for row in rows {
        let (id, time, account, address, place, reason) = row?;
        holds.push(HoldView { id, time: unsigned(time)?, account, address, place, reason });
    }
    let rules = signin_check::rules()?;
    let now = now()?;
    let horizon = now - i64::from(rules.lockdown_quiet_hours) * 3600;
    let mut accounts =
        db.prepare("SELECT DISTINCT account FROM events WHERE kind = 'login_failed' AND time >= ?1 ORDER BY account")?;
    let names: Vec<String> = accounts.query_map(params![horizon], |r| r.get(0))?.collect::<rusqlite::Result<_>>()?;
    let existing: Vec<String> = crate::system::read_state()?.into_iter().map(|a| a.name).collect();
    let mut lockdowns = Vec::new();
    for account in names.into_iter().filter(|name| existing.contains(name)) {
        let lifted = history::lifted(&db, &account)?;
        let since = match lifted {
            Some(time) => time + 1,
            None => 0,
        };
        let mut failures = Vec::new();
        for (time, text) in history::failed_signins(&db, &account, since)? {
            let ip: IpAddr = text.parse().with_context(|| format!("{text} is not an IP address"))?;
            failures.push((time, canonical(ip)));
        }
        if let (Some(start), Some(&(last, _))) = (signin::lockdown(&rules, unsigned(now)?, &failures, lifted), failures.last()) {
            lockdowns.push(LockdownView { account, since: start, last_failure: last });
        }
    }
    Ok(Signins { holds, lockdowns })
}

/// Approves the pending held sign-in `id`, which adds its place to the
/// account's profile, or rejects it, banning its address when `ban` is true.
pub fn decide(id: i64, approve: bool, ban: bool) -> Result<Outcome, Failure> {
    let db = history::open()?;
    let address: Option<String> = db
        .query_row("SELECT address FROM holds WHERE id = ?1 AND state = 'pending'", params![id], |r| r.get(0))
        .optional()
        .context("cannot read the held sign-ins")?;
    let Some(address) = address else {
        return Err(Failure::new(format!("there is no pending held sign-in {id}")));
    };
    let state = if approve { "approved" } else { "rejected" };
    db.execute("UPDATE holds SET state = ?1, decided = ?2 WHERE id = ?3", params![state, now()?, id])
        .context("cannot record the decision")?;
    if !approve && ban {
        return settings::ban(&address);
    }
    Ok(Outcome::messages(vec![format!("held sign-in {id} {state}")]))
}

/// Ends the lockdown of `account` now; failures before this moment no
/// longer count toward one.
pub fn lift(account: &str) -> Result<Outcome, Failure> {
    let db = history::open()?;
    db.execute("INSERT OR REPLACE INTO lifts (account, time) VALUES (?1, ?2)", params![account, now()?])
        .context("cannot record the lift")?;
    Ok(Outcome::messages(vec![format!("lifted the lockdown of {account}")]))
}
