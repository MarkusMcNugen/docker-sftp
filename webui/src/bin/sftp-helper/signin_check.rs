//! The account check sshd runs through pam_exec after a password or key is
//! accepted: whether the sign-in goes ahead, given where it comes from and
//! the account's history. A held sign-in is recorded for an admin's approval.
//!
//! sshd logs a sign-in this check stops as failed, the line a wrong password
//! writes. So each stopped sign-in leaves a note, named by the pid of the
//! sshd process that logs it, that tells the history collector what the
//! failure was, and a token, named by the address, that fail2ban's sshd
//! jail removes in place of counting the failure.

use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use sftp_webui::events::Kind;
use sftp_webui::geo;
use sftp_webui::net::canonical;
use sftp_webui::signin::{self, Decision, Hold, Place, Rules, Seen};

use crate::{history, settings, system};

/// The history collector's notes, one per stopped sign-in, named by the pid
/// of the sshd process that logs it.
pub const NOTES: &str = "/run/sftp/signin-checks";

/// fail2ban's tokens, one per stopped sign-in, named `<address>_<pid>`; the
/// sshd jail's ignorecommand in rootfs/etc/fail2ban/jail.d/00-sftp.conf
/// removes them.
const EXCUSES: &str = "/run/sftp/signin-excused";

/// What the sftp client is told when the check itself fails.
const UNCHECKED: &str = "this sign-in could not be checked, so it is refused; tell an admin";

/// What the check says about a sign-in.
pub enum Answer {
    Allow,
    /// Held for an admin's approval, and why.
    Held(String),
    Refused,
}

fn place_text(place: &Place) -> String {
    match place {
        Place::FileBrowser => "file browser".into(),
        Place::Local => "local network".into(),
        Place::Country(code) => code.clone(),
        Place::Unknown => "unknown".into(),
    }
}

fn address(text: &str) -> Result<IpAddr> {
    let ip: IpAddr = text.parse().with_context(|| format!("{text} is not an IP address"))?;
    Ok(canonical(ip))
}

/// The thresholds in force: the environment's, else settings.conf's, else
/// the defaults in signin::Rules.
pub fn rules() -> Result<Rules> {
    let defaults = Rules::default();
    let value = |key: &str, default: u32| -> Result<u32> {
        let text = settings::current(key, &default.to_string())?;
        text.trim().parse().with_context(|| format!("{key}={text} is not a whole number"))
    };
    Ok(Rules {
        learn_signins: value("SIGNIN_LEARN_SIGNINS", defaults.learn_signins)?,
        learn_days: value("SIGNIN_LEARN_DAYS", defaults.learn_days)?,
        travel_kmh: value("SIGNIN_TRAVEL_KMH", defaults.travel_kmh)?,
        spray_addresses: value("SIGNIN_SPRAY_ADDRESSES", defaults.spray_addresses)?,
        spray_minutes: value("SIGNIN_SPRAY_MINUTES", defaults.spray_minutes)?,
        lockdown_quiet_hours: value("SIGNIN_LOCKDOWN_HOURS", defaults.lockdown_quiet_hours)?,
    })
}

/// Decides the sign-in of `account` from the address `from`, now.
pub fn check(account: &str, from: &str) -> Result<Answer> {
    let ip = address(from)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).context("the clock is before 1970")?.as_secs();
    let rules = rules()?;
    let countries = geo::Countries::open(geo::database_path())?;
    let place_of = |ip: IpAddr| -> Result<Place> { Ok(signin::place_of(ip, countries.lookup(ip)?.as_deref())) };
    let place = place_of(ip)?;
    if place == Place::FileBrowser {
        return Ok(Answer::Allow);
    }
    let db = history::open()?;
    let mut seen = Vec::new();
    for (time, text) in history::approved_signins(&db, account)? {
        let seen_ip = address(&text)?;
        seen.push(Seen { time, address: seen_ip, place: place_of(seen_ip)? });
    }
    let lifted = history::lifted(&db, account)?;
    let since = match lifted {
        Some(time) => time + 1,
        None => 0,
    };
    let mut failures = Vec::new();
    for (time, text) in history::failed_signins(&db, account, since)? {
        failures.push((time, address(&text)?));
    }
    let locked = signin::lockdown(&rules, now, &failures, lifted).is_some();
    Ok(match signin::decide(&rules, now, ip, &place, &seen, locked, sftp_webui::distance::km) {
        Decision::Allow => Answer::Allow,
        Decision::Refuse => Answer::Refused,
        Decision::Hold(hold) => {
            let reason = match hold {
                Hold::NewPlace => "New place: the account has not signed in from here".to_string(),
                Hold::ImpossibleTravel { from, kmh } => format!("Impossible travel: {kmh} km/h from its last sign-in in {from}"),
            };
            history::record_hold(&db, now, account, &ip.to_string(), &place_text(&place), &reason)?;
            Answer::Held(reason)
        }
    })
}

/// Logs `msg` to the auth log as a warning, or to stderr, which pam_exec
/// discards, when syslog cannot be reached.
fn report(msg: &str) {
    if let Err(e) = system::syslog(true, msg) {
        eprintln!("sign-in check: cannot reach syslog ({e}): {msg}");
    }
}

/// `text` with its first letter in capitals.
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Leaves the note and the token for a sign-in sshd is about to log as
/// failed. `from` must parse as an address, since it names the token.
fn leave_notes(kind: &str, account: &str, from: &str) -> Result<()> {
    if let Err(e) = from.parse::<IpAddr>() {
        bail!("{from} is not an address ({e}), so it names no token");
    }
    let sshd = std::os::unix::process::parent_id();
    for dir in [NOTES, EXCUSES] {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot make {dir}"))?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).with_context(|| format!("cannot restrict {dir}"))?;
    }
    std::fs::write(format!("{NOTES}/{sshd}"), format!("{kind}\t{account}\t{from}\n"))
        .context("cannot leave the history collector's note")?;
    std::fs::write(format!("{EXCUSES}/{from}_{sshd}"), "").context("cannot leave fail2ban's token")?;
    Ok(())
}

/// What pam_exec runs in sshd's account stage, with PAM_USER and PAM_RHOST
/// set; exit status 0 lets the sign-in go ahead. A stopped sign-in is
/// logged, leaves its note and token, and says why on stdout, which
/// pam_exec's stdout option shows the sftp client. A check that cannot run
/// refuses the sign-in.
pub fn from_pam() -> ExitCode {
    let account = match std::env::var("PAM_USER") {
        Ok(account) => account,
        Err(e) => {
            report(&format!("refused a sign-in it could not check: PAM_USER: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let from = match std::env::var("PAM_RHOST") {
        Ok(from) => from,
        Err(e) => {
            report(&format!("refused the sign-in of {account}, which it could not check: PAM_RHOST: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let (kind, logged, told) = match check(&account, &from) {
        Ok(Answer::Allow) => return ExitCode::SUCCESS,
        Ok(Answer::Held(reason)) => {
            ("held", format!("held the sign-in of {account} from {from} for an admin's approval: {reason}"), signin::HELD)
        }
        Ok(Answer::Refused) => {
            ("refused", format!("refused the sign-in of {account} from {from}: the account is locked down"), signin::LOCKED)
        }
        Err(e) => ("refused", format!("refused the sign-in of {account} from {from}, which it could not check: {e:#}"), UNCHECKED),
    };
    report(&logged);
    if let Err(e) = leave_notes(kind, &account, &from) {
        report(&format!("the failure sshd logs for {account} from {from} counts against the address: {e:#}"));
    }
    println!("{}", capitalized(told));
    ExitCode::FAILURE
}

/// What the failed sign-in that sshd process `pid` logged really was, from
/// the note the check left in `notes`, which is then used up. None when no
/// note names that account and address.
pub fn excused(notes: &Path, pid: u64, account: &str, address: &str) -> Result<Option<Kind>> {
    let path = notes.join(pid.to_string());
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let mut fields = text.trim_end().splitn(3, '\t');
    let (kind, noted_account, noted_address) = (fields.next(), fields.next(), fields.next());
    if noted_account != Some(account) || noted_address != Some(address) {
        return Ok(None);
    }
    std::fs::remove_file(&path).with_context(|| format!("cannot use up {}", path.display()))?;
    match kind {
        Some("held") => Ok(Some(Kind::LoginHeld)),
        Some("refused") => Ok(Some(Kind::LoginRefused)),
        other => bail!("{} names no answer the check gives: {other:?}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_turns_one_failure_into_what_the_check_did() {
        let notes = std::env::temp_dir().join(format!("signin-notes-{}", std::process::id()));
        std::fs::create_dir_all(&notes).expect("a notes directory");
        std::fs::write(notes.join("4242"), "held\tsig\t198.51.100.40\n").expect("a note");
        assert_eq!(excused(&notes, 4242, "spray", "198.51.100.40").expect("a read"), None, "another account");
        assert_eq!(excused(&notes, 4242, "sig", "198.51.100.41").expect("a read"), None, "another address");
        assert_eq!(excused(&notes, 4343, "sig", "198.51.100.40").expect("a read"), None, "another process");
        assert_eq!(excused(&notes, 4242, "sig", "198.51.100.40").expect("a read"), Some(Kind::LoginHeld));
        assert_eq!(excused(&notes, 4242, "sig", "198.51.100.40").expect("a read"), None, "a note is used once");
        std::fs::write(notes.join("4343"), "refused\tspray\t2001:db8::5\n").expect("a note");
        assert_eq!(excused(&notes, 4343, "spray", "2001:db8::5").expect("a read"), Some(Kind::LoginRefused));
        std::fs::remove_dir(&notes).expect("the notes directory, empty");
    }

    #[test]
    fn capitalizes_the_answer_for_the_client() {
        assert_eq!(capitalized(signin::HELD).chars().next(), Some('T'));
        assert_eq!(capitalized(""), "");
    }
}
