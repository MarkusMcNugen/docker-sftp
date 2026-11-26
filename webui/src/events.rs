//! Login and file events read from the collector's log: syslog lines with
//! RFC 3339 times, written by sshd and by internal-sftp at log level INFO.
//! internal-sftp names no account on its file lines, only its process id;
//! the session line of the same process says whose it is.

use serde::{Deserialize, Serialize};

use crate::timefmt;

/// One syslog line: when, which program and process, and the message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<'a> {
    pub time: u64,
    pub program: &'a str,
    pub pid: u64,
    pub message: &'a str,
}

/// The value of a run of ASCII digits; None when the text holds anything
/// else or the value does not fit.
fn digits(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.bytes().try_fold(0u64, |acc, b| acc.checked_mul(10)?.checked_add(u64::from(b - b'0')))
}

/// `2026-11-26T01:00:00.123456+00:00 host program[pid]: message`; None for
/// a line in any other shape.
pub fn record(line: &str) -> Option<Record<'_>> {
    let (stamp, rest) = line.split_once(' ')?;
    let time = timefmt::parse_rfc3339(stamp)?;
    let (_host, rest) = rest.split_once(' ')?;
    let (tag, message) = rest.split_once(": ")?;
    let (program, pid) = match tag.strip_suffix(']').and_then(|t| t.split_once('[')) {
        Some((program, pid)) => (program, digits(pid)?),
        None => (tag, 0),
    };
    Some(Record { time, program, pid, message })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    LoginOk,
    LoginFailed,
    SessionOpened,
    SessionClosed,
    Browse,
    Download,
    Upload,
    Delete,
    Rename,
    Mkdir,
    Rmdir,
    Attributes,
    Link,
    /// A copy the file browser made: `path` is the copy, `other` the
    /// original.
    Copy,
}

impl Kind {
    /// The name the history stores.
    pub fn name(self) -> &'static str {
        match self {
            Kind::LoginOk => "login_ok",
            Kind::LoginFailed => "login_failed",
            Kind::SessionOpened => "session_opened",
            Kind::SessionClosed => "session_closed",
            Kind::Browse => "browse",
            Kind::Download => "download",
            Kind::Upload => "upload",
            Kind::Delete => "delete",
            Kind::Rename => "rename",
            Kind::Mkdir => "mkdir",
            Kind::Rmdir => "rmdir",
            Kind::Attributes => "attributes",
            Kind::Link => "link",
            Kind::Copy => "copy",
        }
    }
}

/// What a message says happened. `account` and `address` are empty on
/// internal-sftp's file lines; `bytes` counts what was read or written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Happening {
    pub kind: Kind,
    /// Done in the file browser rather than over SSH.
    pub web: bool,
    /// Who did it in the file browser: the account itself, or one that
    /// manages it. Empty over SSH, where it is always the account.
    pub actor: String,
    pub account: String,
    pub address: String,
    pub path: String,
    pub other: String,
    pub bytes: u64,
}

impl Happening {
    fn new(kind: Kind) -> Happening {
        Happening {
            kind,
            web: false,
            actor: String::new(),
            account: String::new(),
            address: String::new(),
            path: String::new(),
            other: String::new(),
            bytes: 0,
        }
    }
}

/// What the file browser logs, in the auth log, for each sign-in and each
/// thing it does with files: its own sftp sessions come from loopback, so
/// only it knows who acted and from where.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebEvent {
    pub kind: Kind,
    /// Who acted.
    pub actor: String,
    /// Whose files.
    pub account: String,
    /// The person's address.
    pub address: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub other: String,
    #[serde(default)]
    pub bytes: u64,
}

/// What a file browser event's message starts with.
const WEB_EVENT: &str = "file browser event ";

/// The auth log message for a file browser event.
pub fn web_event_message(event: &WebEvent) -> Result<String, String> {
    match serde_json::to_string(event) {
        Ok(json) => Ok(format!("{WEB_EVENT}{json}")),
        Err(e) => Err(format!("cannot write a file browser event: {e}")),
    }
}

/// Reads a file browser event from the web servers' messages; None for any
/// other message, and an error for an event that cannot be read.
pub fn web_happening(message: &str) -> Option<Result<Happening, String>> {
    let json = message.strip_prefix(WEB_EVENT)?;
    let event: WebEvent = match serde_json::from_str(json) {
        Ok(e) => e,
        Err(e) => return Some(Err(format!("a file browser event cannot be read ({e}): {json}"))),
    };
    Some(Ok(Happening {
        kind: event.kind,
        web: true,
        actor: event.actor,
        account: event.account,
        address: event.address,
        path: event.path,
        other: event.other,
        bytes: event.bytes,
    }))
}

/// The text between the first quote and `end`, which follows the closing
/// quote; names in internal-sftp's messages are quoted without escaping.
fn quoted<'a>(text: &'a str, end: &str) -> Option<&'a str> {
    let inner = text.strip_prefix('"')?;
    if end.is_empty() {
        return inner.strip_suffix('"');
    }
    inner.rsplit_once(&format!("\"{end}")).map(|(name, _)| name)
}

/// `alice from 203.0.113.24 port 51234 ssh2...` as account and address.
fn who(text: &str) -> Option<(String, String)> {
    let (account, rest) = text.split_once(" from ")?;
    let address = rest.split(' ').next()?;
    Some((account.to_string(), address.to_string()))
}

/// Reads an sshd or internal-sftp message; None for one that records
/// nothing the history keeps.
pub fn happening(program: &str, message: &str) -> Option<Happening> {
    match program {
        "sshd" | "sshd-session" => sshd(message),
        "internal-sftp" | "sftp-server" => sftp(message),
        _ => None,
    }
}

fn sshd(message: &str) -> Option<Happening> {
    if let Some(rest) = message.strip_prefix("Accepted ") {
        let (method, rest) = rest.split_once(" for ")?;
        let (account, address) = who(rest)?;
        return Some(Happening { account, address, other: method.into(), ..Happening::new(Kind::LoginOk) });
    }
    if let Some(rest) = message.strip_prefix("Failed ") {
        let (method, rest) = rest.split_once(" for ")?;
        let rest = match rest.strip_prefix("invalid user ") {
            Some(r) => r,
            None => rest,
        };
        let (account, address) = who(rest)?;
        return Some(Happening { account, address, other: method.into(), ..Happening::new(Kind::LoginFailed) });
    }
    None
}

fn sftp(message: &str) -> Option<Happening> {
    let session = |rest: &str, kind: Kind| -> Option<Happening> {
        let (account, address) = rest.split_once(" from [")?;
        let address = address.strip_suffix(']')?;
        Some(Happening { account: account.into(), address: address.into(), ..Happening::new(kind) })
    };
    if let Some(rest) = message.strip_prefix("session opened for local user ") {
        return session(rest, Kind::SessionOpened);
    }
    if let Some(rest) = message.strip_prefix("session closed for local user ") {
        return session(rest, Kind::SessionClosed);
    }
    if let Some(rest) = message.strip_prefix("closedir ") {
        return Some(Happening { path: quoted(rest, "")?.into(), ..Happening::new(Kind::Browse) });
    }
    if let Some(rest) = message.strip_prefix("close ") {
        let path = quoted(rest, " bytes read ")?;
        let counts = rest.rsplit_once(" bytes read ")?.1;
        let (read, written) = counts.split_once(" written ")?;
        let (read, written) = (digits(read.trim())?, digits(written.trim())?);
        let kind = if written > 0 { Kind::Upload } else { Kind::Download };
        return Some(Happening { path: path.into(), bytes: read + written, ..Happening::new(kind) });
    }
    let two = |rest: &str, kind: Kind| -> Option<Happening> {
        let inner = rest.strip_prefix("old \"")?.strip_suffix('"')?;
        let (from, to) = inner.split_once("\" new \"")?;
        Some(Happening { path: from.into(), other: to.into(), ..Happening::new(kind) })
    };
    for (prefix, kind) in [("rename ", Kind::Rename), ("posix-rename ", Kind::Rename), ("symlink ", Kind::Link), ("hardlink ", Kind::Link)] {
        if let Some(rest) = message.strip_prefix(prefix) {
            return two(rest, kind);
        }
    }
    if let Some(rest) = message.strip_prefix("remove name ") {
        return Some(Happening { path: quoted(rest, "")?.into(), ..Happening::new(Kind::Delete) });
    }
    if let Some(rest) = message.strip_prefix("rmdir name ") {
        return Some(Happening { path: quoted(rest, "")?.into(), ..Happening::new(Kind::Rmdir) });
    }
    if let Some(rest) = message.strip_prefix("mkdir name ") {
        return Some(Happening { path: quoted(rest, " mode ")?.into(), ..Happening::new(Kind::Mkdir) });
    }
    if let Some(rest) = message.strip_prefix("set ") {
        let path = quoted(rest, " ")?;
        return Some(Happening { path: path.into(), ..Happening::new(Kind::Attributes) });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_rfc3339_syslog_lines() {
        let r = record("2026-11-26T01:00:00.123456+01:00 sftp sshd-session[42]: Accepted password for alice from 203.0.113.24 port 51234 ssh2").expect("a line");
        assert_eq!(Some(r.time), timefmt::parse_rfc3339("2026-11-26T00:00:00Z"));
        assert_eq!((r.program, r.pid), ("sshd-session", 42));
        assert!(record("Nov 26 01:00:00 sftp sshd[1]: Accepted password for a from 1.2.3.4 port 1 ssh2").is_none());
    }

    #[test]
    fn reads_logins() {
        let h = happening("sshd-session", "Accepted publickey for alice from 2001:db8::5 port 5 ssh2: ED25519 SHA256:x").expect("a login");
        assert_eq!((h.kind, h.account.as_str(), h.address.as_str(), h.other.as_str()), (Kind::LoginOk, "alice", "2001:db8::5", "publickey"));
        let h = happening("sshd", "Failed password for invalid user bob from 198.51.100.7 port 9 ssh2").expect("a failure");
        assert_eq!((h.kind, h.account.as_str(), h.address.as_str()), (Kind::LoginFailed, "bob", "198.51.100.7"));
        assert!(happening("sshd", "Received disconnect from 1.2.3.4 port 5:11: bye").is_none());
    }

    #[test]
    fn reads_the_file_browsers_events_back() {
        let event = WebEvent {
            kind: Kind::Upload,
            actor: "cat".into(),
            account: "ann".into(),
            address: "203.0.113.9".into(),
            path: "/up/a \"b\"\n.txt".into(),
            other: String::new(),
            bytes: 4,
        };
        let message = web_event_message(&event).expect("a message");
        assert!(!message.contains('\n'), "one line, whatever the name holds");
        let h = web_happening(&message).expect("an event").expect("a readable event");
        assert_eq!(
            (h.kind, h.web, h.actor.as_str(), h.account.as_str(), h.address.as_str(), h.path.as_str(), h.bytes),
            (Kind::Upload, true, "cat", "ann", "203.0.113.9", "/up/a \"b\"\n.txt", 4)
        );
        assert!(web_happening("failed login from 203.0.113.9 (file browser)").is_none(), "other messages are not events");
        assert!(web_happening("file browser event {\"kind\":\"teleport\"}").expect("an event").is_err(), "a bad event is an error");
    }

    #[test]
    fn reads_file_operations() {
        let h = happening("internal-sftp", "session opened for local user alice from [203.0.113.24]").expect("a session");
        assert_eq!((h.kind, h.account.as_str(), h.address.as_str()), (Kind::SessionOpened, "alice", "203.0.113.24"));
        let h = happening("internal-sftp", "close \"/upload/a b.txt\" bytes read 0 written 1234").expect("an upload");
        assert_eq!((h.kind, h.path.as_str(), h.bytes), (Kind::Upload, "/upload/a b.txt", 1234));
        let h = happening("internal-sftp", "close \"/pub/x\" bytes read 99 written 0").expect("a download");
        assert_eq!((h.kind, h.bytes), (Kind::Download, 99));
        let h = happening("internal-sftp", "closedir \"/upload\"").expect("a browse");
        assert_eq!((h.kind, h.path.as_str()), (Kind::Browse, "/upload"));
        let h = happening("internal-sftp", "rename old \"/a\" new \"/b\"").expect("a rename");
        assert_eq!((h.kind, h.path.as_str(), h.other.as_str()), (Kind::Rename, "/a", "/b"));
        let h = happening("internal-sftp", "mkdir name \"/new dir\" mode 0777").expect("a mkdir");
        assert_eq!((h.kind, h.path.as_str()), (Kind::Mkdir, "/new dir"));
        let h = happening("internal-sftp", "remove name \"/old\"").expect("a delete");
        assert_eq!((h.kind, h.path.as_str()), (Kind::Delete, "/old"));
        let h = happening("internal-sftp", "set \"/f\" mode 0644").expect("a set");
        assert_eq!((h.kind, h.path.as_str()), (Kind::Attributes, "/f"));
        assert!(happening("internal-sftp", "open \"/f\" flags READ mode 0666").is_none());
    }

    #[test]
    fn rfc3339_times() {
        assert_eq!(timefmt::parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timefmt::parse_rfc3339("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(timefmt::parse_rfc3339("1970-01-02T00:00:00.5-00:30"), Some(86_400 + 1_800));
        assert_eq!(timefmt::parse_rfc3339("2026-02-30T00:00:00Z"), None);
        assert_eq!(timefmt::parse_rfc3339("2026-11-26 00:00:00Z"), None);
    }
}
