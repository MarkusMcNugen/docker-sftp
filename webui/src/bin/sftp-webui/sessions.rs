//! Admin sessions, in memory: a restart logs every admin out. The cookie
//! holds a 256-bit random id; the store keeps only its SHA-256.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use anyhow::Result;

use crate::auth;
use crate::store::Role;

pub const COOKIE: &str = "__Host-sftp_session";
/// Double-submit token of the forms shown before login.
pub const LOGIN_COOKIE: &str = "__Host-sftp_login";
pub const IDLE: Duration = Duration::from_secs(30 * 60);
pub const ABSOLUTE: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Clone, Debug)]
pub struct Flash {
    /// ok, error or info.
    pub kind: &'static str,
    pub text: String,
    pub detail: Vec<String>,
}

impl Flash {
    pub fn ok(text: impl Into<String>, detail: Vec<String>) -> Flash {
        Flash { kind: "ok", text: text.into(), detail }
    }

    pub fn error(text: impl Into<String>, detail: Vec<String>) -> Flash {
        Flash { kind: "error", text: text.into(), detail }
    }
}

pub struct Session {
    pub admin: String,
    pub role: Role,
    pub csrf: String,
    created: Instant,
    seen: Instant,
    pub flash: Vec<Flash>,
    /// A TOTP secret shown for enrollment and not yet confirmed.
    pub totp_setup: Option<Vec<u8>>,
}

#[derive(Default)]
pub struct Sessions {
    map: HashMap<String, Session>,
}

fn key(cookie: &str) -> String {
    auth::sha256_hex(cookie.as_bytes())
}

impl Sessions {
    /// Returns the cookie value of a new session.
    pub fn create(&mut self, admin: &str, role: Role) -> Result<String> {
        let now = Instant::now();
        self.map.retain(|_, s| now.duration_since(s.seen) < IDLE && now.duration_since(s.created) < ABSOLUTE);
        let cookie = auth::token()?;
        self.map.insert(
            key(&cookie),
            Session {
                admin: admin.into(),
                role,
                csrf: auth::token()?,
                created: now,
                seen: now,
                flash: Vec::new(),
                totp_setup: None,
            },
        );
        Ok(cookie)
    }

    /// The live session of a cookie. `touch` counts the request as activity.
    pub fn get(&mut self, cookie: &str, touch: bool) -> Option<&mut Session> {
        let k = key(cookie);
        let now = Instant::now();
        let s = self.map.get(&k)?;
        let expired = now.duration_since(s.seen) >= IDLE || now.duration_since(s.created) >= ABSOLUTE;
        if expired {
            self.map.remove(&k);
            return None;
        }
        let session = self.map.get_mut(&k)?;
        if touch {
            session.seen = now;
        }
        Some(session)
    }

    pub fn remove(&mut self, cookie: &str) {
        self.map.remove(&key(cookie));
    }

    /// Ends every session of an admin except the one with `keep` as cookie.
    pub fn remove_admin(&mut self, admin: &str, keep: Option<&str>) {
        let keep = keep.map(key);
        self.map.retain(|k, s| s.admin != admin || keep.as_deref() == Some(k.as_str()));
    }
}
