//! Passwords (argon2id), second factors (TOTP) and the throttle on failed
//! logins.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use argon2::{Algorithm, Argon2, Params, PasswordHasher, PasswordVerifier, Version};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::Semaphore;

pub const MIN_PASSWORD: usize = 12;
/// argon2id with 64 MiB, three passes, one lane.
const MEMORY_KIB: u32 = 64 * 1024;
const PASSES: u32 = 3;
const LANES: u32 = 1;
/// Verifications that run at once; the rest wait, so a flood of logins
/// holds at most this many times 64 MiB.
const CONCURRENT: usize = 2;

pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    SystemRandom::new().fill(&mut buf).map_err(|e| anyhow!("no randomness available: {e}"))?;
    Ok(buf)
}

/// A 256-bit random token, base64url.
pub fn token() -> Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes(32)?))
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Compares in time that depends only on the lengths.
pub fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn check_password_rules(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD {
        return Err(format!("the password needs at least {MIN_PASSWORD} characters"));
    }
    if password.chars().any(char::is_control) {
        return Err("the password may not contain control characters".into());
    }
    Ok(())
}

pub struct Hasher {
    argon: Argon2<'static>,
    gate: Arc<Semaphore>,
    /// Verified against for unknown names, so a login takes as long whether
    /// or not the name exists.
    dummy: String,
}

impl Hasher {
    pub fn new() -> Result<Hasher> {
        let params = Params::new(MEMORY_KIB, PASSES, LANES, None).map_err(|e| anyhow!("argon2 parameters: {e}"))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut hasher = Hasher { argon, gate: Arc::new(Semaphore::new(CONCURRENT)), dummy: String::new() };
        hasher.dummy = hasher.hash(&token()?)?;
        Ok(hasher)
    }

    pub fn hash(&self, password: &str) -> Result<String> {
        let salt = random_bytes(16)?;
        let hash = self
            .argon
            .hash_password_with_salt(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("cannot hash the password: {e}"))?;
        Ok(hash.to_string())
    }

    /// Checks a password against a stored hash, or against the dummy hash
    /// when `hash` is None, which always fails.
    pub async fn verify(&self, hash: Option<String>, password: String) -> Result<bool> {
        let permit = Arc::clone(&self.gate).acquire_owned().await.context("the password gate is closed")?;
        let argon = self.argon.clone();
        let known = hash.is_some();
        let hash = match hash {
            Some(h) => h,
            None => self.dummy.clone(),
        };
        let result = tokio::task::spawn_blocking(move || {
            let outcome = argon.verify_password(password.as_bytes(), hash.as_str());
            drop(permit);
            outcome
        })
        .await
        .context("the password check stopped")?;
        match result {
            Ok(()) => Ok(known),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            Err(e) => Err(anyhow!("cannot check the password: {e}")),
        }
    }

    /// As `verify`, on the calling thread, for a caller that limits itself
    /// how many checks run at once.
    pub fn verify_blocking(&self, hash: Option<&str>, password: &str) -> Result<bool> {
        let known = hash.is_some();
        let hash = match hash {
            Some(h) => h,
            None => self.dummy.as_str(),
        };
        match self.argon.verify_password(password.as_bytes(), hash) {
            Ok(()) => Ok(known),
            Err(argon2::password_hash::Error::PasswordInvalid) => Ok(false),
            Err(e) => Err(anyhow!("cannot check the password: {e}")),
        }
    }
}

/// RFC 6238: SHA-1, six digits, 30-second steps.
pub fn totp(secret: &[u8], account: &str) -> Result<totp_rs::Totp> {
    totp_rs::Builder::new()
        .with_algorithm(totp_rs::Algorithm::SHA1)
        .with_digits(6)
        .with_skew(1)
        .with_step_duration(30)
        .with_secret(secret.to_vec())
        .with_account_name(account)
        .with_issuer(Some("sftp"))
        .build()
        .map_err(|e| anyhow!("cannot set up TOTP: {e}"))
}

/// The step of the code if it matches the previous, current or next step
/// and that step is later than `last_step`; each code works once.
pub fn check_code(totp: &totp_rs::Totp, code: &str, last_step: u64, now: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let current = now / 30;
    let mut found = None;
    for step in current.saturating_sub(1)..=current + 1 {
        let expected = totp.generate(step * 30).to_string();
        if same(expected.as_bytes(), code.as_bytes()) && step > last_step && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// Why a login is refused before its password is checked.
pub enum Refusal {
    Locked(Duration),
    Busy(Duration),
}

const WINDOW: Duration = Duration::from_secs(15 * 60);
const ADDRESS_LIMIT: usize = 5;
const LOCKOUT: Duration = Duration::from_secs(15 * 60);
const MINUTE: Duration = Duration::from_secs(60);
const GLOBAL_LIMIT: u32 = 30;

/// Five failures in fifteen minutes lock an address out for fifteen
/// minutes; across all addresses at most thirty failures a minute are
/// evaluated.
pub struct Throttle {
    failures: HashMap<IpAddr, Vec<Instant>>,
    locked: HashMap<IpAddr, Instant>,
    minute_start: Instant,
    minute_failures: u32,
}

impl Throttle {
    pub fn new() -> Throttle {
        Throttle {
            failures: HashMap::new(),
            locked: HashMap::new(),
            minute_start: Instant::now(),
            minute_failures: 0,
        }
    }

    pub fn check(&mut self, ip: IpAddr, now: Instant) -> Result<(), Refusal> {
        if let Some(until) = self.locked.get(&ip) {
            if *until > now {
                return Err(Refusal::Locked(*until - now));
            }
            self.locked.remove(&ip);
        }
        if now.duration_since(self.minute_start) >= MINUTE {
            self.minute_start = now;
            self.minute_failures = 0;
        }
        if self.minute_failures >= GLOBAL_LIMIT {
            return Err(Refusal::Busy(MINUTE.saturating_sub(now.duration_since(self.minute_start))));
        }
        Ok(())
    }

    /// Records a failure; true when it locked the address out.
    pub fn failure(&mut self, ip: IpAddr, now: Instant) -> bool {
        self.minute_failures += 1;
        self.failures.retain(|_, times| {
            times.retain(|t| now.duration_since(*t) < WINDOW);
            !times.is_empty()
        });
        self.locked.retain(|_, until| *until > now);
        let times = self.failures.entry(ip).or_default();
        times.push(now);
        if times.len() >= ADDRESS_LIMIT {
            self.locked.insert(ip, now + LOCKOUT);
            self.failures.remove(&ip);
            return true;
        }
        false
    }

    pub fn success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttles_an_address_and_the_server() {
        let mut t = Throttle::new();
        let ip: IpAddr = "192.0.2.1".parse().expect("ip");
        let now = Instant::now();
        for i in 0..4 {
            assert!(t.check(ip, now).is_ok());
            assert!(!t.failure(ip, now + Duration::from_secs(i)));
        }
        assert!(t.failure(ip, now + Duration::from_secs(5)));
        assert!(matches!(t.check(ip, now + Duration::from_secs(6)), Err(Refusal::Locked(_))));
        assert!(t.check(ip, now + LOCKOUT + Duration::from_secs(6)).is_ok());
        let mut g = Throttle::new();
        for i in 0..GLOBAL_LIMIT {
            let other: IpAddr = format!("198.51.100.{}", i % 200).parse().expect("ip");
            g.failure(other, now);
        }
        assert!(matches!(g.check(ip, now), Err(Refusal::Busy(_))));
        assert!(g.check(ip, now + MINUTE + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn accepts_each_code_once() {
        let secret = vec![7u8; 20];
        let t = totp(&secret, "alice").expect("totp");
        let now = 1_900_000_000;
        let code = t.generate(now).to_string();
        let step = check_code(&t, &code, 0, now).expect("valid code");
        assert_eq!(check_code(&t, &code, step, now), None);
        assert_eq!(check_code(&t, "12345", 0, now), None);
    }

    #[test]
    fn compares_in_constant_shape() {
        assert!(same(b"abc", b"abc"));
        assert!(!same(b"abc", b"abd"));
        assert!(!same(b"abc", b"ab"));
    }
}
