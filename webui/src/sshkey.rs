//! OpenSSH public keys in authorized_keys form. Lines with options before
//! the key type are not accepted, so a key added here can never carry a
//! `command=` or any other option.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};

pub const TYPES: [&str; 7] = [
    "ssh-ed25519",
    "sk-ssh-ed25519@openssh.com",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ecdsa-sha2-nistp256@openssh.com",
    "ssh-rsa",
];

/// The smallest RSA key sshd accepts (RequiredRSASize).
pub const MIN_RSA_BITS: u32 = 2048;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub kind: String,
    pub blob: Vec<u8>,
    pub comment: String,
    pub bits: u32,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn string(&mut self) -> Result<&'a [u8], String> {
        let end = self.pos + 4;
        let Some(len) = self.data.get(self.pos..end) else {
            return Err("the key data ends early".into());
        };
        let len = u32::from_be_bytes([len[0], len[1], len[2], len[3]]) as usize;
        let Some(value) = self.data.get(end..end + len) else {
            return Err("the key data ends early".into());
        };
        self.pos = end + len;
        Ok(value)
    }
}

impl PublicKey {
    pub fn parse(line: &str) -> Result<PublicKey, String> {
        let line = line.trim();
        let mut parts = line.splitn(3, [' ', '\t']);
        let kind = match parts.next() {
            Some(k) => k,
            None => return Err("the key is empty".into()),
        };
        if !TYPES.contains(&kind) {
            return Err(format!(
                "a key must start with its type ({}); options such as from= are not accepted",
                TYPES.join(", ")
            ));
        }
        let data = match parts.next() {
            Some(d) if !d.trim().is_empty() => d.trim(),
            _ => return Err("the key has no data after its type".into()),
        };
        let comment = match parts.next() {
            Some(c) => c.trim().to_string(),
            None => String::new(),
        };
        if comment.chars().any(char::is_control) {
            return Err("the key's comment contains control characters".into());
        }
        let blob = match STANDARD.decode(data) {
            Ok(b) => b,
            Err(e) => return Err(format!("the key data is not valid base64: {e}")),
        };
        let mut reader = Reader { data: &blob, pos: 0 };
        if reader.string()? != kind.as_bytes() {
            return Err("the key data does not match the key type".into());
        }
        let bits = match kind {
            "ssh-rsa" => {
                reader.string()?;
                let modulus = reader.string()?;
                let significant: Vec<u8> = modulus.iter().copied().skip_while(|b| *b == 0).collect();
                let bits = match significant.first() {
                    Some(top) => (significant.len() as u32) * 8 - top.leading_zeros(),
                    None => 0,
                };
                if bits < MIN_RSA_BITS {
                    return Err(format!("the RSA key has {bits} bits; sshd needs at least {MIN_RSA_BITS}"));
                }
                bits
            }
            "ecdsa-sha2-nistp384" => 384,
            "ecdsa-sha2-nistp521" => 521,
            _ => 256,
        };
        Ok(PublicKey {
            kind: kind.to_string(),
            blob,
            comment,
            bits,
        })
    }

    /// The fingerprint ssh-keygen -l prints: SHA256 of the key blob.
    pub fn fingerprint(&self) -> String {
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.blob);
        format!("SHA256:{}", STANDARD_NO_PAD.encode(digest.as_ref()))
    }

    /// The key as one authorized_keys line, without a newline.
    pub fn line(&self) -> String {
        if self.comment.is_empty() {
            format!("{} {}", self.kind, STANDARD.encode(&self.blob))
        } else {
            format!("{} {} {}", self.kind, STANDARD.encode(&self.blob), self.comment)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl bob";

    #[test]
    fn parses_ed25519() {
        let key = PublicKey::parse(ED).expect("valid key");
        assert_eq!(key.kind, "ssh-ed25519");
        assert_eq!(key.comment, "bob");
        assert_eq!(key.bits, 256);
        assert!(key.fingerprint().starts_with("SHA256:"));
        assert_eq!(key.line(), ED);
    }

    #[test]
    fn refuses_options_and_garbage() {
        assert!(PublicKey::parse(&format!("command=\"id\" {ED}")).is_err());
        assert!(PublicKey::parse("ssh-dss AAAA").is_err());
        assert!(PublicKey::parse("ssh-ed25519 !!!").is_err());
        assert!(PublicKey::parse("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl").is_err());
    }
}
