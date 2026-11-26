//! Admins, their roles and second factors, and pending invites, kept in
//! /config/webui/admins.json (mode 0600). Admins listed in WEBUI_ADMIN_FILE
//! are read at start and cannot be changed here, except for their TOTP.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sftp_webui::spec;

pub const PATH: &str = "/config/webui/admins.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Full,
    ReadOnly,
}

impl Role {
    pub fn parse(text: &str) -> Option<Role> {
        match text {
            "full" => Some(Role::Full),
            "read-only" => Some(Role::ReadOnly),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::Full => "full",
            Role::ReadOnly => "read-only",
        }
    }

    /// The role as the pages show it.
    pub fn label(self) -> &'static str {
        match self {
            Role::Full => "Full access",
            Role::ReadOnly => "Read-only",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Totp {
    /// The shared secret, base32.
    pub secret: String,
    /// The last time step whose code was accepted; no code of it or an
    /// earlier step is accepted again.
    pub last_step: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Admin {
    pub name: String,
    pub role: Role,
    pub hash: String,
    pub totp: Option<Totp>,
    pub created: u64,
    pub last_login: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub name: String,
    pub role: Role,
    /// SHA-256 of the token, hex.
    pub token_sha256: String,
    pub expires: u64,
    pub created_by: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Data {
    admins: Vec<Admin>,
    /// TOTP and last login of admins from WEBUI_ADMIN_FILE, by name.
    file_admins: BTreeMap<String, FileAdminState>,
    invites: Vec<Invite>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct FileAdminState {
    totp: Option<Totp>,
    last_login: Option<u64>,
}

/// An admin from WEBUI_ADMIN_FILE: `name:role:argon2id-hash` per line.
#[derive(Clone, Debug)]
pub struct FileAdmin {
    pub name: String,
    pub role: Role,
    pub hash: String,
}

/// An admin as the rest of the server sees it, wherever it is defined.
#[derive(Clone, Debug)]
pub struct AdminView {
    pub name: String,
    pub role: Role,
    pub hash: String,
    pub totp: Option<Totp>,
    pub from_file: bool,
    pub last_login: Option<u64>,
}

pub fn read_admin_file(path: &Path) -> Result<Vec<FileAdmin>> {
    let text = fs::read_to_string(path).with_context(|| format!("cannot read WEBUI_ADMIN_FILE={}", path.display()))?;
    let mut admins: Vec<FileAdmin> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, ':');
        let (Some(name), Some(role), Some(hash)) = (parts.next(), parts.next(), parts.next()) else {
            bail!("{} line {}: expected name:role:hash", path.display(), n + 1);
        };
        spec::validate_name(name).map_err(|e| anyhow::anyhow!("{} line {}: {e}", path.display(), n + 1))?;
        let Some(role) = Role::parse(role) else {
            bail!("{} line {}: the role must be full or read-only", path.display(), n + 1);
        };
        if !hash.starts_with("$argon2id$") {
            bail!("{} line {}: the hash must come from sftp-webui hash-password", path.display(), n + 1);
        }
        if admins.iter().any(|a| a.name == name) {
            bail!("{} line {}: {name} is listed twice", path.display(), n + 1);
        }
        admins.push(FileAdmin { name: name.into(), role, hash: hash.into() });
    }
    Ok(admins)
}

pub struct Store {
    path: PathBuf,
    data: Data,
    file_admins: Vec<FileAdmin>,
}

impl Store {
    pub fn load(admin_file: Option<&Path>) -> Result<Store> {
        let path = PathBuf::from(PATH);
        let data = match fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).with_context(|| format!("{PATH} is not valid"))?,
            Err(e) if e.kind() == ErrorKind::NotFound => Data::default(),
            Err(e) => return Err(e).with_context(|| format!("cannot read {PATH}")),
        };
        let file_admins = match admin_file {
            Some(p) => read_admin_file(p)?,
            None => Vec::new(),
        };
        for f in &file_admins {
            if data.admins.iter().any(|a| a.name == f.name) {
                crate::log(&format!(
                    "{} is in both WEBUI_ADMIN_FILE and {PATH}; the admin file's entry is used",
                    f.name
                ));
            }
        }
        Ok(Store { path, data, file_admins })
    }

    pub fn save(&self) -> Result<()> {
        let json = serde_json::to_vec_pretty(&self.data).context("cannot encode the admin store")?;
        let tmp = self.path.with_extension("json.tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        file.write_all(&json)
            .and_then(|()| file.sync_all())
            .with_context(|| format!("cannot write {}", tmp.display()))?;
        fs::rename(&tmp, &self.path).with_context(|| format!("cannot replace {PATH}"))
    }

    pub fn is_empty(&self) -> bool {
        self.data.admins.is_empty() && self.file_admins.is_empty()
    }

    pub fn list(&self) -> Vec<AdminView> {
        let mut out: Vec<AdminView> = self
            .file_admins
            .iter()
            .map(|f| {
                let state = self.data.file_admins.get(&f.name);
                AdminView {
                    name: f.name.clone(),
                    role: f.role,
                    hash: f.hash.clone(),
                    totp: state.and_then(|s| s.totp.clone()),
                    from_file: true,
                    last_login: state.and_then(|s| s.last_login),
                }
            })
            .collect();
        for a in &self.data.admins {
            if out.iter().any(|v| v.name == a.name) {
                continue;
            }
            out.push(AdminView {
                name: a.name.clone(),
                role: a.role,
                hash: a.hash.clone(),
                totp: a.totp.clone(),
                from_file: false,
                last_login: a.last_login,
            });
        }
        out.sort_by(|x, y| x.name.cmp(&y.name));
        out
    }

    pub fn get(&self, name: &str) -> Option<AdminView> {
        self.list().into_iter().find(|a| a.name == name)
    }

    pub fn full_admins(&self) -> usize {
        self.list().iter().filter(|a| a.role == Role::Full).count()
    }

    fn ui_admin(&mut self, name: &str) -> Result<&mut Admin> {
        if self.file_admins.iter().any(|f| f.name == name) {
            bail!("{name} is defined in WEBUI_ADMIN_FILE; change it there");
        }
        match self.data.admins.iter_mut().find(|a| a.name == name) {
            Some(a) => Ok(a),
            None => bail!("there is no admin named {name}"),
        }
    }

    pub fn add(&mut self, name: &str, role: Role, hash: String, now: u64) -> Result<()> {
        spec::validate_name(name).map_err(|e| anyhow::anyhow!(e))?;
        if self.get(name).is_some() {
            bail!("an admin named {name} already exists");
        }
        self.data.admins.push(Admin {
            name: name.into(),
            role,
            hash,
            totp: None,
            created: now,
            last_login: None,
        });
        self.save()
    }

    pub fn set_password(&mut self, name: &str, hash: String) -> Result<()> {
        self.ui_admin(name)?.hash = hash;
        self.save()
    }

    pub fn set_role(&mut self, name: &str, role: Role) -> Result<()> {
        let current = match self.get(name) {
            Some(a) => a.role,
            None => bail!("there is no admin named {name}"),
        };
        if current == Role::Full && role != Role::Full && self.full_admins() <= 1 {
            bail!("{name} is the last full admin");
        }
        self.ui_admin(name)?.role = role;
        self.save()
    }

    pub fn remove(&mut self, name: &str) -> Result<()> {
        let admin = match self.get(name) {
            Some(a) => a,
            None => bail!("there is no admin named {name}"),
        };
        if admin.role == Role::Full && self.full_admins() <= 1 {
            bail!("{name} is the last full admin");
        }
        self.ui_admin(name)?;
        self.data.admins.retain(|a| a.name != name);
        self.save()
    }

    pub fn set_totp(&mut self, name: &str, totp: Option<Totp>) -> Result<()> {
        if self.file_admins.iter().any(|f| f.name == name) {
            self.data.file_admins.entry(name.to_string()).or_default().totp = totp;
        } else {
            self.ui_admin(name)?.totp = totp;
        }
        self.save()
    }

    pub fn logged_in(&mut self, name: &str, now: u64) -> Result<()> {
        if self.file_admins.iter().any(|f| f.name == name) {
            self.data.file_admins.entry(name.to_string()).or_default().last_login = Some(now);
        } else {
            self.ui_admin(name)?.last_login = Some(now);
        }
        self.save()
    }

    pub fn invites(&self, now: u64) -> Vec<Invite> {
        self.data.invites.iter().filter(|i| i.expires > now).cloned().collect()
    }

    pub fn add_invite(&mut self, invite: Invite) -> Result<()> {
        if self.get(&invite.name).is_some() || self.data.invites.iter().any(|i| i.name == invite.name) {
            bail!("an admin or invite named {} already exists", invite.name);
        }
        let now = sftp_webui::timefmt::now();
        self.data.invites.retain(|i| i.expires > now);
        self.data.invites.push(invite);
        self.save()
    }

    pub fn find_invite(&self, token_sha256: &str, now: u64) -> Option<Invite> {
        self.data
            .invites
            .iter()
            .find(|i| i.expires > now && crate::auth::same(i.token_sha256.as_bytes(), token_sha256.as_bytes()))
            .cloned()
    }

    pub fn remove_invite(&mut self, name: &str) -> Result<()> {
        let before = self.data.invites.len();
        self.data.invites.retain(|i| i.name != name);
        if self.data.invites.len() == before {
            bail!("there is no invite for {name}");
        }
        self.save()
    }
}
