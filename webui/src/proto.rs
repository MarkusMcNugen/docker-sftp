//! Requests the web UI sends the root helper, one JSON object per
//! connection, and the reply the helper sends back. Every field is named and
//! typed; an unknown field or action is refused.

use serde::{Deserialize, Serialize};

use crate::spec::{Group, Options};

pub const SOCKET: &str = "/run/sftp-webui/helper.sock";
/// Where the file browser reaches the root helper. That socket takes only
/// `FilesRequest`s, and only from the file browser's own system account.
pub const FILES_SOCKET: &str = "/run/sftp-files/helper.sock";

/// The most a request may hold: the web server accepts 64 KiB per request,
/// and JSON escaping can make text up to six times longer.
pub const MAX_REQUEST: usize = 6 * 64 * 1024;

/// Who asked for a change, recorded in the audit log.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub admin: String,
    pub address: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PasswordChange {
    Keep,
    Clear,
    Set { value: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountInput {
    pub name: String,
    pub password: PasswordChange,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub dirs: Vec<String>,
    pub options: Options,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BanRules {
    pub bantime: String,
    pub findtime: String,
    pub maxretry: u32,
    pub increment: bool,
    pub maxtime: String,
    pub ignoreip: Vec<String>,
}

/// A value never shown: its debug form is hidden, so no log can print it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[hidden]")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingValue {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Status,
    Accounts,
    AccountPut { actor: Actor, create: bool, account: AccountInput },
    AccountDelete { actor: Actor, name: String, delete_keys: bool },
    KeyAdd { actor: Actor, name: String, key: String },
    KeyDelete { actor: Actor, name: String, fingerprint: String },
    HashPasswords { actor: Actor },
    SessionEnd { actor: Actor, pid: u32 },
    SettingsGet,
    SettingsPut { actor: Actor, values: Vec<SettingValue> },
    Bans,
    Ban { actor: Actor, address: String },
    Unban { actor: Actor, jail: String, address: String },
    /// Held sign-ins waiting for an admin, and the accounts locked down.
    Signins,
    /// Approves a held sign-in, which adds its place to the account's
    /// profile, or rejects it, banning its address when `ban` is true.
    HoldDecide { actor: Actor, id: i64, approve: bool, ban: bool },
    /// Ends an account's lockdown now.
    LockdownLift { actor: Actor, account: String },
    Fail2banPut { actor: Actor, rules: BanRules },
    Log { query: String, before: Option<u64> },
    AuditLog { query: String, before: Option<u64> },
    Audit { actor: Actor, action: String, target: String, outcome: String },
    Groups,
    GroupPut { actor: Actor, create: bool, group: GroupInput },
    GroupDelete { actor: Actor, name: String },
    /// Totals from `from` up to `to`, in buckets of `size` seconds.
    HistorySeries { from: u64, to: u64, size: u64 },
    /// Events newest first, of one account or all when `account` is empty;
    /// `after` gives only those newer than an id, `before` the page older than one.
    Events { account: String, after: Option<i64>, before: Option<i64> },
    /// Bans newest first, a page at a time from `before`.
    BanHistory { before: Option<i64> },
    /// Every account active since `since`, most recently active first.
    People { since: u64 },
    /// Every name tried in failed sign-ins since `since`, most tried first.
    NamesTried { since: u64 },
    /// Failed and successful logins since `since`, by the country of their
    /// address, most failed first.
    LoginsByCountry { since: u64 },
    /// Saves a MaxMind key once a GeoLite2 download with it succeeds.
    MaxmindPut { actor: Actor, account_id: String, license_key: Secret },
    /// Removes the saved MaxMind key and the GeoLite2 copy it kept current.
    MaxmindDelete { actor: Actor },
    /// A sign-in link for an account's file browser: its token, which the
    /// helper keeps only hashed, and when it stops working.
    FilesInvite { actor: Actor, account: String },
    /// Removes an account's web password and second factor, and ends its
    /// file browser sessions.
    FilesReset { actor: Actor, account: String },
    /// Every account's file browser sign-in state.
    FilesLogins,
}

/// What the file browser may ask the root helper, on its own socket.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "request", rename_all = "snake_case", deny_unknown_fields)]
pub enum FilesRequest {
    /// The account a sign-in link is for, while it still works.
    Invite { token: Secret },
    /// Sets an account's web password and second factor with a sign-in
    /// link, which is used up.
    Enroll { token: Secret, password: Secret, totp_secret: Secret, code: String },
    /// Checks a sign-in from `address`; a session comes back.
    SignIn { account: String, password: Secret, code: String, address: String },
    SignOut { session: Secret },
    /// Whether a session may go on, asked on every request it makes: it
    /// lives, its account may still use the file browser, `address` is one
    /// the account may connect from, and with `acting` the account still
    /// manages that account. The session's account comes back.
    Check {
        session: Secret,
        address: String,
        #[serde(default)]
        acting: Option<String>,
    },
    /// A certificate for a key the file browser made, for the account of a
    /// live session, or with `acting` for an account it manages.
    Certificate {
        session: Secret,
        public_key: String,
        #[serde(default)]
        acting: Option<String>,
    },
    /// The accounts a live session's account manages, by name.
    Managed { session: Secret },
    /// Makes a share link to a file of the session's account, or of one
    /// it manages as `acting`, that lasts `days` days and asks for
    /// `password` when it is not empty. The token comes back this once.
    ShareCreate {
        session: Secret,
        #[serde(default)]
        acting: Option<String>,
        path: String,
        days: u32,
        password: Secret,
    },
    /// The share links the session's account made, newest first.
    ShareList { session: Secret },
    /// Ends a share link the session's account made.
    ShareRevoke { session: Secret, id: String },
    /// What a share link leads to, without using it.
    ShareInfo { token: Secret },
    /// Claims a share link for one download from `address`, with its
    /// password when it has one, and signs `public_key` for its account.
    /// ShareDone spends the link once the download is complete, or with
    /// `done` false gives it back.
    ShareClaim { token: Secret, password: Secret, address: String, public_key: String },
    ShareDone { token: Secret, done: bool },
    /// Gives back every claimed link, as the file browser starts: no
    /// download survives its restart.
    ShareReset,
    /// What the server allows of share links to the files of the session's
    /// account, or with `acting` of an account it manages: the strictest of
    /// Settings and both accounts' limits.
    SharePolicy {
        session: Secret,
        #[serde(default)]
        acting: Option<String>,
    },
    /// The history of `path` in the files of the session's account, or with
    /// `acting` of an account it manages: its latest upload, rename to it or
    /// making, and every event that names it, a page newest first from
    /// `before`.
    FileHistory {
        session: Secret,
        #[serde(default)]
        acting: Option<String>,
        path: String,
        #[serde(default)]
        before: Option<i64>,
    },
}

/// What the server allows of share links.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SharePolicy {
    pub allowed: bool,
    pub default_days: u32,
    pub max_days: u32,
    pub password_required: bool,
}

/// A share link just made: its token, shown once, and when it ends.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareMade {
    pub token: Secret,
    pub expires: u64,
}

/// A share link as its maker sees it; never its token.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareView {
    pub id: String,
    pub account: String,
    pub path: String,
    pub created: u64,
    pub expires: u64,
    /// When it was spent, if it was.
    pub used: Option<u64>,
    pub password: bool,
}

/// Where a share link leads, for its page and its download.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareTarget {
    pub account: String,
    pub path: String,
    pub expires: u64,
    pub password: bool,
    /// For a claim, the certificate to read the file with.
    #[serde(default)]
    pub certificate: String,
}

/// A sign-in link just made.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FilesInvite {
    pub token: String,
    pub expires: u64,
}

/// A file browser session the helper opened.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SignedIn {
    pub session: String,
    pub account: String,
}

/// An account's file browser sign-in state, as the admin UI shows it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FilesLogin {
    pub account: String,
    /// True once a web password and second factor are set.
    pub enrolled: bool,
    /// When the account's open sign-in link stops working, if it has one.
    pub invite_expires: Option<u64>,
    pub last_sign_in: Option<u64>,
}

impl Request {
    /// The actor of a request that changes something.
    pub fn actor(&self) -> Option<&Actor> {
        match self {
            Request::AccountPut { actor, .. }
            | Request::AccountDelete { actor, .. }
            | Request::KeyAdd { actor, .. }
            | Request::KeyDelete { actor, .. }
            | Request::HashPasswords { actor }
            | Request::SessionEnd { actor, .. }
            | Request::SettingsPut { actor, .. }
            | Request::Ban { actor, .. }
            | Request::Unban { actor, .. }
            | Request::Fail2banPut { actor, .. }
            | Request::HoldDecide { actor, .. }
            | Request::LockdownLift { actor, .. }
            | Request::Audit { actor, .. }
            | Request::GroupPut { actor, .. }
            | Request::GroupDelete { actor, .. }
            | Request::MaxmindPut { actor, .. }
            | Request::MaxmindDelete { actor }
            | Request::FilesInvite { actor, .. }
            | Request::FilesReset { actor, .. } => Some(actor),
            Request::Status
            | Request::Accounts
            | Request::SettingsGet
            | Request::Bans
            | Request::Log { .. }
            | Request::AuditLog { .. }
            | Request::Groups
            | Request::HistorySeries { .. }
            | Request::Events { .. }
            | Request::BanHistory { .. }
            | Request::People { .. }
            | Request::NamesTried { .. }
            | Request::LoginsByCountry { .. }
            | Request::Signins
            | Request::FilesLogins => None,
        }
    }
}

/// The helper's answer. `messages` carries what `entrypoint apply` said;
/// `data` holds the result of a read, as the type its request names.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub ok: bool,
    pub error: String,
    pub messages: Vec<String>,
    pub data: serde_json::Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub running: bool,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HostKey {
    pub kind: String,
    pub bits: String,
    pub fingerprint: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionInfo {
    pub pid: u32,
    pub account: String,
    pub address: String,
    pub since: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub started: u64,
    pub services: Vec<Service>,
    pub sftp_ports: Vec<u16>,
    pub host_keys: Vec<HostKey>,
    pub sessions: Vec<SessionInfo>,
    pub accounts: usize,
    pub disabled: usize,
    pub transfer_logging: bool,
    pub banned: usize,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct KeyView {
    pub fingerprint: String,
    pub kind: String,
    pub bits: u32,
    pub comment: String,
    pub file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountView {
    pub name: String,
    pub source: String,
    pub editable: bool,
    pub uid: u32,
    pub gid: u32,
    pub dirs: Vec<String>,
    /// The options in effect, after the account's groups.
    pub options: Options,
    /// The options on the account's own line in users.conf, which the web UI
    /// edits; None for an account defined elsewhere.
    pub own: Option<Options>,
    /// The gid on the account's own line; None when it takes its group's or
    /// the default.
    pub own_gid: Option<u32>,
    /// none, hashed or plain for an account in users.conf; none or set for others.
    pub password: String,
    pub rsync_from_env: bool,
    pub rsync_ready: bool,
    pub expired: bool,
    pub keys: Vec<KeyView>,
    pub sessions: Vec<SessionInfo>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Accounts {
    pub accounts: Vec<AccountView>,
    pub plain_passwords: usize,
}

/// A group and the accounts that name it, in the order they are configured.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GroupView {
    pub group: Group,
    pub members: Vec<String>,
    /// Members defined outside users.conf, whose membership the web UI
    /// cannot change.
    pub fixed_members: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Groups {
    pub groups: Vec<GroupView>,
}

/// Totals of one stretch of time in a chart, starting at `start`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bucket {
    pub start: u64,
    pub logins: u64,
    pub failed: u64,
    pub uploads: u64,
    pub downloads: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub bans: u64,
}

/// One ban from the permanent ban store, which keeps what fail2ban's own
/// database drops after dbpurgeage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BanRecord {
    pub id: i64,
    pub jail: String,
    pub address: String,
    pub time: u64,
    /// Seconds; -1 means forever.
    pub length: i64,
    /// Bans of this address in this jail, this one included.
    pub count: i64,
    /// The failed logins behind it; 0 for a ban an admin made, None when
    /// fail2ban kept no record of them.
    pub failures: Option<i64>,
    /// Account names tried in those failed logins.
    pub names: Vec<String>,
}

/// A page of bans newest first; `older` is the id to page back from when
/// more remain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BanPage {
    pub bans: Vec<BanRecord>,
    pub older: Option<i64>,
}

/// Buckets of `size` seconds covering a range, oldest first, none skipped.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Series {
    pub size: u64,
    pub buckets: Vec<Bucket>,
}

/// One stored event, as the Activity pages show it.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventView {
    pub id: i64,
    pub time: u64,
    pub door: String,
    pub kind: String,
    pub account: String,
    pub address: String,
    pub path: String,
    pub other: String,
    pub bytes: u64,
    /// Who acted in the file browser, when it was there; empty over SSH.
    #[serde(default)]
    pub actor: String,
}

/// A name tried in failed sign-ins, how often, and whether it is an
/// account of this server.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct NameCount {
    pub name: String,
    pub count: u64,
    pub known: bool,
}

/// An account that was active in a period: when it last did something, its
/// latest actions, and its totals over the period.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Person {
    pub account: String,
    pub last: u64,
    /// Its three latest actions, newest first; its Activity page has all.
    pub recent: Vec<EventView>,
    pub logins: u64,
    pub failed: u64,
    pub uploads: u64,
    pub downloads: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// A page of events newest first; `older` is the id to page back from when
/// more remain.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EventPage {
    pub events: Vec<EventView>,
    pub older: Option<i64>,
}

/// A file's history, for the file browser's details pane.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileHistory {
    /// The latest event that put something at the path: an upload, a
    /// rename to it, or making a folder there.
    pub added: Option<EventView>,
    /// Every event that names the path, newest first, a page at a time.
    pub events: Vec<EventView>,
    pub older: Option<i64>,
}

/// A group to save, and the accounts in users.conf that should name it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInput {
    pub group: Group,
    pub members: Vec<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SettingView {
    pub key: String,
    pub value: String,
    /// environment, settings.conf or default.
    pub source: String,
    pub locked: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Settings {
    pub settings: Vec<SettingView>,
    pub fixed: Vec<SettingView>,
    pub locations: Locations,
}

/// The country data: which database the country rules read, and the
/// MaxMind key in force, without its license key.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Locations {
    /// dbip or maxmind.
    pub database: String,
    /// When that database was built, in seconds since 1970; 0 when unknown.
    pub built: u64,
    pub account_id: String,
    /// environment, web UI, or empty without a key.
    pub key_source: String,
    /// True while a key is set but no GeoLite2 copy is downloaded yet.
    pub waiting: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BanView {
    pub address: String,
    /// When the ban began, in seconds since 1970; None when fail2ban's
    /// database holds no record of it.
    pub since: Option<u64>,
    /// The ban's length in seconds; -1 means forever.
    pub length: i64,
    /// How many times fail2ban has banned this address in this jail.
    pub count: u32,
    /// The failed logins behind the ban; 0 for a ban an admin made.
    pub failures: Option<u32>,
}

/// A sign-in held for an admin's approval.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HoldView {
    pub id: i64,
    pub time: u64,
    pub account: String,
    pub address: String,
    /// A country code, or local network or unknown.
    pub place: String,
    pub reason: String,
}

/// An account locked to the networks of its approved sign-ins by a password
/// spray.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LockdownView {
    pub account: String,
    pub since: u64,
    pub last_failure: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Signins {
    pub holds: Vec<HoldView>,
    pub lockdowns: Vec<LockdownView>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct JailView {
    pub name: String,
    /// Addresses with failed logins that are not banned yet.
    pub failed: u64,
    /// Failed logins since fail2ban started.
    pub total_failed: u64,
    /// Bans since fail2ban started.
    pub total_banned: u64,
    pub banned: Vec<BanView>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Bans {
    pub enabled: bool,
    pub jails: Vec<JailView>,
    pub saved: BanRules,
    pub effective: BanRules,
    /// Why ban times and counts are missing, when they are.
    pub records_error: Option<String>,
    pub countries: CountryRules,
}

/// The country rules: their two settings, and what the entrypoint made of
/// them when it last applied the configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CountryRules {
    /// SFTP_COUNTRY_RULE: off, block or allow.
    pub rule: SettingView,
    /// SFTP_COUNTRIES: two-letter codes separated by spaces.
    pub countries: SettingView,
    /// What is in force: off, blocking or allowing; refused when the
    /// firewall would not load the rules; unknown when the entrypoint's
    /// record cannot be read.
    pub state: String,
    /// What the firewall said when it refused them, or why the record
    /// cannot be read.
    pub refused: String,
    /// The codes in force, as the entrypoint loaded them.
    pub applied: Vec<String>,
    /// The TCP ports they guard.
    pub ports: Vec<u16>,
    /// Never-ban entries they cannot exempt, each with the reason.
    pub skipped: Vec<String>,
}

/// Failed and successful logins from one country in a period.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CountryCount {
    /// ISO 3166 code in capitals; None for addresses in no country, such as
    /// private ones.
    pub code: Option<String>,
    pub failed: u64,
    pub ok: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct LogPage {
    pub lines: Vec<String>,
    pub older: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub time: u64,
    pub admin: String,
    pub address: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditPage {
    pub entries: Vec<AuditEntry>,
    pub older: Option<u64>,
}
