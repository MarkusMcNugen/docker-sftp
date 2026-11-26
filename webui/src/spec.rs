//! The users.conf account line,
//! `name:password[:e][:uid[:gid[:dir1,dir2,...[:options]]]]`, with the rules
//! the entrypoint applies to it.

use serde::{Deserialize, Serialize};

use crate::net::Network;
use crate::timefmt;

/// The uid and gid of the image's web UI account, which no account may use.
pub const WEBUI_ID: u32 = 980;
/// The uid and gid of the image's file browser account, which no account
/// may use.
pub const FILES_ID: u32 = 981;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Perm {
    List,
    Download,
    Upload,
    Delete,
    Rename,
    Mkdir,
    Attributes,
    Links,
}

impl Perm {
    pub const ALL: [Perm; 8] = [
        Perm::List,
        Perm::Download,
        Perm::Upload,
        Perm::Delete,
        Perm::Rename,
        Perm::Mkdir,
        Perm::Attributes,
        Perm::Links,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Perm::List => "list",
            Perm::Download => "download",
            Perm::Upload => "upload",
            Perm::Delete => "delete",
            Perm::Rename => "rename",
            Perm::Mkdir => "mkdir",
            Perm::Attributes => "attributes",
            Perm::Links => "links",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Perm::List => "List directories",
            Perm::Download => "Download",
            Perm::Upload => "Upload and overwrite",
            Perm::Delete => "Delete",
            Perm::Rename => "Rename and move",
            Perm::Mkdir => "Make directories",
            Perm::Attributes => "Change times and modes",
            Perm::Links => "Make links",
        }
    }

    pub fn parse(text: &str) -> Option<Perm> {
        Perm::ALL.into_iter().find(|p| p.name() == text)
    }
}

pub const READONLY: [Perm; 2] = [Perm::List, Perm::Download];
pub const UPLOADONLY: [Perm; 5] = [Perm::List, Perm::Upload, Perm::Rename, Perm::Mkdir, Perm::Attributes];

/// The permissions in canonical order, each once.
pub fn canonical_perms(perms: &[Perm]) -> Vec<Perm> {
    Perm::ALL.into_iter().filter(|p| perms.contains(p)).collect()
}

/// Full, readonly, uploadonly or custom.
pub fn preset_of(perms: &[Perm]) -> &'static str {
    let perms = canonical_perms(perms);
    if perms == Perm::ALL {
        "full"
    } else if perms == READONLY {
        "readonly"
    } else if perms == UPLOADONLY {
        "uploadonly"
    } else {
        "custom"
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// Every permission unless the line names some.
    pub perms: Vec<Perm>,
    /// True when the line names its permissions; an account that does not
    /// takes them from its groups.
    pub perms_set: bool,
    pub rsync: bool,
    /// The account may sign in to the file browser.
    pub web: bool,
    pub disabled: bool,
    pub expires: Option<String>,
    pub from: Vec<String>,
    pub umask: Option<String>,
    /// The account's groups, in the order its line names them.
    pub groups: Vec<String>,
    /// Accounts, and groups written @name, whose files the account may open.
    pub manage: Vec<String>,
    /// No share links: none to the account's files and none made by it.
    pub noshare: bool,
    /// The longest a share link may last, in days.
    pub share_days: Option<u32>,
    /// Every share link needs a password.
    pub share_password: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            perms: Perm::ALL.to_vec(),
            perms_set: false,
            rsync: false,
            web: false,
            disabled: false,
            expires: None,
            from: Vec::new(),
            umask: None,
            groups: Vec::new(),
            manage: Vec::new(),
            noshare: false,
            share_days: None,
            share_password: false,
        }
    }
}

/// A number of days as users.conf, groups.conf and the settings write it:
/// one to nine digits, the first not 0.
pub fn day_count(text: &str) -> Option<u32> {
    if text.is_empty() || text.len() > 9 || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text.bytes().fold(0, |n, b| n * 10 + u32::from(b - b'0')))
}

impl Options {
    /// Checks the combination and puts every value in canonical form.
    pub fn normalize(&mut self) -> Result<(), String> {
        self.perms = canonical_perms(&self.perms);
        if self.perms.is_empty() {
            return Err("give the account at least one permission".into());
        }
        if !self.perms.contains(&Perm::Upload) {
            for p in [Perm::Delete, Perm::Rename, Perm::Mkdir, Perm::Attributes, Perm::Links] {
                if self.perms.contains(&p) {
                    return Err(format!(
                        "without upload the account is read-only, so it cannot have {}",
                        p.name()
                    ));
                }
            }
        }
        if self.rsync && self.perms != Perm::ALL && self.perms != READONLY {
            return Err("rsync works only with full or read-only permissions".into());
        }
        if let Some(date) = &self.expires
            && !timefmt::valid_date(date)
        {
            return Err(format!("{date} is not a date such as 2027-01-31"));
        }
        let mut nets = Vec::new();
        for item in &self.from {
            let net = Network::parse(item)?.to_string();
            if !nets.contains(&net) {
                nets.push(net);
            }
        }
        self.from = nets;
        if let Some(umask) = &self.umask
            && !valid_umask(umask)
        {
            return Err(format!("{umask} is not an octal umask such as 022"));
        }
        for group in &self.groups {
            validate_name(group).map_err(|e| format!("group: {e}"))?;
        }
        for target in &self.manage {
            let name = match target.strip_prefix('@') {
                Some(group) => group,
                None => target.as_str(),
            };
            validate_name(name).map_err(|e| format!("manage={target}: {e}"))?;
        }
        if let Some(days) = self.share_days
            && !(1..=999_999_999).contains(&days)
        {
            return Err(format!("sharedays={days} is not a number of days from 1 to 999999999"));
        }
        first_of_each(&mut self.groups);
        first_of_each(&mut self.manage);
        Ok(())
    }
}

/// Keeps the first of each repeated item, in order.
fn first_of_each(items: &mut Vec<String>) {
    let mut seen: Vec<String> = Vec::new();
    items.retain(|item| {
        let new = !seen.contains(item);
        if new {
            seen.push(item.clone());
        }
        new
    });
}

/// Three octal digits, optionally after a leading 0.
pub fn valid_umask(text: &str) -> bool {
    let digits = if text.len() == 4 && text.starts_with('0') { &text[1..] } else { text };
    digits.len() == 3 && digits.bytes().all(|b| (b'0'..=b'7').contains(&b))
}

/// Parses the options at the end of an account line.
pub fn parse_options(text: &str) -> Result<Options, String> {
    let mut opts = Options::default();
    let mut preset: Option<&str> = None;
    let mut seen_rsync = false;
    for opt in text.split(',') {
        if opt.is_empty() {
            continue;
        }
        if opt == "rsync" {
            if seen_rsync {
                return Err("option rsync is given twice".into());
            }
            seen_rsync = true;
            opts.rsync = true;
        } else if opt == "web" {
            if opts.web {
                return Err("option web is given twice".into());
            }
            opts.web = true;
        } else if opt == "full" || opt == "readonly" || opt == "uploadonly" || opt.starts_with("perms=") {
            if preset.is_some() {
                return Err("give only one of full, readonly, uploadonly and perms=".into());
            }
            preset = Some(opt);
        } else if opt == "disabled" {
            if opts.disabled {
                return Err("option disabled is given twice".into());
            }
            opts.disabled = true;
        } else if let Some(date) = opt.strip_prefix("expires=") {
            if opts.expires.is_some() {
                return Err("option expires= is given twice".into());
            }
            opts.expires = Some(date.to_string());
        } else if let Some(net) = opt.strip_prefix("from=") {
            if net.is_empty() {
                return Err("from= needs an address or network".into());
            }
            opts.from.push(net.to_string());
        } else if let Some(umask) = opt.strip_prefix("umask=") {
            if opts.umask.is_some() {
                return Err("option umask= is given twice".into());
            }
            opts.umask = Some(umask.to_string());
        } else if let Some(group) = opt.strip_prefix("group=") {
            if opts.groups.iter().any(|g| g == group) {
                return Err(format!("group {group} is given twice"));
            }
            opts.groups.push(group.to_string());
        } else if let Some(target) = opt.strip_prefix("manage=") {
            if opts.manage.iter().any(|m| m == target) {
                return Err(format!("manage={target} is given twice"));
            }
            opts.manage.push(target.to_string());
        } else if opt == "noshare" {
            if opts.noshare {
                return Err("option noshare is given twice".into());
            }
            opts.noshare = true;
        } else if let Some(days) = opt.strip_prefix("sharedays=") {
            if opts.share_days.is_some() {
                return Err("option sharedays= is given twice".into());
            }
            match day_count(days) {
                Some(n) => opts.share_days = Some(n),
                None => return Err(format!("sharedays={days} is not a number of days from 1 to 999999999")),
            }
        } else if opt == "sharepassword" {
            if opts.share_password {
                return Err("option sharepassword is given twice".into());
            }
            opts.share_password = true;
        } else {
            return Err(format!("unknown option \"{opt}\""));
        }
    }
    opts.perms_set = preset.is_some();
    match preset {
        None | Some("full") => {}
        Some("readonly") => opts.perms = READONLY.to_vec(),
        Some("uploadonly") => opts.perms = UPLOADONLY.to_vec(),
        Some(other) => {
            let list = other.trim_start_matches("perms=");
            let mut perms = Vec::new();
            for name in list.split('+') {
                let Some(p) = Perm::parse(name) else {
                    return Err(format!("unknown permission \"{name}\""));
                };
                if perms.contains(&p) {
                    return Err(format!("permission {name} is given twice"));
                }
                perms.push(p);
            }
            opts.perms = perms;
        }
    }
    opts.normalize()?;
    Ok(opts)
}

/// An account line's options in the canonical form the entrypoint also
/// writes. Permissions appear only when the line sets them; full access is
/// written out only when a group could otherwise give less.
pub fn format_options(opts: &Options) -> String {
    write_options(opts, !opts.groups.is_empty())
}

fn write_options(opts: &Options, write_full: bool) -> String {
    let mut out: Vec<String> = Vec::new();
    if opts.rsync {
        out.push("rsync".into());
    }
    if opts.web {
        out.push("web".into());
    }
    if opts.perms_set {
        match preset_of(&opts.perms) {
            "full" if !write_full => {}
            "full" => out.push("full".into()),
            "readonly" => out.push("readonly".into()),
            "uploadonly" => out.push("uploadonly".into()),
            _ => {
                let names: Vec<&str> = canonical_perms(&opts.perms).iter().map(|p| p.name()).collect();
                out.push(format!("perms={}", names.join("+")));
            }
        }
    }
    if opts.disabled {
        out.push("disabled".into());
    }
    if let Some(date) = &opts.expires {
        out.push(format!("expires={date}"));
    }
    for net in &opts.from {
        out.push(format!("from={net}"));
    }
    if let Some(umask) = &opts.umask {
        out.push(format!("umask={umask}"));
    }
    if opts.noshare {
        out.push("noshare".into());
    }
    if let Some(days) = opts.share_days {
        out.push(format!("sharedays={days}"));
    }
    if opts.share_password {
        out.push("sharepassword".into());
    }
    for group in &opts.groups {
        out.push(format!("group={group}"));
    }
    for target in &opts.manage {
        out.push(format!("manage={target}"));
    }
    out.join(",")
}

/// A group in groups.conf: a name, an optional gid for its members' files,
/// and the options it gives them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub name: String,
    pub gid: Option<u32>,
    pub options: Options,
}

/// Parses a groups.conf line, name[:gid[:options]], the way the entrypoint does.
pub fn parse_group_line(text: &str) -> Result<Group, String> {
    let (name, rest) = match text.split_once(':') {
        Some((n, r)) => (n, r),
        None => (text, ""),
    };
    validate_name(name)?;
    let (gid, options) = match rest.split_once(':') {
        Some((g, o)) => (g, o),
        None => (rest, ""),
    };
    let gid = parse_id(gid, "gid").map_err(|e| format!("group {name}: {e}"))?;
    let options = parse_options(options).map_err(|e| format!("group {name}: {e}"))?;
    if !options.groups.is_empty() {
        return Err(format!("group {name}: a group cannot belong to a group"));
    }
    Ok(Group { name: name.to_string(), gid, options })
}

/// Writes a groups.conf line, leaving out empty trailing fields. A group that
/// grants full access says so, since without it the group grants none.
pub fn format_group_line(group: &Group) -> String {
    let options = write_options(&group.options, true);
    match (group.gid, options.is_empty()) {
        (None, true) => group.name.clone(),
        (gid, true) => format!("{}:{}", group.name, id_field(gid)),
        (gid, false) => format!("{}:{}:{options}", group.name, id_field(gid)),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Line {
    pub name: String,
    pub password: String,
    pub encrypted: bool,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub dirs: Vec<String>,
    pub options: Options,
}

pub fn validate_name(name: &str) -> Result<(), String> {
    let b = name.as_bytes();
    let ok_char = |c: &u8| c.is_ascii_alphanumeric() || *c == b'.' || *c == b'_' || *c == b'-';
    if b.is_empty() || b.len() > 32 || !b.iter().all(ok_char) || b[0] == b'-' {
        return Err(format!(
            "\"{name}\" is not a valid name: use letters, digits, '.', '_' and '-', at most 32, not starting with '-'"
        ));
    }
    Ok(())
}

pub fn validate_dir(dir: &str) -> Result<(), String> {
    if dir.is_empty() {
        return Err("a directory name is empty".into());
    }
    if dir.starts_with('/') {
        return Err(format!("directory \"{dir}\" must be relative to the home directory"));
    }
    if dir.chars().any(|c| c.is_control() || c == ':' || c == ',') {
        return Err(format!("directory \"{dir}\" may not contain ':', ',' or control characters"));
    }
    if dir != dir.trim() {
        return Err(format!("directory \"{dir}\" may not begin or end with a space"));
    }
    for comp in dir.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return Err(format!("directory \"{dir}\" may not contain empty, . or .. components"));
        }
    }
    Ok(())
}

fn parse_id(text: &str, what: &str) -> Result<Option<u32>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    if text.len() > 10 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{what} \"{text}\" must be a number from 1 to 4294967294"));
    }
    let value: u64 = match text.parse() {
        Ok(v) => v,
        Err(e) => return Err(format!("{what} \"{text}\": {e}")),
    };
    check_id(value, what).map(Some)
}

pub fn check_id(value: u64, what: &str) -> Result<u32, String> {
    if value == 0 || value >= 4_294_967_295 {
        return Err(format!("{what} {value} must be a number from 1 to 4294967294 (0 is root)"));
    }
    if value == u64::from(WEBUI_ID) {
        return Err(format!("{what} {value} belongs to the image's web UI account"));
    }
    if value == u64::from(FILES_ID) {
        return Err(format!("{what} {value} belongs to the image's file browser account"));
    }
    match u32::try_from(value) {
        Ok(v) => Ok(v),
        Err(e) => Err(format!("{what} {value}: {e}")),
    }
}

fn id_field(id: Option<u32>) -> String {
    match id {
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

/// Parses an account line the way the entrypoint does.
pub fn parse_line(spec: &str) -> Result<Line, String> {
    let name = match spec.split_once(':') {
        Some((n, _)) => n,
        None => {
            validate_name(spec)?;
            return Err(format!("{spec}: expected name:password[:e][:uid[:gid[:dirs[:options]]]]"));
        }
    };
    validate_name(name)?;
    let fields: Vec<&str> = spec.split(':').collect();
    let encrypted = fields.get(2) == Some(&"e");
    let first = if encrypted { 3 } else { 2 };
    let parts: Vec<&str> = spec.splitn(first + 4, ':').collect();
    let field = |i: usize| -> &str {
        match parts.get(i) {
            Some(f) => f,
            None => "",
        }
    };
    let password = field(1).to_string();
    if password.len() > 255 {
        return Err(format!("{name}: password longer than 255 characters"));
    }
    let uid = parse_id(field(first), "uid").map_err(|e| format!("{name}: {e}"))?;
    let gid = parse_id(field(first + 1), "gid").map_err(|e| format!("{name}: {e}"))?;
    let mut dirs = Vec::new();
    for dir in field(first + 2).split(',') {
        if dir.is_empty() {
            continue;
        }
        validate_dir(dir).map_err(|e| format!("{name}: {e}"))?;
        dirs.push(dir.to_string());
    }
    let options = parse_options(field(first + 3)).map_err(|e| format!("{name}: {e}"))?;
    if options.manage.iter().any(|m| m == name) {
        return Err(format!("{name}: manage= names the account itself"));
    }
    Ok(Line {
        name: name.to_string(),
        password,
        encrypted: encrypted && !field(1).is_empty(),
        uid,
        gid,
        dirs,
        options,
    })
}

/// Writes an account line, leaving out empty trailing fields.
pub fn format_line(line: &Line) -> String {
    let mut fields: Vec<String> = vec![line.name.clone(), line.password.clone()];
    if line.encrypted && !line.password.is_empty() {
        fields.push("e".into());
    }
    let fixed = fields.len();
    fields.push(id_field(line.uid));
    fields.push(id_field(line.gid));
    fields.push(line.dirs.join(","));
    fields.push(format_options(&line.options));
    while fields.len() > fixed && fields.last().is_some_and(String::is_empty) {
        fields.pop();
    }
    fields.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_lines() {
        for spec in [
            "alice:pw",
            "bob:",
            "carol:$y$j9T$abc:e:1003",
            "dave:pw:1004:100:up,down/in:rsync,readonly",
            "eve:pw::::perms=list+upload+mkdir,disabled,expires=2027-01-31,from=10.0.0.0/8,from=2001:db8::/32,umask=002",
        ] {
            let line = parse_line(spec).expect(spec);
            assert_eq!(format_line(&line), spec, "{spec}");
        }
    }

    #[test]
    fn mirrors_the_entrypoint_rules() {
        assert!(parse_line("root").is_err());
        assert!(parse_line("-x:pw").is_err());
        assert!(parse_line("x:pw:0").is_err());
        assert!(parse_line("x:pw:980").is_err());
        assert!(parse_line("x:pw:981").is_err());
        assert!(parse_line("x:pw:1000:981").is_err());
        assert!(parse_line("x:pw:::../etc").is_err());
        assert!(parse_line("x:pw:::/etc").is_err());
        assert!(parse_line("x:pw:::up:shell").is_err());
        assert!(parse_line("x:pw:::up:rsync,uploadonly").is_err());
        assert!(parse_line("x:pw:::up:perms=list+delete").is_err());
        assert!(parse_line("x:pw:::up:from=10.0.0.1/8").is_err());
        assert!(parse_line("x:pw:::up:expires=2027-02-30").is_err());
        assert!(parse_line("x:pw:::up:umask=999").is_err());
        let line = parse_line("x:pw:::up:from=10.1.0.0/16,readonly").expect("valid");
        assert_eq!(line.options.perms, READONLY.to_vec());
        assert_eq!(format_options(&line.options), "readonly,from=10.1.0.0/16");
    }

    #[test]
    fn groups_and_manage_round_trip_on_account_lines() {
        for spec in [
            "ann:pw:::up:group=staff,group=partners",
            "ben:pw:::up:full,group=auditors",
            "cat:pw:::up:readonly,group=staff,manage=ann,manage=@partners",
            "dot:pw:::up:rsync,web,readonly",
        ] {
            let line = parse_line(spec).expect(spec);
            assert_eq!(format_line(&line), spec, "{spec}");
        }
        assert!(parse_line("dot:pw:::up:web").expect("valid").options.web);
        assert!(!parse_line("dot:pw:::up").expect("valid").options.web, "web access is off unless given");
        assert_eq!(format_line(&parse_line("dot:pw:::up:readonly,web").expect("valid")), "dot:pw:::up:web,readonly");
        assert!(parse_line("dot:pw:::up:web,web").is_err());
        assert!(!parse_line("ann:pw:::up:group=staff").expect("valid").options.perms_set);
        assert_eq!(format_line(&parse_line("ann:pw:::up:full").expect("valid")), "ann:pw:::up");
        assert!(parse_line("ann:pw:::up:group=staff,group=staff").is_err());
        assert!(parse_line("ann:pw:::up:manage=ann").is_err());
        assert!(parse_line("ann:pw:::up:manage=@-x").is_err());
        assert!(parse_line("ann:pw:::up:full,readonly").is_err());
    }

    #[test]
    fn share_limits_round_trip_and_refuse_bad_values() {
        for spec in ["eve:pw:::up:noshare", "fay:pw:::up:readonly,sharedays=3,sharepassword,group=staff"] {
            let line = parse_line(spec).expect(spec);
            assert_eq!(format_line(&line), spec, "{spec}");
        }
        let line = parse_line("gus:pw:::up:sharepassword,sharedays=14,noshare").expect("valid");
        assert!(line.options.noshare && line.options.share_password);
        assert_eq!(line.options.share_days, Some(14));
        assert_eq!(format_line(&line), "gus:pw:::up:noshare,sharedays=14,sharepassword");
        for bad in [
            "noshare,noshare",
            "sharepassword,sharepassword",
            "sharedays=1,sharedays=2",
            "sharedays=",
            "sharedays=0",
            "sharedays=07",
            "sharedays=1000000000",
            "sharedays=x",
            "sharedays=-1",
        ] {
            assert!(parse_line(&format!("x:pw:::up:{bad}")).is_err(), "{bad}");
        }
        assert_eq!(parse_line("x:pw:::up:sharedays=999999999").expect("valid").options.share_days, Some(999_999_999));
        let group = parse_group_line("partners::noshare,sharedays=2").expect("valid");
        assert!(group.options.noshare);
        assert_eq!(format_group_line(&group), "partners::noshare,sharedays=2");
        assert_eq!(day_count("30"), Some(30));
        assert_eq!(day_count("0"), None);
    }

    #[test]
    fn group_lines_round_trip() {
        for text in ["staff", "staff:2000", "partners:2001:uploadonly,from=203.0.113.0/24,manage=@staff", "admins::full,rsync", "web:3000:web"] {
            let group = parse_group_line(text).expect(text);
            let want = if text == "admins::full,rsync" { "admins::rsync,full" } else { text };
            assert_eq!(format_group_line(&group), want, "{text}");
        }
        let group = parse_group_line("auditors::readonly,expires=2027-03-31").expect("valid");
        assert_eq!(group.gid, None);
        assert!(group.options.perms_set);
        assert!(!parse_group_line("open:3000").expect("valid").options.perms_set);
        assert!(parse_group_line("staff::group=other").is_err());
        assert!(parse_group_line("staff:980").is_err());
        assert!(parse_group_line("staff:981").is_err());
        assert!(parse_group_line("bad name:1").is_err());
    }
}
