//! Groups in /config/sshd/groups.conf, and the group= options that make an
//! account in users.conf a member. A change writes both files and applies
//! them; when the entrypoint refuses, both are put back.

use std::path::Path;

use anyhow::Result;
use sftp_webui::proto::{GroupInput, GroupView, Groups};
use sftp_webui::spec::{self, Group, Line};

use crate::accounts;
use crate::system::{self, Backup, Failure, Outcome, TextFile};

/// The groups.conf line that defines the group, with its index.
fn find(conf: &TextFile, name: &str) -> Result<Option<(usize, Group)>, String> {
    for (i, line) in conf.lines.iter().enumerate() {
        if accounts::is_spec(line) && accounts::name_of(line) == name {
            return spec::parse_group_line(TextFile::content(line).trim_start()).map(|g| Some((i, g)));
        }
    }
    Ok(None)
}

pub fn list() -> Result<Groups> {
    let conf = TextFile::parse(&system::read_text(Path::new(system::GROUPS_CONF))?);
    let state = system::read_state()?;
    let mut memberships: Vec<(String, String, bool)> = Vec::new();
    for account in &state {
        let options = spec::parse_options(&account.options)
            .map_err(|e| anyhow::anyhow!("account {}: {e}", account.name))?;
        for group in options.groups {
            memberships.push((group, account.name.clone(), account.source == "users.conf"));
        }
    }
    let mut out = Groups::default();
    for line in &conf.lines {
        if !accounts::is_spec(line) {
            continue;
        }
        let group = spec::parse_group_line(TextFile::content(line).trim_start())
            .map_err(|e| anyhow::anyhow!("{}: {e}", system::GROUPS_CONF))?;
        let mut view = GroupView { group, members: Vec::new(), fixed_members: Vec::new() };
        for (group, account, editable) in &memberships {
            if *group == view.group.name {
                view.members.push(account.clone());
                if !editable {
                    view.fixed_members.push(account.clone());
                }
            }
        }
        out.groups.push(view);
    }
    Ok(out)
}

/// Rewrites each account line of users.conf that `edit` changes.
fn rewrite_accounts(conf: &mut TextFile, edit: impl Fn(&mut Line) -> bool) -> Result<(), Failure> {
    for i in 0..conf.lines.len() {
        if !accounts::is_spec(&conf.lines[i]) {
            continue;
        }
        let mut line = spec::parse_line(TextFile::content(&conf.lines[i]).trim_start())?;
        if !edit(&mut line) {
            continue;
        }
        let text = spec::format_line(&line);
        if spec::parse_line(&text)? != line {
            return Err(Failure::new(format!("the line of {} does not read back as written", line.name)));
        }
        conf.replace(i, &text);
    }
    Ok(())
}

fn save(groups: &TextFile, users: &TextFile) -> Result<Outcome, Failure> {
    let path = Path::new(system::GROUPS_CONF);
    let backup = Backup::of(path)?;
    system::write_atomic(path, groups.render().as_bytes(), 0o600)?;
    accounts::save_users_conf(users, vec![backup])
}

pub fn put(create: bool, input: GroupInput) -> Result<Outcome, Failure> {
    let GroupInput { mut group, members } = input;
    spec::validate_name(&group.name)?;
    group.gid = match group.gid {
        Some(gid) => Some(spec::check_id(u64::from(gid), "gid")?),
        None => None,
    };
    group.options.normalize()?;
    if !group.options.groups.is_empty() {
        return Err(Failure::new("a group cannot belong to a group"));
    }
    let text = spec::format_group_line(&group);
    if spec::parse_group_line(&text)? != group {
        return Err(Failure::new("the group line does not read back as written"));
    }
    let mut groups = TextFile::parse(&system::read_text(Path::new(system::GROUPS_CONF))?);
    match (create, find(&groups, &group.name)?) {
        (true, Some(_)) => return Err(Failure::new(format!("a group named {} already exists", group.name))),
        (false, None) => return Err(Failure::new(format!("there is no group named {}", group.name))),
        (_, Some((index, _))) => groups.replace(index, &text),
        (_, None) => groups.push(&text),
    }
    let state = system::read_state()?;
    for name in &members {
        match state.iter().find(|a| &a.name == name) {
            Some(a) if a.source == "users.conf" => {}
            Some(_) => {
                return Err(Failure::new(format!(
                    "{name} is defined outside users.conf, so the web UI cannot change its groups"
                )));
            }
            None => return Err(Failure::new(format!("there is no account named {name}"))),
        }
    }
    let mut users = TextFile::parse(&system::read_text(Path::new(system::USERS_CONF))?);
    let name = group.name.clone();
    rewrite_accounts(&mut users, |line| {
        let want = members.contains(&line.name);
        let has = line.options.groups.contains(&name);
        if want && !has {
            line.options.groups.push(name.clone());
        } else if has && !want {
            line.options.groups.retain(|g| *g != name);
        }
        want != has
    })?;
    save(&groups, &users)
}

pub fn delete(name: &str) -> Result<Outcome, Failure> {
    let mut groups = TextFile::parse(&system::read_text(Path::new(system::GROUPS_CONF))?);
    if find(&groups, name)?.is_none() {
        return Err(Failure::new(format!("there is no group named {name}")));
    }
    let mut fixed = Vec::new();
    for account in system::read_state()? {
        let options = spec::parse_options(&account.options)?;
        if account.source != "users.conf" && options.groups.iter().any(|g| g == name) {
            fixed.push(account.name);
        }
    }
    if !fixed.is_empty() {
        return Err(Failure::new(format!(
            "{} {} outside users.conf and still name the group {name}; remove it there first",
            fixed.join(", "),
            if fixed.len() == 1 { "is defined" } else { "are defined" }
        )));
    }
    let target = format!("@{name}");
    groups.lines.retain(|line| !(accounts::is_spec(line) && accounts::name_of(line) == name));
    for i in 0..groups.lines.len() {
        if !accounts::is_spec(&groups.lines[i]) {
            continue;
        }
        let mut group = spec::parse_group_line(TextFile::content(&groups.lines[i]).trim_start())?;
        if group.options.manage.contains(&target) {
            group.options.manage.retain(|m| *m != target);
            groups.replace(i, &spec::format_group_line(&group));
        }
    }
    let mut users = TextFile::parse(&system::read_text(Path::new(system::USERS_CONF))?);
    rewrite_accounts(&mut users, |line| {
        let before = line.options.groups.len() + line.options.manage.len();
        line.options.groups.retain(|g| g != name);
        line.options.manage.retain(|m| *m != target);
        before != line.options.groups.len() + line.options.manage.len()
    })?;
    save(&groups, &users)
}
