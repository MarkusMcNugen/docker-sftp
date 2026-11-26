//! What runs: open SFTP sessions, listening ports, services and host keys,
//! read from /proc and the files the entrypoint keeps in /run/sftp.

use std::collections::HashSet;
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result, bail};
use sftp_webui::proto::{HostKey, Service, SessionInfo, Status};
use sftp_webui::spec;
use sftp_webui::timefmt;

use crate::settings;
use crate::system::{self, Failure, Outcome};

/// True for errors that mean the process ended while it was being read.
fn gone(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::NotFound || e.raw_os_error() == Some(3)
}

fn is_number(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

fn proc_ids() -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc").context("cannot list /proc")? {
        let name = entry.context("cannot list /proc")?.file_name();
        let name = name.to_string_lossy();
        if is_number(&name) {
            pids.push(name.parse().with_context(|| format!("bad process id {name}"))?);
        }
    }
    Ok(pids)
}

/// The process title, up to its first NUL, or None if the process is gone.
fn title(pid: u32) -> Result<Option<String>> {
    match fs::read(format!("/proc/{pid}/cmdline")) {
        Ok(raw) => {
            let end = match raw.iter().position(|b| *b == 0) {
                Some(i) => i,
                None => raw.len(),
            };
            Ok(Some(String::from_utf8_lossy(&raw[..end]).into_owned()))
        }
        Err(e) if gone(&e) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("cannot read /proc/{pid}/cmdline")),
    }
}

/// The account of an sshd-session monitor process, whose title is
/// `sshd-session: <name> [priv]`.
fn session_account(title: &str) -> Option<&str> {
    let name = title.strip_prefix("sshd-session: ")?.strip_suffix(" [priv]")?;
    if spec::validate_name(name).is_ok() { Some(name) } else { None }
}

/// One line of /proc/net/tcp or tcp6: the local port, and whether it listens.
struct TcpEntry {
    local_port: u16,
    listening: bool,
}

fn tcp_entries() -> Result<Vec<TcpEntry>> {
    let mut entries = Vec::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = match fs::read_to_string(file) {
            Ok(t) => t,
            Err(e) if e.kind() == ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("cannot read {file}")),
        };
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 {
                bail!("unexpected line in {file}: {line}");
            }
            let bad = || format!("unexpected line in {file}: {line}");
            let Some((_, local_port)) = f[1].split_once(':') else { bail!(bad()) };
            entries.push(TcpEntry {
                local_port: u16::from_str_radix(local_port, 16).with_context(bad)?,
                listening: f[3] == "0A",
            });
        }
    }
    Ok(entries)
}

fn boot_time() -> Result<u64> {
    let text = fs::read_to_string("/proc/stat").context("cannot read /proc/stat")?;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("btime ") {
            return v.trim().parse().context("bad btime in /proc/stat");
        }
    }
    bail!("/proc/stat has no btime")
}

fn start_time(pid: u32, boot: u64) -> Result<Option<u64>> {
    let text = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(t) => t,
        Err(e) if gone(&e) => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read /proc/{pid}/stat")),
    };
    // Field 22, counted after the command name, which may hold spaces.
    let Some((_, rest)) = text.rsplit_once(')') else { bail!("unexpected /proc/{pid}/stat") };
    let Some(ticks) = rest.split_whitespace().nth(19) else { bail!("unexpected /proc/{pid}/stat") };
    let ticks: u64 = ticks.parse().with_context(|| format!("bad start time in /proc/{pid}/stat"))?;
    let hz = rustix::param::clock_ticks_per_second().max(1);
    Ok(Some(boot + ticks / hz))
}

/// The open sessions, one per sshd-session monitor. A session's address is
/// the one its login came from, as the history collector recorded it: the
/// monitor's sockets cannot be read without CAP_SYS_PTRACE, which sshd's
/// processes, being non-dumpable or another account's, would require. It is
/// empty in the second before the collector reads the login.
pub fn sessions() -> Result<Vec<SessionInfo>> {
    let boot = boot_time()?;
    let db = crate::history::open()?;
    let mut out = Vec::new();
    for pid in proc_ids()? {
        let Some(title) = title(pid)? else { continue };
        let Some(account) = session_account(&title) else { continue };
        let Some(since) = start_time(pid, boot)? else { continue };
        let address = crate::history::login_address(&db, pid, since)?;
        out.push(SessionInfo { pid, account: account.to_string(), address, since });
    }
    out.sort_by_key(|s| s.since);
    Ok(out)
}

pub fn end_session(pid: u32) -> Result<Outcome, Failure> {
    let Some(title) = title(pid)? else {
        return Err(Failure::new(format!("process {pid} has already ended")));
    };
    let Some(account) = session_account(&title) else {
        return Err(Failure::new(format!("process {pid} is not an SFTP session")));
    };
    let raw = i32::try_from(pid).map_err(|e| Failure::new(format!("{pid} is not a process id: {e}")))?;
    let Some(target) = rustix::process::Pid::from_raw(raw) else {
        return Err(Failure::new(format!("{pid} is not a process id")));
    };
    rustix::process::kill_process(target, rustix::process::Signal::TERM)
        .map_err(|e| Failure::new(format!("cannot end process {pid}: {e}")))?;
    Ok(Outcome::messages(vec![format!("ended the session of {account} (process {pid})")]))
}

fn read_ports(path: &Path) -> Result<Vec<u16>> {
    let text = system::read_text(path)?;
    let mut ports = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        ports.push(line.parse().with_context(|| format!("bad port in {}: {line}", path.display()))?);
    }
    Ok(ports)
}

fn alive(pid_file: &str) -> Result<bool> {
    let text = match fs::read_to_string(pid_file) {
        Ok(t) => t,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("cannot read {pid_file}")),
    };
    let pid: u32 = text.trim().parse().with_context(|| format!("bad pid in {pid_file}"))?;
    Ok(Path::new(&format!("/proc/{pid}")).exists())
}

fn host_keys() -> Result<Vec<HostKey>> {
    let mut keys = Vec::new();
    for kind in ["ed25519", "rsa"] {
        let path = format!("/config/sshd/keys/ssh_host_{kind}_key.pub");
        if !Path::new(&path).exists() {
            continue;
        }
        // "256 SHA256:abc... comment (ED25519)"
        let out = system::run("/usr/bin/ssh-keygen", &["-l", "-f", &path])?;
        let mut parts = out.split_whitespace();
        let (Some(bits), Some(fingerprint)) = (parts.next(), parts.next()) else {
            bail!("unexpected ssh-keygen output for {path}: {out}");
        };
        keys.push(HostKey { kind: kind.to_uppercase(), bits: bits.into(), fingerprint: fingerprint.into() });
    }
    Ok(keys)
}

fn started() -> Result<u64> {
    let path = Path::new(system::RUN_DIR).join("supervisor.pid");
    let modified = match fs::metadata(&path) {
        Ok(m) => m.modified().context("cannot read the start time")?,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).context("cannot read the start time"),
    };
    let since = modified.duration_since(std::time::UNIX_EPOCH).context("the start time is before 1970")?;
    Ok(since.as_secs())
}

pub fn status() -> Result<Status> {
    let run = Path::new(system::RUN_DIR);
    let listening: HashSet<u16> = tcp_entries()?.into_iter().filter(|e| e.listening).map(|e| e.local_port).collect();
    let sftp_ports = read_ports(&run.join("ports"))?;
    let ports_text: Vec<String> = sftp_ports.iter().map(u16::to_string).collect();
    let fail2ban_enabled = run.join("fail2ban-enabled").exists();
    let webui_ports = read_ports(&run.join("webui-port"))?;
    let services = vec![
        Service {
            name: "sshd".into(),
            running: !sftp_ports.is_empty() && sftp_ports.iter().all(|p| listening.contains(p)),
            detail: format!("port {}", ports_text.join(", ")),
        },
        Service {
            name: "fail2ban".into(),
            running: fail2ban_enabled && alive("/run/fail2ban/fail2ban.pid")?,
            detail: if fail2ban_enabled { "bans brute-force sources".into() } else { "disabled".into() },
        },
        Service {
            name: "rsyslog".into(),
            running: Path::new("/dev/log").exists(),
            detail: "writes the container log and /var/log/auth.log".into(),
        },
        Service {
            name: "web UI".into(),
            running: !webui_ports.is_empty() && webui_ports.iter().all(|p| listening.contains(p)),
            detail: match webui_ports.first() {
                Some(p) => format!("port {p}"),
                None => "not enabled".into(),
            },
        },
    ];
    let state = system::read_state()?;
    let today = (timefmt::now() / 86_400) as i64;
    let mut disabled = 0;
    for account in &state {
        let opts = spec::parse_options(&account.options).map_err(|e| anyhow::anyhow!("{}: {e}", account.name))?;
        let expired = opts.expires.as_deref().is_some_and(|d| timefmt::days_of(d) <= today);
        if opts.disabled || expired {
            disabled += 1;
        }
    }
    let banned = if fail2ban_enabled { settings::banned_count()? } else { 0 };
    Ok(Status {
        version: env!("CARGO_PKG_VERSION").into(),
        started: started()?,
        services,
        sftp_ports,
        host_keys: host_keys()?,
        sessions: sessions()?,
        accounts: state.len(),
        disabled,
        transfer_logging: Path::new("/etc/rsyslog.d/sftp-chroots.conf").exists(),
        banned,
    })
}
