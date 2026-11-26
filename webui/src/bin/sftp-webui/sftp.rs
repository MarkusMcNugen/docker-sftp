//! A small SFTP version 3 client for the file browser. It speaks over the
//! standard input and output of the image's own ssh client, logged in as
//! the account on the file browser's loopback sshd with a certificate from
//! the root helper, so the server applies the account's own permissions,
//! chroot and umask to everything the file browser does.

use std::path::Path;
use std::process::Stdio;

use anyhow::{Context, Result, anyhow, bail};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

const SSH: &str = "/usr/bin/ssh";
const KNOWN_HOSTS: &str = "/run/sftp-files/known_hosts";
const PORT: &str = "2299";
/// The largest packet accepted from the server.
const MAX_PACKET: u32 = 1024 * 1024;
/// How much one read or write moves.
pub const CHUNK: u32 = 32 * 1024;

const INIT: u8 = 1;
const VERSION: u8 = 2;
const OPEN: u8 = 3;
const CLOSE: u8 = 4;
const READ: u8 = 5;
const WRITE: u8 = 6;
const LSTAT: u8 = 7;
const OPENDIR: u8 = 11;
const READDIR: u8 = 12;
const REMOVE: u8 = 13;
const MKDIR: u8 = 14;
const RMDIR: u8 = 15;
const STAT: u8 = 17;
const RENAME: u8 = 18;
const READLINK: u8 = 19;
const SYMLINK: u8 = 20;
const STATUS: u8 = 101;
const HANDLE: u8 = 102;
const DATA: u8 = 103;
const NAME: u8 = 104;
const ATTRS: u8 = 105;

const STATUS_OK: u32 = 0;
const STATUS_EOF: u32 = 1;
const STATUS_NO_SUCH_FILE: u32 = 2;

const OPEN_READ: u32 = 0x01;
const OPEN_WRITE: u32 = 0x02;
const OPEN_CREATE: u32 = 0x08;
const OPEN_TRUNCATE: u32 = 0x10;
const OPEN_EXCLUSIVE: u32 = 0x20;

/// The server's refusal of one request. The session goes on after it, so
/// the connection is kept; any other error leaves the stream in doubt.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// True when an error leaves the connection unusable: anything but the
/// server's refusal of one request.
pub fn broken(e: &anyhow::Error) -> bool {
    !e.chain().any(|cause| cause.is::<Refused>())
}

/// How a file is opened to write.
#[derive(Clone, Copy)]
pub enum Write {
    /// Made, or emptied first when it is there.
    Replace,
    /// Made; refused when the name is taken.
    New,
    /// Kept as it is, to write on past its end.
    Resume,
}

/// What the server says about a path.
#[derive(Default)]
pub struct Attrs {
    pub size: Option<u64>,
    pub mode: Option<u32>,
    /// Seconds since 1970.
    pub modified: Option<u64>,
}

impl Attrs {
    pub fn dir(&self) -> bool {
        self.mode.is_some_and(|m| m & 0o170_000 == 0o040_000)
    }

    pub fn link(&self) -> bool {
        self.mode.is_some_and(|m| m & 0o170_000 == 0o120_000)
    }

    /// The permission bits as `ls` shows them, such as `rwxr-x---`.
    pub fn permissions(&self) -> String {
        let Some(mode) = self.mode else { return String::new() };
        let bits = [(0o400, 'r'), (0o200, 'w'), (0o100, 'x'), (0o040, 'r'), (0o020, 'w'), (0o010, 'x'), (0o004, 'r'), (0o002, 'w'), (0o001, 'x')];
        bits.iter().map(|&(bit, c)| if mode & bit != 0 { c } else { '-' }).collect()
    }
}

/// A file or folder in a listing.
pub struct Entry {
    pub name: String,
    pub attrs: Attrs,
}

/// Reads SFTP's big-endian fields from a packet.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, at: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).context("a field runs past the packet")?;
        let Some(bytes) = self.data.get(self.at..end) else { bail!("a field runs past the packet") };
        self.at = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok((u64::from(self.u32()?) << 32) | u64::from(self.u32()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = usize::try_from(self.u32()?).context("a field is too long")?;
        self.take(n)
    }

    fn text(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.bytes()?).into_owned())
    }

    fn attrs(&mut self) -> Result<Attrs> {
        let flags = self.u32()?;
        let mut a = Attrs::default();
        if flags & 0x1 != 0 {
            a.size = Some(self.u64()?);
        }
        if flags & 0x2 != 0 {
            self.take(8)?;
        }
        if flags & 0x4 != 0 {
            a.mode = Some(self.u32()?);
        }
        if flags & 0x8 != 0 {
            self.take(4)?;
            a.modified = Some(u64::from(self.u32()?));
        }
        if flags & 0x8000_0000 != 0 {
            for _ in 0..self.u32()? {
                self.bytes()?;
                self.bytes()?;
            }
        }
        Ok(a)
    }
}

fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    put_u32(out, u32::try_from(bytes.len()).context("a field is too long")?);
    out.extend_from_slice(bytes);
    Ok(())
}

/// A request's fields that start with a path.
fn path_fields(path: &str) -> Result<Vec<u8>> {
    let mut f = Vec::new();
    put_bytes(&mut f, path.as_bytes())?;
    Ok(f)
}

/// The error in a reply that is not the one expected: the server's status
/// in words, or the unexpected reply's type.
fn refusal(kind: u8, body: &[u8]) -> anyhow::Error {
    if kind != STATUS {
        return anyhow!("the server sent an unexpected reply ({kind})");
    }
    let mut r = Reader::new(body);
    let (code, message) = match (r.u32(), r.text()) {
        (Ok(code), Ok(message)) => (code, message),
        (Err(e), _) | (_, Err(e)) => return e.context("the server's status cannot be read"),
    };
    let words = match code {
        2 => "there is no such file or folder",
        3 => "the account may not do that",
        5 => "the server did not understand the request",
        8 => "the server does not offer that",
        _ => message.as_str(),
    };
    anyhow::Error::new(Refused(words.to_string()))
}

/// One sftp session, logged in as one account.
pub struct Sftp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u32,
}

impl Sftp {
    /// Logs in as `account` on the file browser's loopback sshd with `key`
    /// and its certificate.
    pub async fn connect(account: &str, key: &Path, certificate: &Path) -> Result<Sftp> {
        let mut child = Command::new(SSH)
            .arg("-F")
            .arg("/dev/null")
            .arg("-i")
            .arg(key)
            .arg("-o")
            .arg(format!("CertificateFile={}", certificate.display()))
            .args(["-o", "IdentitiesOnly=yes", "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes"])
            .args(["-o", "BatchMode=yes", "-o", "LogLevel=ERROR", "-o"])
            .arg(format!("UserKnownHostsFile={KNOWN_HOSTS}"))
            .args(["-p", PORT, "-l", account, "127.0.0.1", "-s", "sftp"])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .context("cannot start ssh")?;
        let input = child.stdin.take().context("ssh has no input")?;
        let output = BufReader::new(child.stdout.take().context("ssh has no output")?);
        let mut sftp = Sftp { child, input, output, next: 1 };
        let mut greeting = Vec::new();
        put_u32(&mut greeting, 3);
        let answer = match sftp.send(INIT, &greeting).await {
            Ok(()) => sftp.receive().await,
            Err(e) => Err(e),
        };
        match answer {
            Ok((VERSION, _)) => Ok(sftp),
            Ok((kind, _)) => bail!("the server answered sftp's greeting with {kind}"),
            Err(e) => Err(e.context(sftp.why().await)),
        }
    }

    /// What ssh said on its way out, for an error message.
    async fn why(&mut self) -> String {
        let Some(mut err) = self.child.stderr.take() else { return "ssh failed".into() };
        let mut text = String::new();
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), err.read_to_string(&mut text)).await;
        match read {
            Ok(Ok(_)) if !text.trim().is_empty() => format!("ssh: {}", text.trim()),
            Ok(Ok(_)) => "ssh ended without a word".into(),
            Ok(Err(e)) => format!("cannot read what ssh said: {e}"),
            Err(elapsed) => format!("ssh said nothing ({elapsed})"),
        }
    }

    async fn send(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        let len = u32::try_from(payload.len() + 1).context("the request is too large")?;
        let mut packet = Vec::with_capacity(payload.len() + 5);
        put_u32(&mut packet, len);
        packet.push(kind);
        packet.extend_from_slice(payload);
        self.input.write_all(&packet).await.context("cannot write to ssh")?;
        self.input.flush().await.context("cannot write to ssh")
    }

    async fn receive(&mut self) -> Result<(u8, Vec<u8>)> {
        let len = self.output.read_u32().await.context("the sftp session ended")?;
        if len == 0 || len > MAX_PACKET {
            bail!("the server sent a packet of {len} B");
        }
        let kind = self.output.read_u8().await.context("the sftp session ended")?;
        let mut body = vec![0u8; usize::try_from(len - 1).context("the packet is too large")?];
        self.output.read_exact(&mut body).await.context("the sftp session ended")?;
        Ok((kind, body))
    }

    /// Sends a request and returns the reply's type and its body after the
    /// request id.
    async fn call(&mut self, kind: u8, fields: &[u8]) -> Result<(u8, Vec<u8>)> {
        let id = self.next;
        self.next = self.next.wrapping_add(1);
        let mut payload = Vec::with_capacity(fields.len() + 4);
        put_u32(&mut payload, id);
        payload.extend_from_slice(fields);
        self.send(kind, &payload).await?;
        let (reply, body) = self.receive().await?;
        let got = Reader::new(&body).u32()?;
        if got != id {
            bail!("the server answered request {got}, not {id}");
        }
        Ok((reply, body[4..].to_vec()))
    }

    /// A request answered by a plain status.
    async fn simple(&mut self, kind: u8, fields: &[u8]) -> Result<()> {
        let (reply, body) = self.call(kind, fields).await?;
        if reply == STATUS && Reader::new(&body).u32()? == STATUS_OK {
            return Ok(());
        }
        Err(refusal(reply, &body))
    }

    async fn handle(&mut self, kind: u8, fields: &[u8]) -> Result<Vec<u8>> {
        let (reply, body) = self.call(kind, fields).await?;
        if reply != HANDLE {
            return Err(refusal(reply, &body));
        }
        Ok(Reader::new(&body).bytes()?.to_vec())
    }

    /// What the path names, a link's target for a link.
    pub async fn stat(&mut self, path: &str) -> Result<Attrs> {
        let (reply, body) = self.call(STAT, &path_fields(path)?).await?;
        if reply != ATTRS {
            return Err(refusal(reply, &body));
        }
        Reader::new(&body).attrs()
    }

    /// What the path itself is, a link as a link.
    pub async fn lstat(&mut self, path: &str) -> Result<Attrs> {
        let (reply, body) = self.call(LSTAT, &path_fields(path)?).await?;
        if reply != ATTRS {
            return Err(refusal(reply, &body));
        }
        Reader::new(&body).attrs()
    }

    /// Whether anything, a dangling link included, has the name.
    pub async fn exists(&mut self, path: &str) -> Result<bool> {
        let (reply, body) = self.call(LSTAT, &path_fields(path)?).await?;
        if reply == ATTRS {
            return Ok(true);
        }
        if reply == STATUS && Reader::new(&body).u32()? == STATUS_NO_SUCH_FILE {
            return Ok(false);
        }
        Err(refusal(reply, &body))
    }

    /// Where a link points.
    pub async fn readlink(&mut self, path: &str) -> Result<String> {
        let (reply, body) = self.call(READLINK, &path_fields(path)?).await?;
        if reply != NAME {
            return Err(refusal(reply, &body));
        }
        let mut r = Reader::new(&body);
        if r.u32()? == 0 {
            bail!("the server named no target for {path}");
        }
        r.text()
    }

    /// Makes a link at `link` to `target`. OpenSSH's server takes the target
    /// first, the reverse of the draft standard's order.
    pub async fn symlink(&mut self, target: &str, link: &str) -> Result<()> {
        let mut fields = path_fields(target)?;
        put_bytes(&mut fields, link.as_bytes())?;
        self.simple(SYMLINK, &fields).await
    }

    /// A folder's entries, without . and ..
    pub async fn list(&mut self, path: &str) -> Result<Vec<Entry>> {
        let dir = self.handle(OPENDIR, &path_fields(path)?).await?;
        let mut fields = Vec::new();
        put_bytes(&mut fields, &dir)?;
        let mut out = Vec::new();
        let listed = loop {
            let (reply, body) = match self.call(READDIR, &fields).await {
                Ok(r) => r,
                Err(e) => break Err(e),
            };
            if reply == STATUS && Reader::new(&body).u32()? == STATUS_EOF {
                break Ok(());
            }
            if reply != NAME {
                break Err(refusal(reply, &body));
            }
            let mut r = Reader::new(&body);
            for _ in 0..r.u32()? {
                let name = r.text()?;
                r.bytes()?;
                let attrs = r.attrs()?;
                if name != "." && name != ".." {
                    out.push(Entry { name, attrs });
                }
            }
        };
        let closed = self.simple(CLOSE, &fields).await;
        listed?;
        closed?;
        Ok(out)
    }

    pub async fn open_read(&mut self, path: &str) -> Result<Vec<u8>> {
        self.open(path, OPEN_READ).await
    }

    pub async fn open_write(&mut self, path: &str, how: Write) -> Result<Vec<u8>> {
        let flags = match how {
            Write::Replace => OPEN_WRITE | OPEN_CREATE | OPEN_TRUNCATE,
            Write::New => OPEN_WRITE | OPEN_CREATE | OPEN_EXCLUSIVE,
            Write::Resume => OPEN_WRITE,
        };
        self.open(path, flags).await
    }

    async fn open(&mut self, path: &str, flags: u32) -> Result<Vec<u8>> {
        let mut fields = path_fields(path)?;
        put_u32(&mut fields, flags);
        put_u32(&mut fields, 0);
        self.handle(OPEN, &fields).await
    }

    /// Up to CHUNK bytes from `offset`; None at the end of the file.
    pub async fn read(&mut self, file: &[u8], offset: u64) -> Result<Option<Vec<u8>>> {
        let mut fields = Vec::new();
        put_bytes(&mut fields, file)?;
        fields.extend_from_slice(&offset.to_be_bytes());
        put_u32(&mut fields, CHUNK);
        let (reply, body) = self.call(READ, &fields).await?;
        if reply == DATA {
            return Ok(Some(Reader::new(&body).bytes()?.to_vec()));
        }
        if reply == STATUS && Reader::new(&body).u32()? == STATUS_EOF {
            return Ok(None);
        }
        Err(refusal(reply, &body))
    }

    /// Writes `data` at `offset`, in pieces of at most CHUNK bytes.
    pub async fn write(&mut self, file: &[u8], offset: u64, data: &[u8]) -> Result<()> {
        let mut at = offset;
        for piece in data.chunks(CHUNK as usize) {
            let mut fields = Vec::new();
            put_bytes(&mut fields, file)?;
            fields.extend_from_slice(&at.to_be_bytes());
            put_bytes(&mut fields, piece)?;
            self.simple(WRITE, &fields).await?;
            at += piece.len() as u64;
        }
        Ok(())
    }

    pub async fn close(&mut self, file: &[u8]) -> Result<()> {
        let mut fields = Vec::new();
        put_bytes(&mut fields, file)?;
        self.simple(CLOSE, &fields).await
    }

    pub async fn mkdir(&mut self, path: &str) -> Result<()> {
        let mut fields = path_fields(path)?;
        put_u32(&mut fields, 0);
        self.simple(MKDIR, &fields).await
    }

    pub async fn remove(&mut self, path: &str) -> Result<()> {
        self.simple(REMOVE, &path_fields(path)?).await
    }

    pub async fn rmdir(&mut self, path: &str) -> Result<()> {
        self.simple(RMDIR, &path_fields(path)?).await
    }

    pub async fn rename(&mut self, from: &str, to: &str) -> Result<()> {
        let mut fields = path_fields(from)?;
        put_bytes(&mut fields, to.as_bytes())?;
        self.simple(RENAME, &fields).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_listings_and_refuses_short_packets() {
        let mut body = Vec::new();
        put_u32(&mut body, 1);
        put_bytes(&mut body, b"report.pdf").expect("a name");
        put_bytes(&mut body, b"-rw-r--r-- 1 a a 9 report.pdf").expect("a long name");
        put_u32(&mut body, 0x1 | 0x4 | 0x8);
        body.extend_from_slice(&9u64.to_be_bytes());
        put_u32(&mut body, 0o100_644);
        put_u32(&mut body, 1_700_000_000);
        put_u32(&mut body, 1_700_000_100);
        let mut r = Reader::new(&body);
        assert_eq!(r.u32().expect("a count"), 1);
        assert_eq!(r.text().expect("a name"), "report.pdf");
        r.bytes().expect("a long name");
        let a = r.attrs().expect("attributes");
        assert_eq!((a.size, a.modified, a.dir()), (Some(9), Some(1_700_000_100), false));
        let mut short = Reader::new(&body[..6]);
        short.u32().expect("a count");
        assert!(short.text().is_err(), "a field past the end is refused");
        let mut status = Vec::new();
        put_u32(&mut status, 3);
        put_bytes(&mut status, b"Permission denied").expect("a message");
        put_bytes(&mut status, b"").expect("a language");
        assert_eq!(refusal(STATUS, &status).to_string(), "the account may not do that");
        assert!(refusal(DATA, &[]).to_string().contains("unexpected"));
    }
}
