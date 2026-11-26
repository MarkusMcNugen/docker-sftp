//! Pages of /var/log/auth.log and the audit log, newest first. A search
//! reads every line; a page ends after PAGE matches and names a cursor for
//! the next, older page, so every line stays reachable.

use std::fs::File;
use std::io::{ErrorKind, Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use sftp_webui::proto::{AuditEntry, AuditPage, LogPage};

use crate::system;

/// Newest first: the live log, then the copy the rotation keeps.
const AUTH_LOGS: [&str; 2] = ["/var/log/auth.log", "/var/log/auth.log.1"];
const PAGE: usize = 200;
const CHUNK: u64 = 64 * 1024;
const OFFSET_BITS: u32 = 56;
const END: u64 = (1 << OFFSET_BITS) - 1;

fn encode(file: usize, offset: u64) -> u64 {
    ((file as u64) << OFFSET_BITS) | offset.min(END)
}

fn decode(cursor: u64) -> (usize, u64) {
    ((cursor >> OFFSET_BITS) as usize, cursor & END)
}

/// Reads lines of `path` backwards from offset `end`, adding those that
/// contain `query` to `out` until it holds `want`. Returns the offset of the
/// oldest line read, 0 when the start of the file was reached.
fn read_back(path: &Path, end: u64, query: &str, want: usize, out: &mut Vec<String>) -> Result<u64> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e).with_context(|| format!("cannot open {}", path.display())),
    };
    let len = file.metadata().with_context(|| format!("cannot inspect {}", path.display()))?.len();
    let mut pos = end.min(len);
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let content_end = if tail.last() == Some(&b'\n') { tail.len() - 1 } else { tail.len() };
        match tail[..content_end].iter().rposition(|b| *b == b'\n') {
            Some(i) => {
                let start = pos + i as u64 + 1;
                consider(&tail[i + 1..content_end], query, out);
                tail.truncate(i + 1);
                if out.len() >= want {
                    return Ok(start);
                }
            }
            None if pos == 0 => {
                consider(&tail[..content_end], query, out);
                return Ok(0);
            }
            None => {
                let n = CHUNK.min(pos);
                pos -= n;
                let mut chunk = vec![0u8; n as usize];
                file.seek(SeekFrom::Start(pos)).with_context(|| format!("cannot read {}", path.display()))?;
                file.read_exact(&mut chunk).with_context(|| format!("cannot read {}", path.display()))?;
                chunk.extend_from_slice(&tail);
                tail = chunk;
            }
        }
    }
}

fn consider(line: &[u8], query: &str, out: &mut Vec<String>) {
    if line.is_empty() {
        return;
    }
    let text = String::from_utf8_lossy(line);
    if query.is_empty() || text.to_lowercase().contains(query) {
        out.push(text.into_owned());
    }
}

/// One page across `files`, newest first, from the cursor `before`.
fn page(files: &[&str], query: &str, before: Option<u64>) -> Result<(Vec<String>, Option<u64>)> {
    let query = query.trim().to_lowercase();
    let (mut file, mut end) = match before {
        Some(c) => decode(c),
        None => (0, END),
    };
    let mut lines = Vec::new();
    while file < files.len() {
        let stop = read_back(Path::new(files[file]), end, &query, PAGE, &mut lines)?;
        if lines.len() >= PAGE {
            let older = if stop > 0 {
                Some(encode(file, stop))
            } else if file + 1 < files.len() {
                Some(encode(file + 1, END))
            } else {
                None
            };
            return Ok((lines, older));
        }
        file += 1;
        end = END;
    }
    Ok((lines, None))
}

pub fn auth_page(query: &str, before: Option<u64>) -> Result<LogPage> {
    let (lines, older) = page(&AUTH_LOGS, query, before)?;
    Ok(LogPage { lines, older })
}

pub fn audit_page(query: &str, before: Option<u64>) -> Result<AuditPage> {
    let (lines, older) = page(&[system::AUDIT_LOG], query, before)?;
    let entries = lines
        .into_iter()
        .map(|line| match serde_json::from_str::<AuditEntry>(&line) {
            Ok(entry) => entry,
            Err(e) => AuditEntry {
                action: format!("unreadable line ({e})"),
                target: line,
                ..AuditEntry::default()
            },
        })
        .collect();
    Ok(AuditPage { entries, older })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn pages_backwards_through_every_line() {
        let dir = std::env::temp_dir().join(format!("sftp-helper-logs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("log");
        let mut f = File::create(&path).expect("create");
        for i in 0..1000 {
            writeln!(f, "line {i} {}", if i % 3 == 0 { "match" } else { "other" }).expect("write");
        }
        drop(f);
        let p = path.to_string_lossy().into_owned();
        let files = [p.as_str()];
        let (first, older) = page(&files, "MATCH", None).expect("page");
        assert_eq!(first.len(), PAGE);
        assert_eq!(first[0], "line 999 match");
        let (second, rest) = page(&files, "match", older).expect("page");
        assert_eq!(second[0], format!("line {} match", 999 - 3 * PAGE));
        assert_eq!(first.len() + second.len(), 334);
        assert!(rest.is_none());
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
