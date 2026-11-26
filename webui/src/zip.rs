//! Zip archives. They are written as a stream, entry by entry while the
//! files are read, so a folder of any size downloads without being held
//! anywhere, and read through their central directory, so an archive lists
//! without being unpacked. Entries are stored, not compressed; zip64 fields
//! appear only where a size, an offset or the count of entries needs them.

use anyhow::{Result, bail};

const LOCAL: u32 = 0x0403_4b50;
const DESCRIPTOR: u32 = 0x0807_4b50;
const CENTRAL: u32 = 0x0201_4b50;
const END: u32 = 0x0605_4b50;
const END64: u32 = 0x0606_4b50;
const LOCATOR64: u32 = 0x0706_4b50;
const FLAG_ENCRYPTED: u16 = 0x0001;
const FLAG_DESCRIPTOR: u16 = 0x0008;
const FLAG_UTF8: u16 = 0x0800;
const MAX32: u64 = 0xFFFF_FFFF;
/// Made on Unix, so the external attributes carry the mode, by a writer
/// that knows zip64 (version 4.5).
const MADE_BY: u16 = (3 << 8) | 45;

/// The size of the end record without a comment, and the most a comment
/// may add, so the end record lies in the last END_SPAN bytes.
const END_LEN: usize = 22;
pub const END_SPAN: u64 = END_LEN as u64 + 0xFFFF;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    Link,
}

fn put16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A value that fits in 32 bits, or the zip64 marker for one that does not.
fn low32(v: u64) -> u32 {
    if v >= MAX32 { u32::MAX } else { v as u32 }
}

/// MS-DOS time and date of a moment in UTC, as zip records them; a moment
/// before 1980, or one not known, is recorded as its first second.
fn dos_time(mtime: Option<u64>) -> (u16, u16) {
    let Some(mtime) = mtime else { return (0, (1 << 5) | 1) };
    let (y, m, d, hh, mm, ss) = crate::timefmt::parts(mtime);
    if y < 1980 {
        return (0, (1 << 5) | 1);
    }
    let years = (y - 1980).min(127) as u16;
    let date = (years << 9) | ((m as u16) << 5) | d as u16;
    let time = ((hh as u16) << 11) | ((mm as u16) << 5) | (ss as u16 / 2);
    (time, date)
}

/// The zip64 extended information field holding `values` in order.
fn zip64_extra(values: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + values.len() * 8);
    put16(&mut out, 0x0001);
    put16(&mut out, (values.len() * 8) as u16);
    for v in values {
        put64(&mut out, *v);
    }
    out
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = flate2::Crc::new();
    crc.update(data);
    crc.sum()
}

/// What the central directory records of an entry once it is written.
struct Written {
    name: Vec<u8>,
    kind: Kind,
    mode: u32,
    time: u16,
    date: u16,
    flags: u16,
    crc: u32,
    size: u64,
    offset: u64,
    /// Its local header and descriptor carry zip64 sizes.
    wide: bool,
}

/// A zip archive written as a stream: each call returns the bytes to send
/// next, and `finish` the central directory after the last entry.
#[derive(Default)]
pub struct Writer {
    sent: u64,
    done: Vec<Written>,
    open: Option<Written>,
}

fn name_bytes(name: &str) -> Result<Vec<u8>> {
    if name.is_empty() || name.len() > usize::from(u16::MAX) {
        bail!("an entry's name must hold 1 to 65535 bytes");
    }
    Ok(name.as_bytes().to_vec())
}

fn local_header(out: &mut Vec<u8>, w: &Written, size32: u32, extra: &[u8]) {
    put32(out, LOCAL);
    put16(out, if w.wide { 45 } else { 20 });
    put16(out, w.flags);
    put16(out, 0);
    put16(out, w.time);
    put16(out, w.date);
    put32(out, if w.flags & FLAG_DESCRIPTOR != 0 { 0 } else { w.crc });
    put32(out, size32);
    put32(out, size32);
    put16(out, w.name.len() as u16);
    put16(out, extra.len() as u16);
    out.extend_from_slice(&w.name);
    out.extend_from_slice(extra);
}

impl Writer {
    pub fn new() -> Writer {
        Writer::default()
    }

    /// How many bytes the archive holds so far.
    pub fn sent(&self) -> u64 {
        self.sent
    }

    /// The local header of a file whose bytes follow it. `listed` is its
    /// size as listed, which decides whether its sizes take zip64 fields,
    /// as they do when it is not known; `end_file` comes after its bytes.
    pub fn begin_file(&mut self, name: &str, mode: u32, mtime: Option<u64>, listed: Option<u64>) -> Result<Vec<u8>> {
        if self.open.is_some() {
            bail!("a file is already open in the archive");
        }
        let (time, date) = dos_time(mtime);
        let w = Written {
            name: name_bytes(name)?,
            kind: Kind::File,
            mode,
            time,
            date,
            flags: FLAG_DESCRIPTOR | FLAG_UTF8,
            crc: 0,
            size: 0,
            offset: self.sent,
            wide: listed.is_none_or(|n| n >= MAX32),
        };
        let mut out = Vec::new();
        if w.wide {
            local_header(&mut out, &w, u32::MAX, &zip64_extra(&[0, 0]));
        } else {
            local_header(&mut out, &w, 0, &[]);
        }
        self.sent += out.len() as u64;
        self.open = Some(w);
        Ok(out)
    }

    /// The data descriptor after a file's bytes: their CRC-32 and count.
    pub fn end_file(&mut self, crc: u32, size: u64) -> Result<Vec<u8>> {
        let Some(mut w) = self.open.take() else { bail!("no file is open in the archive") };
        if !w.wide && size >= MAX32 {
            bail!("{} grew past 4 GiB while it was read", String::from_utf8_lossy(&w.name));
        }
        self.sent += size;
        let mut out = Vec::new();
        put32(&mut out, DESCRIPTOR);
        put32(&mut out, crc);
        if w.wide {
            put64(&mut out, size);
            put64(&mut out, size);
        } else {
            put32(&mut out, size as u32);
            put32(&mut out, size as u32);
        }
        self.sent += out.len() as u64;
        w.crc = crc;
        w.size = size;
        self.done.push(w);
        Ok(out)
    }

    /// A folder's entry; `name` ends in a slash.
    pub fn dir(&mut self, name: &str, mode: u32, mtime: Option<u64>) -> Result<Vec<u8>> {
        self.whole(name, Kind::Dir, mode, mtime, &[])
    }

    /// A link's entry, with its target as its content, as the zip and unzip
    /// tools store one.
    pub fn link(&mut self, name: &str, mtime: Option<u64>, target: &str) -> Result<Vec<u8>> {
        self.whole(name, Kind::Link, 0o777, mtime, target.as_bytes())
    }

    /// An entry whose content is known before its header is written.
    fn whole(&mut self, name: &str, kind: Kind, mode: u32, mtime: Option<u64>, data: &[u8]) -> Result<Vec<u8>> {
        if self.open.is_some() {
            bail!("a file is still open in the archive");
        }
        let (time, date) = dos_time(mtime);
        let w = Written {
            name: name_bytes(name)?,
            kind,
            mode,
            time,
            date,
            flags: FLAG_UTF8,
            crc: crc32(data),
            size: data.len() as u64,
            offset: self.sent,
            wide: false,
        };
        let mut out = Vec::new();
        local_header(&mut out, &w, low32(w.size), &[]);
        out.extend_from_slice(data);
        self.sent += out.len() as u64;
        self.done.push(w);
        Ok(out)
    }

    /// The central directory and the end records.
    pub fn finish(self) -> Result<Vec<u8>> {
        if self.open.is_some() {
            bail!("a file is still open in the archive");
        }
        let start = self.sent;
        let mut out = Vec::new();
        for w in &self.done {
            let big_size = w.wide || w.size >= MAX32;
            let big_offset = w.offset >= MAX32;
            let mut wide = Vec::new();
            if big_size {
                wide.push(w.size);
                wide.push(w.size);
            }
            if big_offset {
                wide.push(w.offset);
            }
            let extra = if wide.is_empty() { Vec::new() } else { zip64_extra(&wide) };
            let kind_bits = match w.kind {
                Kind::File => 0o100_000,
                Kind::Dir => 0o040_000,
                Kind::Link => 0o120_000,
            };
            let attrs = ((kind_bits | (w.mode & 0o7777)) << 16) | if w.kind == Kind::Dir { 0x10 } else { 0 };
            put32(&mut out, CENTRAL);
            put16(&mut out, MADE_BY);
            put16(&mut out, if wide.is_empty() { 20 } else { 45 });
            put16(&mut out, w.flags);
            put16(&mut out, 0);
            put16(&mut out, w.time);
            put16(&mut out, w.date);
            put32(&mut out, w.crc);
            let size32 = if big_size { u32::MAX } else { w.size as u32 };
            put32(&mut out, size32);
            put32(&mut out, size32);
            put16(&mut out, w.name.len() as u16);
            put16(&mut out, extra.len() as u16);
            put16(&mut out, 0);
            put16(&mut out, 0);
            put16(&mut out, 0);
            put32(&mut out, attrs);
            put32(&mut out, low32(w.offset));
            out.extend_from_slice(&w.name);
            out.extend_from_slice(&extra);
        }
        let size = out.len() as u64;
        let count = self.done.len() as u64;
        if count >= 0xFFFF || start >= MAX32 || size >= MAX32 {
            let record = start + size;
            put32(&mut out, END64);
            put64(&mut out, 44);
            put16(&mut out, MADE_BY);
            put16(&mut out, 45);
            put32(&mut out, 0);
            put32(&mut out, 0);
            put64(&mut out, count);
            put64(&mut out, count);
            put64(&mut out, size);
            put64(&mut out, start);
            put32(&mut out, LOCATOR64);
            put32(&mut out, 0);
            put64(&mut out, record);
            put32(&mut out, 1);
        }
        put32(&mut out, END);
        put16(&mut out, 0);
        put16(&mut out, 0);
        put16(&mut out, count.min(0xFFFF) as u16);
        put16(&mut out, count.min(0xFFFF) as u16);
        put32(&mut out, low32(size));
        put32(&mut out, low32(start));
        put16(&mut out, 0);
        Ok(out)
    }
}

/// Little-endian fields read from a slice.
struct Fields<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Fields<'a> {
    fn new(data: &'a [u8], at: usize) -> Self {
        Fields { data, at }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n);
        let Some(bytes) = end.and_then(|end| self.data.get(self.at..end)) else {
            bail!("the archive's directory ends early")
        };
        self.at += n;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Ok(u64::from_le_bytes(a))
    }
}

/// Where an archive's central directory lies and what it holds.
#[derive(Debug, PartialEq, Eq)]
pub struct Directory {
    pub offset: u64,
    pub size: u64,
    pub count: u64,
}

/// What the end of an archive says: the directory, or where the zip64 end
/// record that describes it lies.
#[derive(Debug, PartialEq, Eq)]
pub enum Ending {
    Directory(Directory),
    Zip64At(u64),
}

/// Reads the end of an archive of `len` bytes from `tail`, its last bytes
/// (END_SPAN of them, or all of a smaller archive).
pub fn ending(tail: &[u8], len: u64) -> Result<Ending> {
    if tail.len() < END_LEN {
        bail!("this is not a zip archive: it is too short");
    }
    let Some(at) = (0..=tail.len() - END_LEN).rev().find(|&i| tail[i..i + 4] == END.to_le_bytes()) else {
        bail!("this is not a zip archive: it has no end record");
    };
    let mut f = Fields::new(tail, at + 4);
    let (disk, cd_disk) = (f.u16()?, f.u16()?);
    if disk != 0 || cd_disk != 0 {
        bail!("this archive is split across several files");
    }
    f.u16()?;
    let count = f.u16()?;
    let size = f.u32()?;
    let offset = f.u32()?;
    let end_at = len - tail.len() as u64 + at as u64;
    if (count == 0xFFFF || size == u32::MAX || offset == u32::MAX) && at >= 20 {
        let mut l = Fields::new(tail, at - 20);
        if l.u32()? == LOCATOR64 {
            l.u32()?;
            return Ok(Ending::Zip64At(l.u64()?));
        }
    }
    if u64::from(offset) + u64::from(size) > end_at {
        bail!("this archive's directory lies past its end");
    }
    Ok(Ending::Directory(Directory { offset: offset.into(), size: size.into(), count: count.into() }))
}

/// Reads a zip64 end record: the 56 bytes at the place `ending` named.
pub fn ending64(record: &[u8]) -> Result<Directory> {
    let mut f = Fields::new(record, 0);
    if f.u32()? != END64 {
        bail!("this archive's zip64 end record is missing");
    }
    f.u64()?;
    f.u16()?;
    f.u16()?;
    f.u32()?;
    f.u32()?;
    f.u64()?;
    let count = f.u64()?;
    let size = f.u64()?;
    let offset = f.u64()?;
    Ok(Directory { offset, size, count })
}

/// An entry as the central directory lists it.
#[derive(Debug, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    pub kind: Kind,
    /// Its size unpacked, and as stored.
    pub size: u64,
    pub packed: u64,
    /// 0 stored, 8 deflated; others are not read here.
    pub method: u16,
    pub crc: u32,
    pub encrypted: bool,
    /// Where its local header lies.
    pub offset: u64,
}

/// The entries of a central directory read whole.
pub fn entries(cd: &[u8], count: u64) -> Result<Vec<Listed>> {
    let mut f = Fields::new(cd, 0);
    let mut out = Vec::new();
    for _ in 0..count {
        if f.u32()? != CENTRAL {
            bail!("the archive's directory holds something that is not an entry");
        }
        let made_by = f.u16()?;
        f.u16()?;
        let flags = f.u16()?;
        let method = f.u16()?;
        f.u32()?;
        let crc = f.u32()?;
        let mut packed = u64::from(f.u32()?);
        let mut size = u64::from(f.u32()?);
        let name_len = usize::from(f.u16()?);
        let extra_len = usize::from(f.u16()?);
        let comment_len = usize::from(f.u16()?);
        f.u16()?;
        f.u16()?;
        let attrs = f.u32()?;
        let mut offset = u64::from(f.u32()?);
        let name = String::from_utf8_lossy(f.take(name_len)?).into_owned();
        let mut extra = Fields::new(f.take(extra_len)?, 0);
        while extra.at + 4 <= extra.data.len() {
            let id = extra.u16()?;
            let len = usize::from(extra.u16()?);
            let body = extra.take(len)?;
            if id == 0x0001 {
                let mut z = Fields::new(body, 0);
                if size == MAX32 {
                    size = z.u64()?;
                }
                if packed == MAX32 {
                    packed = z.u64()?;
                }
                if offset == MAX32 {
                    offset = z.u64()?;
                }
            }
        }
        f.take(comment_len)?;
        let unix = made_by >> 8 == 3;
        let kind = match (attrs >> 16) & 0o170_000 {
            0o040_000 if unix => Kind::Dir,
            0o120_000 if unix => Kind::Link,
            _ if name.ends_with('/') => Kind::Dir,
            _ => Kind::File,
        };
        out.push(Listed { name, kind, size, packed, method, crc, encrypted: flags & FLAG_ENCRYPTED != 0, offset });
    }
    Ok(out)
}

/// Where an entry's content starts, from the first 30 bytes of its local
/// header at `offset`.
pub fn content_at(header: &[u8], offset: u64) -> Result<u64> {
    let mut f = Fields::new(header, 0);
    if f.u32()? != LOCAL {
        bail!("the archive's entry has no header where its directory says");
    }
    f.take(22)?;
    let name_len = u64::from(f.u16()?);
    let extra_len = u64::from(f.u16()?);
    Ok(offset + 30 + name_len + extra_len)
}

/// An entry's path made safe to unpack below a folder: relative, with no
/// empty, . or .. parts and no backslash. None for one that would leave it.
pub fn safe_path(name: &str) -> Option<String> {
    let trimmed = name.trim_end_matches('/');
    if trimmed.is_empty() || trimmed.starts_with('/') || trimmed.contains('\\') || trimmed.chars().any(char::is_control) {
        return None;
    }
    let parts: Vec<&str> = trimmed.split('/').collect();
    if parts.iter().any(|p| p.is_empty() || *p == "." || *p == "..") {
        return None;
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_back(zip: &[u8]) -> Vec<Listed> {
        let len = zip.len() as u64;
        let tail = &zip[zip.len().saturating_sub(END_SPAN as usize)..];
        let dir = match ending(tail, len).expect("an end record") {
            Ending::Directory(d) => d,
            Ending::Zip64At(at) => ending64(&zip[at as usize..at as usize + 56]).expect("a zip64 end record"),
        };
        entries(&zip[dir.offset as usize..(dir.offset + dir.size) as usize], dir.count).expect("entries")
    }

    #[test]
    fn writes_what_it_reads_back() {
        let mut w = Writer::new();
        let mut zip = Vec::new();
        zip.extend(w.dir("docs/", 0o755, Some(1_700_000_000)).expect("dir"));
        let body = b"hello from sftp\n";
        zip.extend(w.begin_file("docs/hello.txt", 0o644, Some(1_700_000_000), Some(body.len() as u64)).expect("begin"));
        zip.extend_from_slice(body);
        zip.extend(w.end_file(crc32(body), body.len() as u64).expect("end"));
        zip.extend(w.link("docs/latest", None, "hello.txt").expect("link"));
        assert_eq!(w.sent(), zip.len() as u64);
        zip.extend(w.finish().expect("finish"));
        let listed = read_back(&zip);
        let names: Vec<(&str, Kind, u64)> = listed.iter().map(|l| (l.name.as_str(), l.kind, l.size)).collect();
        assert_eq!(names, vec![("docs/", Kind::Dir, 0), ("docs/hello.txt", Kind::File, 16), ("docs/latest", Kind::Link, 9)]);
        assert_eq!(listed[1].crc, crc32(body));
        let at = content_at(&zip[listed[1].offset as usize..], listed[1].offset).expect("header");
        assert_eq!(&zip[at as usize..at as usize + 16], body);
    }

    #[test]
    fn widens_only_what_needs_it() {
        let mut w = Writer::new();
        let mut zip = w.begin_file("big.bin", 0o644, None, Some(MAX32)).expect("begin");
        zip.extend_from_slice(b"abc");
        zip.extend(w.end_file(crc32(b"abc"), 3).expect("end"));
        zip.extend(w.finish().expect("finish"));
        let listed = read_back(&zip);
        assert_eq!(listed[0].size, 3);
        let mut w = Writer::new();
        let mut zip = Vec::new();
        for i in 0..0x1_0000u32 {
            zip.extend(w.dir(&format!("d{i}/"), 0o755, None).expect("dir"));
        }
        zip.extend(w.finish().expect("finish"));
        assert_eq!(read_back(&zip).len(), 0x1_0000);
    }

    #[test]
    fn refuses_a_file_that_outgrows_its_header() {
        let mut w = Writer::new();
        w.begin_file("x", 0o644, None, Some(10)).expect("begin");
        assert!(w.end_file(0, MAX32).is_err());
        let mut unknown = Writer::new();
        unknown.begin_file("y", 0o644, None, None).expect("begin");
        assert!(unknown.end_file(0, MAX32).is_ok(), "a file of unknown size takes zip64 sizes");
    }

    #[test]
    fn keeps_unpacked_paths_inside() {
        assert_eq!(safe_path("a/b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(safe_path("a/").as_deref(), Some("a"));
        for bad in ["/etc/passwd", "../x", "a/../../x", "a//b", "a\\b", "./a", "", "a/\nb"] {
            assert_eq!(safe_path(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn dates_before_1980_become_its_first_day() {
        assert_eq!(dos_time(Some(0)), (0, (1 << 5) | 1));
        assert_eq!(dos_time(None), (0, (1 << 5) | 1));
        let (_, date) = dos_time(Some(1_700_000_000));
        assert_eq!(date >> 9, 2023 - 1980);
    }

    /// Writes a sample archive to ZIP_SAMPLE for a check by another zip
    /// reader: `ZIP_SAMPLE=x.zip cargo test --lib zip -- --ignored`.
    #[test]
    #[ignore = "writes a file for an outside check"]
    fn writes_a_sample_for_outside_checks() {
        let Some(path) = std::env::var_os("ZIP_SAMPLE") else { return };
        let mut w = Writer::new();
        let mut zip = Vec::new();
        zip.extend(w.dir("sample/", 0o755, Some(1_700_000_000)).expect("dir"));
        for (name, body) in [("sample/a.txt", &b"alpha\n"[..]), ("sample/sub/b.txt", &b"beta\n"[..])] {
            zip.extend(w.begin_file(name, 0o644, Some(1_700_000_000), Some(body.len() as u64)).expect("begin"));
            zip.extend_from_slice(body);
            zip.extend(w.end_file(crc32(body), body.len() as u64).expect("end"));
        }
        zip.extend(w.begin_file("sample/unknown-size.txt", 0o644, None, None).expect("begin"));
        zip.extend_from_slice(b"gamma\n");
        zip.extend(w.end_file(crc32(b"gamma\n"), 6).expect("end"));
        zip.extend(w.link("sample/link", Some(1_700_000_000), "a.txt").expect("link"));
        zip.extend(w.finish().expect("finish"));
        std::fs::write(path, zip).expect("write");
    }
}
