//! Tar archives, as the file browser reads them: a 512-byte header before
//! each entry's data, ustar names with their prefix, GNU long names and
//! links, pax records for the path, the link and the size, and sizes in
//! octal or base-256. Reading the bytes, and inflating a .tar.gz, is the
//! caller's: it hands `Reader` each header and each extension's data.

use anyhow::{Result, bail};

/// Headers and the padding after each entry's data come in blocks of this.
pub const BLOCK: u64 = 512;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    File,
    Dir,
    /// A hard or symbolic link, which is never unpacked.
    Link,
    /// A device, a pipe or anything else that is not unpacked.
    Other,
}

/// One entry of an archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub kind: Kind,
    /// The size of its data, which follows its header.
    pub size: u64,
    /// Where a link points; empty otherwise.
    pub link: String,
}

/// What a header block means.
#[derive(Debug, PartialEq, Eq)]
pub enum Step {
    /// A block of zeros: the archive ends.
    End,
    /// A GNU long name or link, or pax records, describing the next entry:
    /// its `size` bytes of data go to `Reader::extension`.
    Extension { typeflag: u8, size: u64 },
    /// An entry, whose `size` bytes of data follow.
    Entry(Entry),
}

/// Bytes of padding after `size` bytes of data, up to the next block.
pub fn padding(size: u64) -> u64 {
    (BLOCK - size % BLOCK) % BLOCK
}

/// Turns header blocks into entries, carrying long names and pax records to
/// the entry they describe.
#[derive(Default)]
pub struct Reader {
    long_name: Option<String>,
    long_link: Option<String>,
    pax_path: Option<String>,
    pax_link: Option<String>,
    pax_size: Option<u64>,
}

/// The text of a NUL-terminated header field.
fn text(field: &[u8]) -> String {
    let end = match field.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => field.len(),
    };
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// A number field: octal digits, padded with spaces or NULs, or base-256
/// when its first byte has the high bit set.
fn number(field: &[u8], what: &str) -> Result<u64> {
    if let Some(&first) = field.first()
        && first & 0x80 != 0
    {
        let mut value: u64 = u64::from(first & 0x7f);
        for &b in &field[1..] {
            if value > u64::MAX >> 8 {
                bail!("the {what} of an entry is too large");
            }
            value = (value << 8) | u64::from(b);
        }
        return Ok(value);
    }
    let digits: &[u8] = {
        let start = field.iter().position(|&b| b != b' ' && b != 0);
        let end = field.iter().rposition(|&b| b != b' ' && b != 0);
        match (start, end) {
            (Some(s), Some(e)) => &field[s..=e],
            (None, _) | (_, None) => &[],
        }
    };
    let mut value: u64 = 0;
    for &b in digits {
        if !(b'0'..=b'7').contains(&b) {
            bail!("the {what} of an entry is not an octal number");
        }
        if value > u64::MAX >> 3 {
            bail!("the {what} of an entry is too large");
        }
        value = (value << 3) | u64::from(b - b'0');
    }
    Ok(value)
}

impl Reader {
    /// Reads a header block.
    pub fn header(&mut self, block: &[u8]) -> Result<Step> {
        if block.len() != BLOCK as usize {
            bail!("a tar header is {BLOCK} B, not {} B", block.len());
        }
        if block.iter().all(|&b| b == 0) {
            return Ok(Step::End);
        }
        let stored = number(&block[148..156], "checksum")?;
        let unsigned: u64 = block.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { u64::from(b) }).sum();
        let signed: i64 =
            block.iter().enumerate().map(|(i, &b)| if (148..156).contains(&i) { 32 } else { i64::from(b as i8) }).sum();
        if stored != unsigned && !i64::try_from(stored).is_ok_and(|s| s == signed) {
            bail!("a tar header's checksum does not match: this is not a tar archive, or it is damaged");
        }
        let typeflag = block[156];
        let size = number(&block[124..136], "size")?;
        if matches!(typeflag, b'L' | b'K' | b'x' | b'g') {
            return Ok(Step::Extension { typeflag, size });
        }
        let mut name = text(&block[0..100]);
        if &block[257..262] == b"ustar" {
            let prefix = text(&block[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        let mut link = text(&block[157..257]);
        if let Some(long) = self.long_name.take() {
            name = long;
        }
        if let Some(long) = self.long_link.take() {
            link = long;
        }
        if let Some(path) = self.pax_path.take() {
            name = path;
        }
        if let Some(path) = self.pax_link.take() {
            link = path;
        }
        let size = match self.pax_size.take() {
            Some(n) => n,
            None => size,
        };
        let kind = match typeflag {
            b'0' | 0 | b'7' => {
                if name.ends_with('/') {
                    Kind::Dir
                } else {
                    Kind::File
                }
            }
            b'5' => Kind::Dir,
            b'1' | b'2' => Kind::Link,
            _ => Kind::Other,
        };
        // A link's or a folder's size is not data that follows.
        let size = if matches!(kind, Kind::File | Kind::Other) { size } else { 0 };
        Ok(Step::Entry(Entry { name, kind, size, link }))
    }

    /// Takes the data of an extension header.
    pub fn extension(&mut self, typeflag: u8, data: &[u8]) -> Result<()> {
        match typeflag {
            b'L' => self.long_name = Some(text(data)),
            b'K' => self.long_link = Some(text(data)),
            b'x' => {
                for (key, value) in pax_records(data)? {
                    match key.as_str() {
                        "path" => self.pax_path = Some(value),
                        "linkpath" => self.pax_link = Some(value),
                        "size" => match value.parse::<u64>() {
                            Ok(n) => self.pax_size = Some(n),
                            Err(e) => bail!("a pax size of {value} is not a number: {e}"),
                        },
                        _ => {}
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
}

/// The `length key=value\n` records of a pax header.
fn pax_records(data: &[u8]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut at = 0;
    while at < data.len() {
        if data[at] == 0 {
            break;
        }
        let Some(space) = data[at..].iter().position(|&b| b == b' ') else { bail!("a pax record has no length") };
        let length: usize = match std::str::from_utf8(&data[at..at + space]).map(str::parse::<usize>) {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => bail!("a pax record's length is not a number: {e}"),
            Err(e) => bail!("a pax record's length is not text: {e}"),
        };
        let end = at + length;
        if length <= space + 1 || end > data.len() || data[end - 1] != b'\n' {
            bail!("a pax record's length does not match its text");
        }
        let record = String::from_utf8_lossy(&data[at + space + 1..end - 1]).into_owned();
        let Some((key, value)) = record.split_once('=') else { bail!("a pax record has no key") };
        out.push((key.to_string(), value.to_string()));
        at = end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A ustar header for `name`, of `typeflag` and `size`, its checksum set.
    fn header(name: &str, prefix: &str, typeflag: u8, size: u64) -> Vec<u8> {
        let mut b = vec![0u8; BLOCK as usize];
        b[..name.len()].copy_from_slice(name.as_bytes());
        let size_text = format!("{size:011o}");
        b[124..135].copy_from_slice(size_text.as_bytes());
        b[156] = typeflag;
        b[257..263].copy_from_slice(b"ustar\0");
        b[263..265].copy_from_slice(b"00");
        b[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
        b[148..156].copy_from_slice(b"        ");
        let sum: u64 = b.iter().map(|&x| u64::from(x)).sum();
        b[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        b
    }

    #[test]
    fn reads_names_with_their_prefix_kinds_and_sizes() {
        let mut r = Reader::default();
        let step = r.header(&header("a.txt", "deep/er", b'0', 1234)).expect("a header");
        assert_eq!(step, Step::Entry(Entry { name: "deep/er/a.txt".into(), kind: Kind::File, size: 1234, link: String::new() }));
        let dir = r.header(&header("folder/", "", b'5', 0)).expect("a header");
        assert!(matches!(dir, Step::Entry(Entry { kind: Kind::Dir, size: 0, .. })));
        assert_eq!(r.header(&[0u8; 512]).expect("an end"), Step::End);
        assert_eq!(padding(1234), 302);
        assert_eq!(padding(1024), 0);
    }

    #[test]
    fn carries_long_names_and_pax_records_to_the_next_entry() {
        let mut r = Reader::default();
        let long = "x/".repeat(80) + "file.txt";
        assert_eq!(r.header(&header("././@LongLink", "", b'L', long.len() as u64 + 1)).expect("a header"), Step::Extension {
            typeflag: b'L',
            size: long.len() as u64 + 1
        });
        r.extension(b'L', format!("{long}\0").as_bytes()).expect("a long name");
        let Step::Entry(e) = r.header(&header("short", "", b'0', 5)).expect("a header") else { panic!("an entry") };
        assert_eq!(e.name, long);
        let records = "32 path=pax/a name that is long\n14 size=99999\n";
        r.extension(b'x', records.as_bytes()).expect("pax records");
        let Step::Entry(e) = r.header(&header("ignored", "", b'0', 1)).expect("a header") else { panic!("an entry") };
        assert_eq!((e.name.as_str(), e.size), ("pax/a name that is long", 99_999));
        let Step::Entry(e) = r.header(&header("next", "", b'0', 1)).expect("a header") else { panic!("an entry") };
        assert_eq!((e.name.as_str(), e.size), ("next", 1), "records describe one entry only");
    }

    #[test]
    fn reads_base_256_sizes_and_refuses_damage() {
        let mut b = header("big", "", b'0', 0);
        b[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0]);
        b[148..156].copy_from_slice(b"        ");
        let sum: u64 = b.iter().map(|&x| u64::from(x)).sum();
        b[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let Step::Entry(e) = Reader::default().header(&b).expect("a header") else { panic!("an entry") };
        assert_eq!(e.size, 2 << 32);
        let mut bad = header("a", "", b'0', 1);
        bad[0] = b'b';
        assert!(Reader::default().header(&bad).is_err(), "a wrong checksum is refused");
        assert!(Reader::default().extension(b'x', b"99 path=x\n").is_err(), "a record longer than its data is refused");
        let link = header("to", "", b'2', 7);
        let Step::Entry(e) = Reader::default().header(&link).expect("a header") else { panic!("an entry") };
        assert_eq!((e.kind, e.size), (Kind::Link, 0), "a link has no data");
    }
}
