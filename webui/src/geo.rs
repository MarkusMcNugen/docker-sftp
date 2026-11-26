//! The country an IP address is in, from an MMDB country database: DB-IP
//! Lite, which the image carries, or MaxMind GeoLite2 when an account key
//! has fetched it. Both use the GeoIP2 Country record layout.

use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result, bail};
use maxminddb::{Reader, WithinOptions, geoip2};

use crate::net::Network;

/// MaxMind GeoLite2, fetched with an account key; preferred when present.
pub const MAXMIND_DB: &str = "/config/geoip/GeoLite2-Country.mmdb";
/// DB-IP Lite, which the image carries.
pub const DBIP_DB: &str = "/usr/local/share/sftp/geo/dbip-country-lite.mmdb";
/// Where the entrypoint records the country rules it applied, for the
/// helper and the web servers; absent while the rule is off.
pub const STATE_FILE: &str = "/run/sftp/country-rules";

/// The database to read: MaxMind's when present, else DB-IP's.
pub fn database_path() -> &'static Path {
    if Path::new(MAXMIND_DB).exists() { Path::new(MAXMIND_DB) } else { Path::new(DBIP_DB) }
}

/// True for a two-letter ISO 3166 code in either case.
pub fn valid_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic())
}

pub struct Countries {
    reader: Reader<Vec<u8>>,
}

impl Countries {
    pub fn open(path: &Path) -> Result<Countries> {
        let reader = Reader::open_readfile(path).with_context(|| format!("cannot read the country database {}", path.display()))?;
        Ok(Countries { reader })
    }

    /// A database held in memory, such as a download not yet installed.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Countries> {
        let reader = Reader::from_source(bytes).context("the data is not a MaxMind database")?;
        Ok(Countries { reader })
    }

    /// The ISO 3166 code of the country `ip` is in, such as CN; None when the
    /// database places it in no country, as for private addresses.
    pub fn lookup(&self, ip: IpAddr) -> Result<Option<String>> {
        let found = self.reader.lookup(ip).with_context(|| format!("cannot look up {ip}"))?;
        let record: Option<geoip2::Country> = found.decode().with_context(|| format!("cannot read the record of {ip}"))?;
        Ok(record.and_then(|r| r.country.iso_code.map(str::to_ascii_uppercase)))
    }

    /// Every network the database places in one of `codes` (ISO codes, any
    /// case), as CIDR text, IPv4 and IPv6 apart.
    pub fn networks(&self, codes: &[String]) -> Result<(Vec<String>, Vec<String>)> {
        let (mut v4, mut v6) = (Vec::new(), Vec::new());
        let walk = self.reader.networks(WithinOptions::default()).context("cannot walk the country database")?;
        for item in walk {
            let found = item.context("cannot read the country database")?;
            let record: Option<geoip2::Country> = found.decode().context("cannot read a country record")?;
            let Some(code) = record.and_then(|r| r.country.iso_code) else { continue };
            if !codes.iter().any(|c| c.eq_ignore_ascii_case(code)) {
                continue;
            }
            let network = found.network().context("cannot read a network of the country database")?.to_string();
            if network.contains(':') { v6.push(network) } else { v4.push(network) }
        }
        Ok((v4, v6))
    }

    /// Every country the database knows, as its ISO code in capitals and
    /// its English name, sorted by code.
    pub fn names(&self) -> Result<Vec<(String, String)>> {
        let mut names = std::collections::BTreeMap::new();
        let walk = self.reader.networks(WithinOptions::default()).context("cannot walk the country database")?;
        for item in walk {
            let found = item.context("cannot read the country database")?;
            let record: Option<geoip2::Country> = found.decode().context("cannot read a country record")?;
            let Some(country) = record.map(|r| r.country) else { continue };
            let (Some(code), Some(name)) = (country.iso_code, country.names.english) else { continue };
            names.entry(code.to_ascii_uppercase()).or_insert_with(|| name.to_string());
        }
        Ok(names.into_iter().collect())
    }

    /// What the database calls itself, such as DBIP-Country-Lite.
    pub fn kind(&self) -> &str {
        &self.reader.metadata().database_type
    }

    /// When the database was built, in seconds since 1970.
    pub fn built(&self) -> u64 {
        self.reader.metadata().build_epoch
    }
}

/// The largest database a download may unpack to; GeoLite2 Country is
/// about a tenth of this.
const MAX_DATABASE: u64 = 128 * 1024 * 1024;

/// The text of a NUL-padded tar header field.
fn field_text(field: &[u8]) -> String {
    let end = match field.iter().position(|&b| b == 0) {
        Some(i) => i,
        None => field.len(),
    };
    String::from_utf8_lossy(&field[..end]).trim().to_string()
}

/// GeoLite2-Country.mmdb from the tar.gz MaxMind serves. The archive is
/// read in memory: no name in it ever becomes a path.
pub fn mmdb_from_tar_gz(archive: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(archive)
        .take(MAX_DATABASE + 1)
        .read_to_end(&mut tar)
        .context("cannot unpack the download")?;
    if tar.len() as u64 > MAX_DATABASE {
        bail!("the download unpacks to more than {MAX_DATABASE} B");
    }
    let mut at = 0;
    while at + 512 <= tar.len() {
        let header = &tar[at..at + 512];
        if header.iter().all(|&b| b == 0) {
            break;
        }
        let name = field_text(&header[0..100]);
        let size_text = field_text(&header[124..136]);
        if size_text.is_empty() || !size_text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            bail!("the entry {name} has no size");
        }
        let size = usize::from_str_radix(&size_text, 8).with_context(|| format!("the entry {name} is too large"))?;
        let start = at + 512;
        let end = start.checked_add(size).with_context(|| format!("the entry {name} is too large"))?;
        if end > tar.len() {
            bail!("the download ends inside {name}");
        }
        let regular = header[156] == b'0' || header[156] == 0;
        if regular && (name == "GeoLite2-Country.mmdb" || name.ends_with("/GeoLite2-Country.mmdb")) {
            return Ok(tar[start..end].to_vec());
        }
        at = start + size.div_ceil(512) * 512;
    }
    bail!("the download holds no GeoLite2-Country.mmdb")
}

/// Opens a downloaded database and checks that it is a country database
/// that places a public address in a country.
pub fn check_download(bytes: Vec<u8>) -> Result<Countries> {
    let db = Countries::from_bytes(bytes)?;
    if !db.kind().contains("Country") {
        bail!("the download is a {} database, not a country database", db.kind());
    }
    let probe = IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8));
    if db.lookup(probe)?.is_none() {
        bail!("the download places 8.8.8.8 in no country");
    }
    Ok(db)
}

/// Loopback, private and link-local ranges, which belong to no country and
/// always pass the country rules.
const ALWAYS_V4: [&str; 6] = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10"];
const ALWAYS_V6: [&str; 3] = ["::1/128", "fc00::/7", "fe80::/10"];

/// What the country rules do with the listed countries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// Drop the listed countries.
    Block,
    /// Drop every country but the listed ones.
    Allow,
}

/// The country rules, checked: what they do, to which countries, on which
/// TCP ports, and the networks that always pass.
#[derive(Debug)]
pub struct RuleInput {
    pub rule: Rule,
    /// ISO 3166 codes in capitals.
    pub codes: Vec<String>,
    pub ports: Vec<u16>,
    /// Networks in canonical form, each once.
    pub exempt: Vec<String>,
    /// Why each never-ban entry the firewall cannot use, such as a host
    /// name, is missing from `exempt`.
    pub skipped: Vec<String>,
}

/// The items of a list separated by commas or white space.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty())
}

fn push_once(list: &mut Vec<String>, item: String) {
    if !list.contains(&item) {
        list.push(item);
    }
}

/// Checks the country rules the entrypoint asks for. `rule` is block or
/// allow, `codes` two-letter country codes, and `ports` the TCP ports the
/// rules guard. `trusted` is WEBUI_TRUSTED_NETWORKS, every entry of which
/// must be a network. `never_ban` is fail2ban's ignoreip, read as fail2ban
/// reads it: host bits are cleared, and an entry that is no address or
/// network is left out, with the reason in `skipped`.
pub fn rule_input(rule: &str, codes: &str, ports: &str, trusted: &str, never_ban: &str) -> Result<RuleInput> {
    let rule = match rule {
        "block" => Rule::Block,
        "allow" => Rule::Allow,
        other => bail!("the country rule {other} is neither block nor allow"),
    };
    let codes: Vec<String> = words(codes).map(str::to_ascii_uppercase).collect();
    if let Some(bad) = codes.iter().find(|c| !valid_code(c)) {
        bail!("{bad} is not a two-letter country code");
    }
    if rule == Rule::Allow && codes.is_empty() {
        bail!("allowing only listed countries needs at least one country");
    }
    let mut port_list = Vec::new();
    for word in words(ports) {
        if !word.bytes().all(|b| b.is_ascii_digit()) {
            bail!("{word} is not a port number");
        }
        let port: u16 = word.parse().with_context(|| format!("{word} is not a port number"))?;
        if port == 0 {
            bail!("{word} is not a port number");
        }
        if !port_list.contains(&port) {
            port_list.push(port);
        }
    }
    if port_list.is_empty() {
        bail!("the country rules need a port to guard");
    }
    let mut exempt = Vec::new();
    for word in words(trusted) {
        let net = Network::parse(word).map_err(|e| anyhow::anyhow!("WEBUI_TRUSTED_NETWORKS: {e}"))?;
        push_once(&mut exempt, net.to_string());
    }
    let mut skipped = Vec::new();
    for word in words(never_ban) {
        match Network::parse_masked(word) {
            Ok(net) => push_once(&mut exempt, net.to_string()),
            Err(why) => skipped.push(why),
        }
    }
    Ok(RuleInput { rule, codes, ports: port_list, exempt, skipped })
}

/// The country rules in force, as the entrypoint recorded them.
#[derive(Debug)]
pub struct RuleState {
    pub input: RuleInput,
    /// What the firewall said when it refused the rules; None when it
    /// enforces them.
    pub refused: Option<String>,
}

/// Reads the entrypoint's record of the country rules: key=value lines
/// giving enforced (yes, or "no: " and why) and the rule, countries, ports,
/// trusted and never_ban it handed to `country-rules`, which are read as
/// `rule_input` reads them. None when the file is absent.
pub fn read_state(path: &Path) -> Result<Option<RuleState>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let field = |key: &str| -> Result<&str> {
        text.lines()
            .find_map(|line| line.strip_prefix(key).and_then(|rest| rest.strip_prefix('=')))
            .with_context(|| format!("{} has no {key}", path.display()))
    };
    let input = rule_input(field("rule")?, field("countries")?, field("ports")?, field("trusted")?, field("never_ban")?)?;
    let refused = match field("enforced")? {
        "yes" => None,
        other => Some(match other.strip_prefix("no: ") {
            Some(why) => why.to_string(),
            None => other.to_string(),
        }),
    };
    Ok(Some(RuleState { input, refused }))
}

/// The country rules as the web servers apply them to each request.
#[derive(Debug)]
pub struct Gate {
    rule: Rule,
    codes: Vec<String>,
    exempt: Vec<Network>,
}

impl Gate {
    /// The rules in `input`. With none, the gate for when the rules in force
    /// cannot be read, which lets in only loopback, private and link-local
    /// addresses.
    pub fn new(input: Option<&RuleInput>) -> Result<Gate> {
        let extra: &[String] = match input {
            Some(i) => &i.exempt,
            None => &[],
        };
        let mut exempt = Vec::new();
        for text in ALWAYS_V4.iter().chain(ALWAYS_V6.iter()).copied().chain(extra.iter().map(String::as_str)) {
            exempt.push(Network::parse(text).map_err(anyhow::Error::msg)?);
        }
        Ok(match input {
            Some(i) => Gate { rule: i.rule, codes: i.codes.clone(), exempt },
            None => Gate { rule: Rule::Allow, codes: Vec::new(), exempt },
        })
    }

    /// A gate that lets no one in, for when even `new` fails.
    pub fn sealed() -> Gate {
        Gate { rule: Rule::Allow, codes: Vec::new(), exempt: Vec::new() }
    }

    /// Whether `ip`, which the database places in `country`, may connect, as
    /// the firewall decides: the exempt networks always may; block refuses
    /// the listed countries, and allow every other one, no country included.
    pub fn admits(&self, ip: IpAddr, country: Option<&str>) -> bool {
        if crate::net::any_contains(&self.exempt, ip) {
            return true;
        }
        let listed = country.is_some_and(|c| self.codes.iter().any(|l| l.eq_ignore_ascii_case(c)));
        match self.rule {
            Rule::Block => !listed,
            Rule::Allow => listed,
        }
    }
}

/// The table that holds the country rules.
const TABLE: &str = "inet sftp_countries";

/// Elements per nft script, and per set of listed networks. A script is one
/// netlink batch, which must fit the socket's send buffer, and a container
/// in a user namespace cannot raise that buffer past the host's
/// net.core.wmem_max: there, with the default limit, a batch of about 5,600
/// ranges loads and one of about 11,000 does not. nft reads a set's
/// elements back before each batch it adds to the set, so each batch of
/// listed networks fills a set of its own.
const BATCH: usize = 4000;

/// One of the table's two generations of sets. A reload fills the
/// generation the rules do not read, points the rules at it in one
/// transaction, then deletes the other, so the rules in force only ever
/// read whole sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    A,
    B,
}

impl Generation {
    /// What the names of the generation's sets begin with.
    fn prefix(self) -> &'static str {
        match self {
            Generation::A => "a_",
            Generation::B => "b_",
        }
    }
}

/// The table as `nft -t list table inet sftp_countries` shows it: the names
/// of its sets, and the generation its rules read.
#[derive(Debug, Default)]
pub struct Loaded {
    pub sets: Vec<String>,
    pub live: Option<Generation>,
}

/// Reads a terse listing of the table.
pub fn read_listing(listing: &str) -> Loaded {
    let sets = listing
        .lines()
        .filter_map(|l| l.trim().strip_prefix("set "))
        .filter_map(|rest| rest.split_whitespace().next())
        .map(str::to_string)
        .collect();
    let live = if listing.contains("@a_exempt4") {
        Some(Generation::A)
    } else if listing.contains("@b_exempt4") {
        Some(Generation::B)
    } else {
        None
    };
    Loaded { sets, live }
}

/// Points the rules at the sets whose names begin with `p`, `listed4` and
/// `listed6` among them, in one transaction.
fn rules(rule: Rule, p: &str, listed4: &[String], listed6: &[String]) -> String {
    let mut s = format!(
        "flush chain {TABLE} input\n\
         add rule {TABLE} input ct state established,related accept\n\
         add rule {TABLE} input iifname \"lo\" accept\n\
         add rule {TABLE} input ip saddr @{p}exempt4 accept\n\
         add rule {TABLE} input ip6 saddr @{p}exempt6 accept\n"
    );
    match rule {
        Rule::Block => {
            for name in listed4 {
                s.push_str(&format!("add rule {TABLE} input ip saddr @{name} tcp dport @{p}ports drop\n"));
            }
            for name in listed6 {
                s.push_str(&format!("add rule {TABLE} input ip6 saddr @{name} tcp dport @{p}ports drop\n"));
            }
        }
        Rule::Allow => {
            for name in listed4 {
                s.push_str(&format!("add rule {TABLE} input ip saddr @{name} accept\n"));
            }
            for name in listed6 {
                s.push_str(&format!("add rule {TABLE} input ip6 saddr @{name} accept\n"));
            }
            s.push_str(&format!("add rule {TABLE} input tcp dport @{p}ports drop\n"));
        }
    }
    s
}

/// `networks`, all of one family, as the fewest ranges that cover the same
/// addresses, in order: overlapping and adjacent networks join, and a range
/// is written as a network where it is one, else as first-last.
pub fn ranges(networks: &[String]) -> Result<Vec<String>> {
    let mut family = None;
    let mut spans = Vec::with_capacity(networks.len());
    for text in networks {
        let (v4, first, last) = Network::parse(text).map_err(anyhow::Error::msg)?.span();
        match family {
            Some(f) if f != v4 => bail!("{text} is not of the same family as the networks before it"),
            Some(_) => {}
            None => family = Some(v4),
        }
        spans.push((first, last));
    }
    spans.sort_unstable();
    let mut joined: Vec<(u128, u128)> = Vec::with_capacity(spans.len());
    for (first, last) in spans {
        match joined.last_mut() {
            Some(prev) if first <= prev.1.saturating_add(1) => prev.1 = prev.1.max(last),
            Some(_) | None => joined.push((first, last)),
        }
    }
    let v4 = family == Some(true);
    Ok(joined.into_iter().map(|(first, last)| range_text(v4, first, last)).collect())
}

/// The addresses from `first` to `last` as nft writes them: a network when
/// they are one, else first-last.
fn range_text(v4: bool, first: u128, last: u128) -> String {
    let addr = |n: u128| if v4 { IpAddr::V4(std::net::Ipv4Addr::from(n as u32)) } else { IpAddr::V6(std::net::Ipv6Addr::from(n)) };
    let host = last - first;
    if host & host.wrapping_add(1) == 0 && first & host == 0 {
        let bits = if v4 { 32 } else { 128 };
        format!("{}/{}", addr(first), bits - host.count_ones())
    } else {
        format!("{}-{}", addr(first), addr(last))
    }
}

/// The nftables scripts that load the country rules into the table, in
/// order, each one transaction, given what the table holds now. New TCP
/// connections to the guarded ports are dropped when they come from `v4`
/// and `v6`, the listed countries' networks as `ranges` joins them (block),
/// or from anywhere else (allow). Established connections, loopback,
/// private ranges and the exempt networks always pass, and other ports are
/// left alone.
///
/// The first script makes the table and chain where missing and deletes
/// every set the rules do not read. The new generation's sets follow: the
/// ports and exempt networks, which merge what overlaps as it is added, and
/// the listed networks, BATCH to a set. One script then points the rules at
/// them, and the last deletes the generation they read before.
pub fn nft_loads(input: &RuleInput, v4: &[String], v6: &[String], loaded: &Loaded) -> Vec<String> {
    let new = match loaded.live {
        Some(Generation::A) => Generation::B,
        Some(Generation::B) | None => Generation::A,
    };
    let p = new.prefix();
    let old = loaded.live.map(Generation::prefix);
    let mut first = format!("table {TABLE} {{\n    chain input {{ type filter hook input priority filter - 10; policy accept; }}\n}}\n");
    for name in &loaded.sets {
        if old.is_none_or(|o| !name.starts_with(o)) {
            first.push_str(&format!("delete set {TABLE} {name}\n"));
        }
    }
    let mut loads = vec![first];

    let mut e4: Vec<String> = ALWAYS_V4.iter().map(|n| n.to_string()).collect();
    let mut e6: Vec<String> = ALWAYS_V6.iter().map(|n| n.to_string()).collect();
    for net in &input.exempt {
        push_once(if net.contains(':') { &mut e6 } else { &mut e4 }, net.clone());
    }
    let ports: Vec<String> = input.ports.iter().map(u16::to_string).collect();
    let mut script = format!(
        "add set {TABLE} {p}ports {{ type inet_service; }}\n\
         add set {TABLE} {p}exempt4 {{ type ipv4_addr; flags interval; auto-merge; }}\n\
         add set {TABLE} {p}exempt6 {{ type ipv6_addr; flags interval; auto-merge; }}\n"
    );
    let mut count = 0;
    for (name, items) in [("ports", &ports), ("exempt4", &e4), ("exempt6", &e6)] {
        for chunk in items.chunks(BATCH) {
            if count + chunk.len() > BATCH {
                loads.push(std::mem::take(&mut script));
                count = 0;
            }
            script.push_str(&format!("add element {TABLE} {p}{name} {{ {} }}\n", chunk.join(", ")));
            count += chunk.len();
        }
    }
    loads.push(script);

    let mut listed: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    for (i, (family, kind, items)) in [("4", "ipv4_addr", v4), ("6", "ipv6_addr", v6)].into_iter().enumerate() {
        for (k, chunk) in items.chunks(BATCH).enumerate() {
            let name = format!("{p}listed{family}_{k}");
            loads.push(format!(
                "add set {TABLE} {name} {{ type {kind}; flags interval; }}\nadd element {TABLE} {name} {{ {} }}\n",
                chunk.join(", ")
            ));
            listed[i].push(name);
        }
    }
    loads.push(rules(input.rule, p, &listed[0], &listed[1]));

    if let Some(o) = old {
        let gone: String = loaded.sets.iter().filter(|n| n.starts_with(o)).map(|n| format!("delete set {TABLE} {n}\n")).collect();
        if !gone.is_empty() {
            loads.push(gone);
        }
    }
    loads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_rules_and_reads_never_ban_entries_as_fail2ban_does() {
        let input = rule_input("block", "cn, ru", "22 8443 22", "203.0.113.0/24", "127.0.0.1/8 ::1 2001:db8::/32 host.example")
            .expect("valid rules");
        assert_eq!(input.rule, Rule::Block);
        assert_eq!(input.codes, ["CN", "RU"]);
        assert_eq!(input.ports, [22, 8443]);
        assert_eq!(input.exempt, ["203.0.113.0/24", "127.0.0.0/8", "::1/128", "2001:db8::/32"]);
        assert_eq!(input.skipped.len(), 1);
        assert!(input.skipped[0].starts_with("host.example "), "{:?}", input.skipped);
        assert!(rule_input("off", "CN", "22", "", "").is_err());
        assert!(rule_input("allow", "", "22", "", "").is_err(), "allowing no country would close every guarded port");
        assert!(rule_input("block", "", "22", "", "").is_ok(), "blocking no country drops nothing");
        for bad in ["CHN", "C1", "C"] {
            assert!(rule_input("block", bad, "22", "", "").is_err(), "{bad}");
        }
        for bad in ["", "0", "+22", "65536", "22a"] {
            assert!(rule_input("block", "CN", bad, "", "").is_err(), "port {bad:?}");
        }
        assert!(rule_input("block", "CN", "22", "10.0.0.1/8", "").is_err(), "trusted networks are read strictly");
        assert!(valid_code("cn") && valid_code("US") && !valid_code("USA") && !valid_code("1A"));
    }

    /// The sets `script` adds elements to, empties or deletes.
    fn changed(script: &str) -> Vec<String> {
        let mut names = Vec::new();
        for line in script.lines() {
            for verb in ["add element ", "flush set ", "delete set "] {
                if let Some(rest) = line.strip_prefix(verb).and_then(|r| r.strip_prefix("inet sftp_countries ")) {
                    names.push(rest.split_whitespace().next().expect("a set name").to_string());
                }
            }
        }
        names
    }

    fn many(count: usize) -> (Vec<String>, Vec<String>) {
        let v4 = (0..count).map(|i| format!("1.{}.{}.0/24", i / 256 % 256, i % 256)).collect();
        let v6 = (0..count / 2).map(|i| format!("2001:db8:{i:x}::/48")).collect();
        (v4, v6)
    }

    #[test]
    fn never_changes_a_set_the_rules_in_force_read() {
        let (v4, v6) = many(9000);
        let input = rule_input("block", "CN", "22 8443", "203.0.113.0/24", "127.0.0.1/8 2001:db8::/32").expect("valid rules");
        let names = |p: &str| ["ports", "exempt4", "exempt6", "listed4_0", "listed4_1", "listed6_0"].map(|n| format!("{p}{n}")).to_vec();
        let mut stray = names("b_");
        stray.push("a_listed4_7".to_string());
        let starts = [
            Loaded::default(),
            Loaded { sets: names("a_"), live: Some(Generation::A) },
            Loaded { sets: names("b_"), live: Some(Generation::B) },
            Loaded { sets: stray, live: Some(Generation::B) },
            Loaded { sets: names("a_"), live: None },
        ];
        for start in &starts {
            let loads = nft_loads(&input, &v4, &v6, start);
            let mut live = start.live;
            for script in &loads {
                if script.starts_with("flush chain") {
                    live = read_listing(script).live;
                    assert!(live.is_some(), "the rules read a generation: {script}");
                    continue;
                }
                if let Some(now) = live {
                    for name in changed(script) {
                        assert!(!name.starts_with(now.prefix()), "from {start:?}, a script changes {name}, which the rules read: {script}");
                    }
                }
            }
            let new = if start.live == Some(Generation::A) { Generation::B } else { Generation::A };
            assert_eq!(live, Some(new), "from {start:?}, the rules end on the other generation");
            let deleted: Vec<&str> =
                loads.iter().flat_map(|s| s.lines()).filter_map(|l| l.strip_prefix("delete set inet sftp_countries ")).collect();
            for name in &start.sets {
                assert!(deleted.contains(&name.as_str()), "from {start:?}, {name} is deleted");
            }
        }
    }

    #[test]
    fn loads_every_network_once_in_batches_the_kernel_takes() {
        let (v4, v6) = many(9000);
        let input = rule_input("block", "CN", "22", "", "").expect("valid rules");
        let loads = nft_loads(&input, &v4, &v6, &Loaded::default());
        let mut loaded4 = Vec::new();
        let mut sets_filled: Vec<String> = Vec::new();
        for script in &loads {
            let mut count = 0;
            for line in script.lines().filter_map(|l| l.strip_prefix("add element inet sftp_countries ")) {
                let (set, rest) = line.split_once(' ').expect("a set and its elements");
                let items: Vec<&str> = rest.trim_start_matches("{ ").trim_end_matches(" }").split(", ").collect();
                count += items.len();
                if set.contains("listed") {
                    assert!(!sets_filled.contains(&set.to_string()), "{set} is filled by one script only");
                    assert!(script.contains(&format!("add set inet sftp_countries {set} ")), "{set} is made by the script that fills it");
                    sets_filled.push(set.to_string());
                }
                if set.starts_with("a_listed4_") {
                    loaded4.extend(items.iter().map(|i| i.to_string()));
                }
            }
            assert!(count <= BATCH, "{count} elements in one script");
        }
        assert_eq!(loaded4, v4, "every network once, in order");
        assert_eq!(sets_filled, ["a_listed4_0", "a_listed4_1", "a_listed4_2", "a_listed6_0", "a_listed6_1"]);
    }

    #[test]
    fn joins_networks_into_the_fewest_ranges() {
        let texts = |list: &[&str]| list.iter().map(|s| s.to_string()).collect::<Vec<String>>();
        let v4 = texts(&["10.0.1.0/24", "192.0.2.64/26", "10.0.0.0/24", "10.0.3.0/24", "10.0.2.128/25", "10.0.2.0/25", "192.0.2.0/24"]);
        assert_eq!(ranges(&v4).expect("networks"), ["10.0.0.0/22", "192.0.2.0/24"]);
        assert_eq!(ranges(&texts(&["1.0.0.0/24", "1.0.2.0/24", "1.0.1.0/24", "1.0.4.0/32"])).expect("networks"), ["1.0.0.0-1.0.2.255", "1.0.4.0/32"]);
        assert_eq!(ranges(&texts(&["2001:db8:8000::/33", "2001:db8::/33"])).expect("networks"), ["2001:db8::/32"]);
        assert_eq!(ranges(&texts(&["::/0", "2001:db8::/32"])).expect("networks"), ["::/0"]);
        assert_eq!(ranges(&texts(&["0.0.0.0/0"])).expect("networks"), ["0.0.0.0/0"]);
        assert!(ranges(&[]).expect("no networks").is_empty());
        assert!(ranges(&texts(&["10.0.0.0/8", "2001:db8::/32"])).is_err(), "one family to a list");
        assert!(ranges(&texts(&["10.0.0.1/8"])).is_err(), "a network with host bits set is refused");
    }

    #[test]
    fn reads_the_sets_and_the_generation_the_rules_read() {
        let listing = "table inet sftp_countries {\n\tset b_ports {\n\t\ttype inet_service\n\t}\n\tset b_exempt4 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\tauto-merge\n\t}\n\tset b_listed4_0 {\n\t\ttype ipv4_addr\n\t\tflags interval\n\t}\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n\t\tct state established,related accept\n\t\tip saddr @b_exempt4 accept\n\t\tip saddr @b_listed4_0 tcp dport @b_ports drop\n\t}\n}\n";
        let loaded = read_listing(listing);
        assert_eq!(loaded.sets, ["b_ports", "b_exempt4", "b_listed4_0"]);
        assert_eq!(loaded.live, Some(Generation::B));
        assert_eq!(read_listing(&listing.replace("b_", "a_")).live, Some(Generation::A));
        let idle = read_listing("table inet sftp_countries {\n\tset a_ports {\n\t\ttype inet_service\n\t}\n\tchain input {\n\t\ttype filter hook input priority filter - 10; policy accept;\n\t}\n}\n");
        assert_eq!((idle.sets.len(), idle.live), (1, None));
    }

    #[test]
    fn the_rules_drop_the_right_side_on_the_guarded_ports_only() {
        let v4 = vec!["1.0.1.0/24".to_string()];
        let input = rule_input("block", "CN", "22 8443", "203.0.113.0/24", "127.0.0.1/8 2001:db8::/32").expect("valid rules");
        let loads = nft_loads(&input, &v4, &[], &Loaded::default());
        let all = loads.concat();
        assert!(all.contains("add element inet sftp_countries a_ports { 22, 8443 }\n"));
        assert!(all.contains("add element inet sftp_countries a_listed4_0 { 1.0.1.0/24 }\n"));
        assert!(!all.contains("a_listed6"), "no IPv6 networks, no IPv6 set");
        assert_eq!(all.matches("127.0.0.0/8").count(), 1, "a network that always passes is listed once");
        assert!(all.contains("203.0.113.0/24") && all.contains("2001:db8::/32") && all.contains("10.0.0.0/8"));
        let block = loads.iter().find(|s| s.starts_with("flush chain")).expect("the rules");
        let drops: Vec<&str> = block.lines().filter(|l| l.ends_with(" drop")).collect();
        assert_eq!(drops, ["add rule inet sftp_countries input ip saddr @a_listed4_0 tcp dport @a_ports drop"]);
        let (many4, many6) = many(9000);
        let allow_loads = nft_loads(&rule_input("allow", "US", "22", "", "").expect("valid rules"), &many4, &many6, &Loaded::default());
        let allow = allow_loads.iter().find(|s| s.starts_with("flush chain")).expect("the rules");
        let lines: Vec<&str> = allow.lines().collect();
        assert_eq!(lines.iter().filter(|l| l.ends_with(" accept") && l.contains("@a_listed")).count(), 5, "each listed set lets its networks in");
        assert_eq!(lines[lines.len() - 1], "add rule inet sftp_countries input tcp dport @a_ports drop", "everything else is dropped last");
        let exempt = allow.find("ip saddr @a_exempt4 accept").expect("the exempt rule");
        assert!(exempt < allow.find("@a_listed4_0").expect("a listed rule"), "exempt networks pass first");
        assert_eq!(lines.iter().filter(|l| l.ends_with(" drop")).count(), 1);
    }

    #[test]
    fn the_web_servers_admit_as_the_firewall_does() {
        let ip = |s: &str| s.parse::<IpAddr>().expect("an address");
        let input = rule_input("block", "CN", "8443", "203.0.113.0/24", "").expect("valid rules");
        let block = Gate::new(Some(&input)).expect("a gate");
        assert!(!block.admits(ip("1.0.1.1"), Some("CN")));
        assert!(block.admits(ip("8.8.8.8"), Some("US")));
        assert!(block.admits(ip("198.51.100.1"), None), "block lets in an address in no country");
        assert!(block.admits(ip("203.0.113.9"), Some("CN")), "an exempt network passes");
        assert!(block.admits(ip("192.168.1.5"), Some("CN")) && block.admits(ip("::ffff:10.0.0.1"), Some("CN")), "private ranges pass");
        let allow = Gate::new(Some(&rule_input("allow", "US", "8443", "", "").expect("valid rules"))).expect("a gate");
        assert!(allow.admits(ip("8.8.8.8"), Some("US")) && !allow.admits(ip("1.0.1.1"), Some("CN")));
        assert!(!allow.admits(ip("198.51.100.1"), None), "allow refuses an address in no country");
        let closed = Gate::new(None).expect("a gate");
        assert!(closed.admits(ip("127.0.0.1"), None) && closed.admits(ip("fe80::1"), None));
        assert!(!closed.admits(ip("8.8.8.8"), Some("US")), "unreadable rules let in only private ranges");
        assert!(!Gate::sealed().admits(ip("127.0.0.1"), None));
    }

    /// A tar.gz holding each (name, kind, content), as GNU tar writes one.
    fn tar_gz(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut tar = Vec::new();
        for (name, kind, content) in entries {
            let mut header = vec![0u8; 512];
            header[..name.len()].copy_from_slice(name.as_bytes());
            header[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
            header[156] = *kind;
            tar.extend_from_slice(&header);
            tar.extend_from_slice(content);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar).expect("compressed in memory");
        gz.finish().expect("compressed in memory")
    }

    #[test]
    fn finds_the_database_in_maxminds_archive() {
        let data = vec![7u8; 1500];
        let archive = tar_gz(&[
            ("GeoLite2-Country_20261124/", b'5', b""),
            ("GeoLite2-Country_20261124/COPYRIGHT.txt", b'0', b"Database and Contents Copyright (c) MaxMind, Inc."),
            ("GeoLite2-Country_20261124/GeoLite2-Country.mmdb", b'0', &data),
        ]);
        assert_eq!(mmdb_from_tar_gz(&archive).expect("the database"), data);
        let none = tar_gz(&[("GeoLite2-Country_20261124/LICENSE.txt", b'0', b"license")]);
        assert!(mmdb_from_tar_gz(&none).is_err(), "an archive without the database is refused");
        let mut cut = tar_gz(&[("GeoLite2-Country.mmdb", b'0', &data)]);
        cut.truncate(cut.len() / 2);
        assert!(mmdb_from_tar_gz(&cut).is_err(), "a cut-off download is refused");
        assert!(mmdb_from_tar_gz(b"not gzip").is_err());
        assert!(check_download(data).is_err(), "bytes that are no database are refused");
    }

    #[test]
    fn reads_the_entrypoints_record() {
        let dir = std::env::temp_dir().join(format!("sftp-geo-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        let path = dir.join("country-rules");
        assert!(read_state(&path).expect("no record is no error").is_none(), "an absent record means the rule is off");
        let record = |enforced: &str| {
            format!("enforced={enforced}\nrule=block\ncountries=CN RU\nports=22 8443\ntrusted=\nnever_ban=127.0.0.1/8 ::1 gateway.example\n")
        };
        std::fs::write(&path, record("yes")).expect("a record");
        let state = read_state(&path).expect("a valid record").expect("a rule in force");
        assert_eq!(state.refused, None);
        assert_eq!((state.input.rule, state.input.codes.len(), state.input.ports.len()), (Rule::Block, 2, 2));
        assert_eq!(state.input.skipped.len(), 1, "the host name is not exempt");
        std::fs::write(&path, record("no: Operation not permitted")).expect("a record");
        let state = read_state(&path).expect("a valid record").expect("a rule in force");
        assert_eq!(state.refused.as_deref(), Some("Operation not permitted"));
        std::fs::write(&path, "enforced=yes\nrule=block\n").expect("a record");
        assert!(read_state(&path).is_err(), "a record missing a field is refused");
        std::fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    }

    /// Needs a country database: SFTP_GEO_DB=/path/to/dbip-country-lite.mmdb.
    #[test]
    #[ignore = "needs a country database named by SFTP_GEO_DB"]
    fn finds_countries() {
        let path = std::env::var("SFTP_GEO_DB").expect("SFTP_GEO_DB names a country database");
        let db = Countries::open(Path::new(&path)).expect("the database opens");
        assert!(db.kind().contains("Country"), "{}", db.kind());
        let ip = |s: &str| s.parse::<IpAddr>().expect("an address");
        let code = |s: &str| db.lookup(ip(s)).expect("a lookup");
        for public in ["8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"] {
            let found = code(public).expect("a public address has a country");
            assert!(found.len() == 2 && found.bytes().all(|b| b.is_ascii_uppercase()), "{public}: {found}");
        }
        assert_eq!(code("10.0.0.1"), None);
        let started = std::time::Instant::now();
        let (v4, v6) = db.networks(&["cn".to_string()]).expect("the networks of a country");
        eprintln!("CN: {} IPv4 and {} IPv6 networks in {:?}", v4.len(), v6.len(), started.elapsed());
        assert!(!v4.is_empty() && !v6.is_empty());
        for net in [&v4[0], &v4[v4.len() / 2], &v6[0]] {
            let first = net.split('/').next().expect("a network address");
            assert_eq!(code(first).as_deref(), Some("CN"), "{net}");
        }
        let names = db.names().expect("the countries' names");
        eprintln!("{} countries named", names.len());
        assert!(names.len() > 200, "{} countries", names.len());
        assert!(names.iter().any(|(code, name)| code == "CN" && name == "China"));
        assert!(names.windows(2).all(|w| w[0].0 < w[1].0), "sorted by code, each once");
        let bytes = std::fs::read(&path).expect("the database's bytes");
        let archive = tar_gz(&[("GeoLite2-Country_20261124/GeoLite2-Country.mmdb", b'0', &bytes)]);
        let checked = check_download(mmdb_from_tar_gz(&archive).expect("the database")).expect("a country database");
        assert!(checked.built() > 1_600_000_000, "built {}", checked.built());
    }
}
