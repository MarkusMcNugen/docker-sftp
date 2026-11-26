//! IPv4 and IPv6 addresses and networks.

use std::fmt;
use std::net::IpAddr;

/// A network with no host bits set, such as `10.0.0.0/8` or `2001:db8::/32`.
/// A bare address is a network of one address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Network {
    addr: IpAddr,
    prefix: u8,
}

impl Network {
    pub fn parse(text: &str) -> Result<Network, String> {
        let text = text.trim();
        let (addr, prefix) = parts(text)?;
        let masked = mask(addr, prefix);
        if masked != addr {
            return Err(format!("{text} has host bits set; the network is {masked}/{prefix}"));
        }
        Ok(Network { addr, prefix })
    }

    /// The network `text` names with its host bits cleared, as fail2ban
    /// reads its own default `127.0.0.1/8` as 127.0.0.0/8.
    pub fn parse_masked(text: &str) -> Result<Network, String> {
        let (addr, prefix) = parts(text.trim())?;
        Ok(Network { addr: mask(addr, prefix), prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        if ip.is_ipv4() != self.addr.is_ipv4() {
            return false;
        }
        mask(ip, self.prefix) == self.addr
    }

    /// Whether the network is IPv4, and its first and last addresses as
    /// numbers.
    pub fn span(&self) -> (bool, u128, u128) {
        match self.addr {
            IpAddr::V4(a) => {
                let first = u128::from(u32::from(a));
                (true, first, first + (1u128 << (32 - u32::from(self.prefix))) - 1)
            }
            IpAddr::V6(a) => {
                let first = u128::from(a);
                let host = 128 - u32::from(self.prefix);
                let last = if host == 128 { u128::MAX } else { first | ((1u128 << host) - 1) };
                (false, first, last)
            }
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// The address and prefix length of `address` or `address/length`; a bare
/// address has the full length.
fn parts(text: &str) -> Result<(IpAddr, u8), String> {
    let (addr_text, prefix_text) = match text.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (text, None),
    };
    let addr: IpAddr = match addr_text.parse() {
        Ok(a) => a,
        Err(e) => return Err(format!("{text} is not an address or network: {e}")),
    };
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        None => max,
        Some(p) => {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("{text} is not an address or network: bad prefix length"));
            }
            let n: u8 = match p.parse() {
                Ok(n) => n,
                Err(e) => return Err(format!("{text} is not an address or network: {e}")),
            };
            if n > max {
                return Err(format!("{text}: the prefix length can be at most {max}"));
            }
            n
        }
    };
    Ok((addr, prefix))
}

/// An IPv4 address carried in IPv6 as `::ffff:a.b.c.d` becomes plain IPv4.
pub fn canonical(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

/// Parses networks separated by commas or white space.
pub fn parse_list(text: &str) -> Result<Vec<Network>, String> {
    let mut nets = Vec::new();
    for item in text.split(|c: char| c == ',' || c.is_whitespace()) {
        if item.is_empty() {
            continue;
        }
        nets.push(Network::parse(item)?);
    }
    Ok(nets)
}

pub fn any_contains(nets: &[Network], ip: IpAddr) -> bool {
    nets.iter().any(|n| n.contains(ip))
}

fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let m = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) };
            IpAddr::V4((bits & m).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let m = if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix)) };
            IpAddr::V6((bits & m).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_matches() {
        let net = Network::parse("10.0.0.0/8").expect("valid");
        assert!(net.contains("10.1.2.3".parse().expect("ip")));
        assert!(!net.contains("11.0.0.1".parse().expect("ip")));
        assert!(net.contains("::ffff:10.9.9.9".parse().expect("ip")));
        let six = Network::parse("2001:db8::/32").expect("valid");
        assert!(six.contains("2001:db8::5".parse().expect("ip")));
        assert_eq!(Network::parse("192.0.2.7").expect("valid").to_string(), "192.0.2.7/32");
        assert!(Network::parse("0.0.0.0/0").expect("valid").contains("8.8.8.8".parse().expect("ip")));
    }

    #[test]
    fn refuses_host_bits_and_garbage() {
        assert!(Network::parse("10.0.0.1/8").is_err());
        assert!(Network::parse("10.0.0.0/33").is_err());
        assert!(Network::parse("example.com").is_err());
        assert!(Network::parse("10.0.0.0/").is_err());
        assert!(Network::parse("10.0.0.0/+8").is_err());
    }

    #[test]
    fn reads_host_bits_as_fail2ban_does() {
        assert_eq!(Network::parse_masked("127.0.0.1/8").expect("valid").to_string(), "127.0.0.0/8");
        assert_eq!(Network::parse_masked("2001:db8::7/32").expect("valid").to_string(), "2001:db8::/32");
        assert_eq!(Network::parse_masked(" ::1 ").expect("valid").to_string(), "::1/128");
        assert!(Network::parse_masked("host.example").is_err());
        assert!(Network::parse_masked("10.0.0.0/33").is_err());
    }
}
