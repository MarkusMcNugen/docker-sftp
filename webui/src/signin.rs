//! Whether a sign-in goes ahead. A sign-in from an unusual place, a country
//! the account has not signed in from or one too far from its last sign-in
//! for the time between, is held for an admin's approval once the account's
//! profile has enough sign-ins. While a password spray goes on, failed
//! sign-ins for one account from several addresses within a window, the
//! account is locked to the networks of its approved sign-ins.

use std::collections::HashSet;
use std::net::IpAddr;

/// The helper's answer to a file browser sign-in held for approval. The
/// web server matches it, so a held sign-in never counts as a failed one.
pub const HELD: &str = "this sign-in is held until an admin approves it, as it does not match where this account signs in from; \
                        try again once it is approved";

/// The helper's answer to a file browser sign-in refused by a lockdown,
/// matched the same way.
pub const LOCKED: &str = "this account is locked down after failed sign-ins from many addresses, so only networks it has \
                          signed in from before can sign in; an admin can lift the lockdown";

/// The thresholds, which the Settings page sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rules {
    /// Approved sign-ins an account needs before holds start.
    pub learn_signins: u32,
    /// Days from an account's first approved sign-in before holds start.
    pub learn_days: u32,
    /// Speed in km/h above which two sign-ins from different countries
    /// count as impossible travel.
    pub travel_kmh: u32,
    /// Different failing addresses that lock an account down.
    pub spray_addresses: u32,
    /// Minutes those failures must fall within.
    pub spray_minutes: u32,
    /// Hours without a failed sign-in after which a lockdown ends.
    pub lockdown_quiet_hours: u32,
}

impl Default for Rules {
    fn default() -> Rules {
        Rules {
            learn_signins: 5,
            learn_days: 7,
            travel_kmh: 750,
            spray_addresses: 3,
            spray_minutes: 60,
            lockdown_quiet_hours: 24,
        }
    }
}

/// Where a sign-in comes from, as far as the rules are concerned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Place {
    /// Loopback: the file browser's own session, checked at its sign-in.
    FileBrowser,
    /// A private, shared or link-local network, which has no country.
    Local,
    /// A public address in a country, by its two-letter code.
    Country(String),
    /// A public address the country database does not place.
    Unknown,
}

/// The place of `ip`, given the country the database finds for it.
pub fn place_of(ip: IpAddr, country: Option<&str>) -> Place {
    let ip = crate::net::canonical(ip);
    if ip.is_loopback() {
        return Place::FileBrowser;
    }
    let local = match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_unique_local() || v6.is_unicast_link_local(),
    };
    if local {
        return Place::Local;
    }
    match country {
        Some(code) => Place::Country(code.to_ascii_uppercase()),
        None => Place::Unknown,
    }
}

/// One approved sign-in of an account, which its profile learns from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    pub time: u64,
    pub address: IpAddr,
    pub place: Place,
}

/// Why a sign-in is held.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hold {
    /// A place the account has not signed in from.
    NewPlace,
    /// Too far from the account's last sign-in, in `from`, for the time
    /// between, at `kmh`.
    ImpossibleTravel { from: String, kmh: u64 },
}

/// What happens to a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision {
    /// It goes ahead and joins the profile.
    Allow,
    /// It waits for an admin's approval.
    Hold(Hold),
    /// The account is locked down and the address is not one of its trusted
    /// networks.
    Refuse,
}

/// The network a trusted address stands for: its /24 for IPv4, its /64 for
/// IPv6.
fn network(ip: IpAddr) -> IpAddr {
    match crate::net::canonical(ip) {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            IpAddr::from([a, b, c, 0])
        }
        IpAddr::V6(v6) => {
            let mut bytes = v6.octets();
            bytes[8..].fill(0);
            IpAddr::from(bytes)
        }
    }
}

/// True when `ip` is in the network of one of the approved sign-ins.
pub fn trusted(ip: IpAddr, seen: &[Seen]) -> bool {
    let net = network(ip);
    seen.iter().any(|s| network(s.address) == net)
}

/// When the account's current lockdown began, or None when it is not
/// locked down. `failures` are its failed sign-ins, oldest first. A lockdown
/// starts at the failure that brings `spray_addresses` different addresses
/// within `spray_minutes`, and lasts until `lockdown_quiet_hours` pass with
/// no failure. Failures at or before `lifted`, when an admin lifted the last
/// lockdown, are not counted, and neither are loopback ones.
pub fn lockdown(rules: &Rules, now: u64, failures: &[(u64, IpAddr)], lifted: Option<u64>) -> Option<u64> {
    let window = u64::from(rules.spray_minutes) * 60;
    let quiet = u64::from(rules.lockdown_quiet_hours) * 3600;
    let mut since = None;
    let mut last: Option<u64> = None;
    let mut recent: Vec<(u64, IpAddr)> = Vec::new();
    for &(time, address) in failures {
        let address = crate::net::canonical(address);
        if address.is_loopback() || lifted.is_some_and(|l| time <= l) {
            continue;
        }
        if last.is_some_and(|l| time >= l + quiet) {
            since = None;
            recent.clear();
        }
        recent.retain(|(t, _)| time.saturating_sub(*t) <= window);
        recent.push((time, address));
        if since.is_none() {
            let distinct: HashSet<IpAddr> = recent.iter().map(|(_, a)| *a).collect();
            if distinct.len() >= rules.spray_addresses as usize {
                since = Some(time);
            }
        }
        last = Some(time);
    }
    let start = since?;
    let end = last?;
    (now < end + quiet).then_some(start)
}

/// Whether a sign-in to an account, from `ip` at `place` and time `now`,
/// goes ahead. `seen` holds the account's approved sign-ins, `locked` says
/// whether it is locked down, and `distance_km` gives the distance between
/// two countries, nearest point to nearest point, when it is known.
pub fn decide(
    rules: &Rules,
    now: u64,
    ip: IpAddr,
    place: &Place,
    seen: &[Seen],
    locked: bool,
    distance_km: impl Fn(&str, &str) -> Option<u64>,
) -> Decision {
    if *place == Place::FileBrowser {
        return Decision::Allow;
    }
    if locked {
        return if trusted(ip, seen) { Decision::Allow } else { Decision::Refuse };
    }
    let first = seen.iter().map(|s| s.time).min();
    let learning = seen.len() < rules.learn_signins as usize
        || first.is_none_or(|f| now.saturating_sub(f) < u64::from(rules.learn_days) * 86_400);
    if learning || *place == Place::Local {
        return Decision::Allow;
    }
    if !seen.iter().any(|s| s.place == *place) {
        return Decision::Hold(Hold::NewPlace);
    }
    let (Place::Country(here), Some(last)) = (place, seen.iter().max_by_key(|s| s.time)) else {
        return Decision::Allow;
    };
    let Place::Country(there) = &last.place else { return Decision::Allow };
    if there == here {
        return Decision::Allow;
    }
    let Some(km) = distance_km(there.as_str(), here.as_str()) else { return Decision::Allow };
    let seconds = now.saturating_sub(last.time).max(1);
    let kmh = km.saturating_mul(3600) / seconds;
    if kmh > u64::from(rules.travel_kmh) {
        return Decision::Hold(Hold::ImpossibleTravel { from: there.clone(), kmh });
    }
    Decision::Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 86_400;

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    fn seen(time: u64, address: &str, country: &str) -> Seen {
        Seen { time, address: ip(address), place: Place::Country(country.into()) }
    }

    /// Five sign-ins over eight days from the United States, the last at day 8.
    fn profile() -> Vec<Seen> {
        (0..5).map(|i| seen(i * 2 * DAY, "203.0.113.24", "US")).collect()
    }

    fn far(_: &str, _: &str) -> Option<u64> {
        Some(7_000)
    }

    #[test]
    fn places_loopback_local_and_public_addresses() {
        assert_eq!(place_of(ip("127.0.0.1"), None), Place::FileBrowser);
        assert_eq!(place_of(ip("::ffff:127.0.0.1"), None), Place::FileBrowser);
        for local in ["10.0.4.17", "192.168.1.5", "172.16.0.9", "100.64.3.2", "169.254.1.1", "fd00::5", "fe80::1"] {
            assert_eq!(place_of(ip(local), Some("US")), Place::Local, "{local}");
        }
        assert_eq!(place_of(ip("203.0.113.24"), Some("us")), Place::Country("US".into()));
        assert_eq!(place_of(ip("203.0.113.24"), None), Place::Unknown);
    }

    #[test]
    fn trusts_the_network_of_an_approved_sign_in() {
        let seen = profile();
        assert!(trusted(ip("203.0.113.200"), &seen));
        assert!(!trusted(ip("203.0.114.24"), &seen));
        let v6 = [Seen { time: 0, address: ip("2001:db8:1:2::5"), place: Place::Unknown }];
        assert!(trusted(ip("2001:db8:1:2:ffff::1"), &v6));
        assert!(!trusted(ip("2001:db8:1:3::5"), &v6));
    }

    #[test]
    fn learns_until_enough_sign_ins_over_enough_days() {
        let rules = Rules::default();
        let few = &profile()[..4];
        let now = 9 * DAY;
        assert_eq!(decide(&rules, now, ip("198.51.100.7"), &Place::Country("RU".into()), few, false, far), Decision::Allow);
        let young: Vec<Seen> = (0..5).map(|i| seen(i * DAY, "203.0.113.24", "US")).collect();
        assert_eq!(decide(&rules, 5 * DAY, ip("198.51.100.7"), &Place::Country("RU".into()), &young, false, far), Decision::Allow);
    }

    #[test]
    fn holds_a_new_country_once_learned() {
        let rules = Rules::default();
        let now = 9 * DAY;
        let decision = decide(&rules, now, ip("198.51.100.7"), &Place::Country("RU".into()), &profile(), false, far);
        assert_eq!(decision, Decision::Hold(Hold::NewPlace));
        assert_eq!(decide(&rules, now, ip("198.51.100.7"), &Place::Unknown, &profile(), false, far), Decision::Hold(Hold::NewPlace));
        assert_eq!(decide(&rules, now, ip("198.51.100.7"), &Place::Country("US".into()), &profile(), false, far), Decision::Allow);
        assert_eq!(decide(&rules, now, ip("10.0.4.17"), &Place::Local, &profile(), false, far), Decision::Allow);
    }

    #[test]
    fn holds_impossible_travel_between_known_countries() {
        let rules = Rules::default();
        let mut seen = profile();
        seen.push(seen_in_canada(8 * DAY + 3600));
        let last = 8 * DAY + 3600;
        let two_hours = decide(&rules, last + 2 * 3600, ip("203.0.113.30"), &Place::Country("US".into()), &seen, false, |_, _| Some(3_000));
        assert_eq!(two_hours, Decision::Hold(Hold::ImpossibleTravel { from: "CA".into(), kmh: 1_500 }));
        let five_hours = decide(&rules, last + 5 * 3600, ip("203.0.113.30"), &Place::Country("US".into()), &seen, false, |_, _| Some(3_000));
        assert_eq!(five_hours, Decision::Allow, "600 km/h is under the limit");
        let unknown = decide(&rules, last + 60, ip("203.0.113.30"), &Place::Country("US".into()), &seen, false, |_, _| None);
        assert_eq!(unknown, Decision::Allow, "no distance, no travel hold");
    }

    fn seen_in_canada(time: u64) -> Seen {
        seen(time, "198.51.100.40", "CA")
    }

    #[test]
    fn locks_down_after_a_spray_and_lifts_after_quiet_hours() {
        let rules = Rules::default();
        let t = 100 * DAY;
        let spray = [(t, ip("192.0.2.1")), (t + 600, ip("192.0.2.2")), (t + 1200, ip("192.0.2.3"))];
        assert_eq!(lockdown(&rules, t + 1300, &spray, None), Some(t + 1200));
        assert_eq!(lockdown(&rules, t + 1200 + 24 * 3600, &spray, None), None, "24 h with no failure ends it");
        assert_eq!(lockdown(&rules, t + 1300, &spray[..2], None), None, "two addresses are not a spray");
        let slow = [(t, ip("192.0.2.1")), (t + 3000, ip("192.0.2.2")), (t + 7200, ip("192.0.2.3"))];
        assert_eq!(lockdown(&rules, t + 7300, &slow, None), None, "not within one hour");
        assert_eq!(lockdown(&rules, t + 1300, &spray, Some(t + 1200)), None, "an admin lifted it");
        let same = [(t, ip("192.0.2.1")), (t + 10, ip("192.0.2.1")), (t + 20, ip("192.0.2.1"))];
        assert_eq!(lockdown(&rules, t + 30, &same, None), None, "one address is fail2ban's to ban");
    }

    #[test]
    fn a_lockdown_admits_only_trusted_networks() {
        let rules = Rules::default();
        let now = 9 * DAY;
        assert_eq!(decide(&rules, now, ip("203.0.113.99"), &Place::Country("US".into()), &profile(), true, far), Decision::Allow);
        assert_eq!(decide(&rules, now, ip("198.51.100.7"), &Place::Country("US".into()), &profile(), true, far), Decision::Refuse);
        assert_eq!(decide(&rules, now, ip("127.0.0.1"), &Place::FileBrowser, &profile(), true, far), Decision::Allow);
    }
}
