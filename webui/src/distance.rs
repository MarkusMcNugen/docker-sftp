//! Distances between countries in km, nearest border point to nearest border
//! point, for the impossible travel rule. The table comes from Natural
//! Earth's 1:50m country boundaries, made by tools/country-distances/generate.py:
//! the magic b"CTDK", a little-endian u16 count n, n two-letter codes in
//! ascending order, then an n by n matrix of little-endian u16 km.

use std::sync::OnceLock;

static DATA: &[u8] = include_bytes!("../data/country-distances.bin");

struct Table {
    codes: Vec<[u8; 2]>,
    km: &'static [u8],
}

fn parse() -> Option<Table> {
    let rest = DATA.strip_prefix(b"CTDK")?;
    let (count, rest) = rest.split_first_chunk::<2>()?;
    let n = usize::from(u16::from_le_bytes(*count));
    let (codes, km) = rest.split_at_checked(n * 2)?;
    if km.len() != n * n * 2 {
        return None;
    }
    let (pairs, rest) = codes.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    Some(Table { codes: pairs.to_vec(), km })
}

fn table() -> Option<&'static Table> {
    static TABLE: OnceLock<Option<Table>> = OnceLock::new();
    TABLE.get_or_init(parse).as_ref()
}

fn index(table: &Table, code: &str) -> Option<usize> {
    let &[a, b] = code.as_bytes() else { return None };
    let key = [a.to_ascii_uppercase(), b.to_ascii_uppercase()];
    table.codes.iter().position(|c| *c == key)
}

/// The distance in km between two countries, by their two-letter codes, or
/// None when the table lacks one of them.
pub fn km(a: &str, b: &str) -> Option<u64> {
    let table = table()?;
    let n = table.codes.len();
    let at = 2 * (index(table, a)? * n + index(table, b)?);
    let pair = table.km.get(at..at + 2)?;
    Some(u64::from(u16::from_le_bytes([pair[0], pair[1]])))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_lists_each_country_once_in_order() {
        let table = table().expect("the embedded table parses");
        assert_eq!(table.codes.len(), 237);
        assert!(table.codes.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn measures_neighbors_straits_and_far_pairs() {
        assert_eq!(km("US", "CA"), Some(0));
        assert_eq!(km("fr", "de"), Some(0));
        assert_eq!(km("GB", "FR"), Some(37));
        assert_eq!(km("US", "RU"), Some(85));
        assert_eq!(km("RU", "US"), Some(85));
        assert_eq!(km("BR", "JP"), Some(13_820));
        assert_eq!(km("US", "US"), Some(0));
        assert_eq!(km("US", "ZZ"), None);
        assert_eq!(km("USA", "CA"), None);
    }
}
