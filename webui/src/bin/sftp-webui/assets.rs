//! The stylesheet, scripts and icons, compiled into the binary and served
//! under names that carry a hash of their content, so a browser may cache
//! them for good. Icons are Phosphor (MIT) and inlined as SVG.

use std::collections::HashMap;
use std::sync::OnceLock;

const CSS: &[u8] = include_bytes!("../../../assets/app.css");
const JS: &[u8] = include_bytes!("../../../assets/app.js");
const FILES_JS: &[u8] = include_bytes!("../../../assets/files.js");
const HTMX: &[u8] = include_bytes!("../../../assets/htmx-2.0.11.min.js");
const FAVICON: &[u8] = include_bytes!("../../../assets/favicon.svg");
const FONT_SANS: &[u8] = include_bytes!("../../../assets/fonts/Geist-Variable.woff2");
const FONT_MONO: &[u8] = include_bytes!("../../../assets/fonts/GeistMono-Variable.woff2");

/// The logo's outline version, drawn in the theme's accent and text colors.
pub const BRAND: &str = concat!(
    r#"<svg class="brand-mark" viewBox="16 22 96 88" aria-hidden="true" focusable="false">"#,
    r#"<path class="f" d="M24 42a8 8 0 0 1 8-8h20l8 8h36a8 8 0 0 1 8 8v42a8 8 0 0 1-8 8H32a8 8 0 0 1-8-8z"/>"#,
    r#"<path class="p" d="M44 60l11 10-11 10"/><path class="p" d="M62 82h18"/></svg>"#
);

macro_rules! icons {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_str!(concat!("../../../assets/icons/", $name, ".svg")))),*]
    };
}

const ICONS: &[(&str, &str)] = icons![
    "users", "user", "user-plus", "user-gear", "gauge", "shield-check", "prohibit", "gear-six", "scroll",
    "clipboard-text", "sign-out", "sign-in", "plus", "trash", "key", "pencil-simple", "lock-simple",
    "lock-simple-open", "check-circle", "warning", "warning-circle", "x-circle", "info", "copy", "sun", "moon",
    "desktop", "eye", "eye-slash", "calendar-blank", "globe-hemisphere-west", "folder-simple",
    "arrows-left-right", "arrows-clockwise", "magnifying-glass", "plugs-connected", "fingerprint",
    "shield-warning", "power", "link-simple", "caret-left", "caret-right", "list", "x", "hard-drives",
    "download-simple", "upload-simple", "device-mobile", "sliders-horizontal", "tray-arrow-down",
    "clock-counter-clockwise", "terminal-window", "identification-badge", "cube", "caret-up-down",
    "caret-down", "minus-circle", "sidebar-simple", "question", "folder-simple-plus", "folder-open", "check",
    "calendar-x", "circle-half", "arrow-counter-clockwise", "clock", "check-circle-fill", "x-circle-fill",
    "minus-circle-fill", "warning-circle-fill", "table", "chart-line", "file", "file-text", "file-pdf",
    "file-image", "file-zip", "file-code", "file-audio", "file-video", "share-network", "dots-three-vertical",
    "house", "arrow-up", "arrow-down", "arrows-down-up", "hourglass-medium", "infinity", "repeat", "gavel", "user-switch",
    "folder-user", "trend-up", "trend-down", "funnel-simple", "arrow-bend-up-right", "cloud-arrow-up",
    "link-break", "timer", "users-three", "browser", "squares-four", "rows", "copy-simple",
];

/// An icon's SVG, sized to the text around it and hidden from screen
/// readers; the text next to it carries the meaning.
pub fn icon(name: &str) -> &'static str {
    static MAP: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        ICONS
            .iter()
            .map(|(n, svg)| {
                (*n, svg.replacen("<svg ", "<svg class=\"icon\" aria-hidden=\"true\" focusable=\"false\" ", 1))
            })
            .collect()
    });
    match map.get(name) {
        Some(svg) => svg.as_str(),
        None => "",
    }
}

macro_rules! flags {
    ($($code:literal),* $(,)?) => {
        &[$(($code, include_bytes!(concat!("../../../assets/flags/", $code, ".svg")) as &[u8])),*]
    };
}

/// Country flags (flag-icons, MIT) by lower-case ISO 3166 code; `xx` is
/// the flag for an unknown country.
const FLAGS: &[(&str, &[u8])] = flags![
    "ad", "ae", "af", "ag", "ai", "al", "am", "ao", "aq", "ar", "as", "at", "au", "aw", "ax", "az",
    "ba", "bb", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bl", "bm", "bn", "bo", "bq", "br", "bs",
    "bt", "bv", "bw", "by", "bz", "ca", "cc", "cd", "cf", "cg", "ch", "ci", "ck", "cl", "cm", "cn",
    "co", "cp", "cr", "cu", "cv", "cw", "cx", "cy", "cz", "de", "dg", "dj", "dk", "dm", "do", "dz",
    "ec", "ee", "eg", "eh", "er", "es", "et", "eu", "fi", "fj", "fk", "fm", "fo", "fr", "ga", "gb",
    "gd", "ge", "gf", "gg", "gh", "gi", "gl", "gm", "gn", "gp", "gq", "gr", "gs", "gt", "gu", "gw",
    "gy", "hk", "hm", "hn", "hr", "ht", "hu", "ic", "id", "ie", "il", "im", "in", "io", "iq", "ir",
    "is", "it", "je", "jm", "jo", "jp", "ke", "kg", "kh", "ki", "km", "kn", "kp", "kr", "kw", "ky",
    "kz", "la", "lb", "lc", "li", "lk", "lr", "ls", "lt", "lu", "lv", "ly", "ma", "mc", "md", "me",
    "mf", "mg", "mh", "mk", "ml", "mm", "mn", "mo", "mp", "mq", "mr", "ms", "mt", "mu", "mv", "mw",
    "mx", "my", "mz", "na", "nc", "ne", "nf", "ng", "ni", "nl", "no", "np", "nr", "nu", "nz", "om",
    "pa", "pc", "pe", "pf", "pg", "ph", "pk", "pl", "pm", "pn", "pr", "ps", "pt", "pw", "py", "qa",
    "re", "ro", "rs", "ru", "rw", "sa", "sb", "sc", "sd", "se", "sg", "sh", "si", "sj", "sk", "sl",
    "sm", "sn", "so", "sr", "ss", "st", "sv", "sx", "sy", "sz", "tc", "td", "tf", "tg", "th", "tj",
    "tk", "tl", "tm", "tn", "to", "tr", "tt", "tv", "tw", "tz", "ua", "ug", "um", "un", "us", "uy",
    "uz", "va", "vc", "ve", "vg", "vi", "vn", "vu", "wf", "ws", "xk", "xx", "ye", "yt", "za", "zm",
    "zw",
];

fn flag_name(code: &str, svg: &[u8]) -> String {
    format!("flag-{code}.{}.svg", fnv(svg))
}

/// The URL of a country's flag by ISO 3166 code in either case; an unknown
/// code gets the unknown-country flag.
pub fn flag(code: &str) -> &'static str {
    static MAP: OnceLock<HashMap<&'static str, String>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        FLAGS.iter().map(|&(c, svg)| (c, format!("/static/{}", flag_name(c, svg)))).collect()
    });
    let lower = code.to_ascii_lowercase();
    match map.get(lower.as_str()) {
        Some(url) => url.as_str(),
        None => match map.get("xx") {
            Some(url) => url.as_str(),
            None => "",
        },
    }
}

fn fnv(data: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{:010x}", h >> 24)
}

pub struct Asset {
    pub body: &'static [u8],
    pub content_type: &'static str,
}

pub struct Assets {
    pub css: String,
    pub js: String,
    /// The file browser's file manager; only its pages load it.
    pub files_js: String,
    pub htmx: String,
    pub favicon: String,
    files: HashMap<String, Asset>,
}

impl Assets {
    pub fn new() -> Assets {
        let sans = format!("geist.{}.woff2", fnv(FONT_SANS));
        let mono = format!("geist-mono.{}.woff2", fnv(FONT_MONO));
        // The stylesheet names its fonts by fixed paths; they become the
        // hashed names here, before the stylesheet's own hash is taken.
        let styles = String::from_utf8_lossy(CSS)
            .replace("/static/geist.woff2", &format!("/static/{sans}"))
            .replace("/static/geist-mono.woff2", &format!("/static/{mono}"));
        let styles: &'static [u8] = Box::leak(styles.into_bytes().into_boxed_slice());
        let css = format!("app.{}.css", fnv(styles));
        let js = format!("app.{}.js", fnv(JS));
        let files_js = format!("files.{}.js", fnv(FILES_JS));
        let htmx = format!("htmx.{}.js", fnv(HTMX));
        let mut files = HashMap::new();
        files.insert(css.clone(), Asset { body: styles, content_type: "text/css; charset=utf-8" });
        files.insert(sans, Asset { body: FONT_SANS, content_type: "font/woff2" });
        files.insert(mono, Asset { body: FONT_MONO, content_type: "font/woff2" });
        files.insert(js.clone(), Asset { body: JS, content_type: "text/javascript; charset=utf-8" });
        files.insert(files_js.clone(), Asset { body: FILES_JS, content_type: "text/javascript; charset=utf-8" });
        files.insert(htmx.clone(), Asset { body: HTMX, content_type: "text/javascript; charset=utf-8" });
        let favicon = format!("favicon.{}.svg", fnv(FAVICON));
        files.insert(favicon.clone(), Asset { body: FAVICON, content_type: "image/svg+xml" });
        for &(code, svg) in FLAGS {
            files.insert(flag_name(code, svg), Asset { body: svg, content_type: "image/svg+xml" });
        }
        Assets {
            css: format!("/static/{css}"),
            js: format!("/static/{js}"),
            files_js: format!("/static/{files_js}"),
            htmx: format!("/static/{htmx}"),
            favicon: format!("/static/{favicon}"),
            files,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Asset> {
        self.files.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every icon a template names exists, so none renders as nothing.
    #[test]
    fn templates_name_only_known_icons() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/templates");
        for entry in std::fs::read_dir(dir).expect("templates") {
            let path = entry.expect("entry").path();
            let text = std::fs::read_to_string(&path).expect("read");
            for part in text.split("icon(\"").skip(1) {
                let name = &part[..part.find('"').expect("closing quote")];
                assert!(!icon(name).is_empty(), "{} names unknown icon {name}", path.display());
            }
        }
    }
}
