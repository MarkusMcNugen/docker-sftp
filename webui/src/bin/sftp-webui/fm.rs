//! The file manager: the three-pane page of an account's files, the details
//! of one item, and the changes made from them. Every read and change is the
//! account's own sftp request on the session's connection, so the server's
//! permission checks, chroot and umask apply exactly as on the sftp port.
//! File names reach the page only through the templates' escaping.

use std::cmp::Ordering;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use anyhow::{Result, anyhow, bail};
use askama::Template;
use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use sftp_webui::{tar, zip};
use tokio::sync::OwnedMutexGuard;

use crate::app;
use crate::browser::{Browser, Conn, Who, capitalized, failure, layout, sftp_of};
use crate::pages::Layout;
use crate::sftp::{self, Attrs, Entry, Sftp, Write};

type Shared = State<Arc<Browser>>;

/// Rows on one page of a folder; the pages after it hold the rest.
pub const PAGE_ROWS: usize = 500;

/// The body a bulk change may carry: every row of a page selected, each
/// path as long as a path may be (4096 bytes) and percent-encoded, so any
/// selection a page can make fits.
pub const BULK_BODY: usize = PAGE_ROWS * 4096 * 3 + 64 * 1024;

/// The requests that carry a selection, which BULK_BODY bounds.
pub fn carries_selection(path: &str) -> bool {
    matches!(path, "/delete" | "/move" | "/copy" | "/zip")
}

/// A path inside the account's folder as the browser asks for it: absolute,
/// with . and .. resolved and no trailing slash but the root's.
pub fn clean(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            name => parts.push(name),
        }
    }
    format!("/{}", parts.join("/"))
}

pub fn child(dir: &str, name: &str) -> String {
    if dir == "/" { format!("/{name}") } else { format!("{dir}/{name}") }
}

pub fn parent_of(path: &str) -> String {
    clean(&format!("{path}/.."))
}

pub fn name_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((_, name)) => name,
        None => path,
    }
}

/// True when `path` is `folder` or lies inside it.
fn within(path: &str, folder: &str) -> bool {
    path == folder || folder == "/" || path.strip_prefix(folder).is_some_and(|rest| rest.starts_with('/'))
}

/// A name for a new folder or a rename: one path segment.
pub fn plain_name(name: &str) -> Result<&str> {
    let name = name.trim();
    if name.is_empty() || name == "." || name == ".." || name.contains('/') || name.chars().any(char::is_control) {
        bail!("a name may not be empty, . or .., or hold a slash");
    }
    Ok(name)
}

/// Percent-encodes text for a query string or a header's filename*.
pub fn query_text(text: &str) -> String {
    text.bytes()
        .map(|b| if b.is_ascii_alphanumeric() || b"-._~/".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") })
        .collect()
}

/// Case-insensitive order in which runs of digits compare as numbers, so
/// file2 comes before file10.
fn natural(a: &str, b: &str) -> Ordering {
    let mut x = a.chars().peekable();
    let mut y = b.chars().peekable();
    loop {
        match (x.peek().copied(), y.peek().copied()) {
            (None, None) => return a.cmp(b),
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let mut n = String::new();
                while let Some(&c) = x.peek().filter(|c| c.is_ascii_digit()) {
                    n.push(c);
                    x.next();
                }
                let mut m = String::new();
                while let Some(&d) = y.peek().filter(|d| d.is_ascii_digit()) {
                    m.push(d);
                    y.next();
                }
                let (n, m) = (n.trim_start_matches('0'), m.trim_start_matches('0'));
                let ord = n.len().cmp(&m.len()).then_with(|| n.cmp(m));
                if ord != Ordering::Equal {
                    return ord;
                }
            }
            (Some(c), Some(d)) => {
                let ord = c.to_lowercase().cmp(d.to_lowercase());
                if ord != Ordering::Equal {
                    return ord;
                }
                x.next();
                y.next();
            }
        }
    }
}

/// How an entry shows: its icon, the icon's tone and a word for its kind.
#[derive(Clone, Copy)]
pub struct Look {
    pub tone: &'static str,
    pub icon: &'static str,
    pub word: &'static str,
}

/// A name's extension in lower case; empty for none, as for `.profile`.
fn ext_of(name: &str) -> String {
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => ext.to_ascii_lowercase(),
        Some(_) | None => String::new(),
    }
}

/// How a file previews: as an image, a PDF, audio, video or text, and the
/// type it is served as; None for a file the browser cannot show. HTML and
/// SVG source show as text or as a picture, never as a page.
pub fn preview_of(name: &str) -> Option<(&'static str, &'static str)> {
    Some(match ext_of(name).as_str() {
        "png" => ("image", "image/png"),
        "jpg" | "jpeg" => ("image", "image/jpeg"),
        "gif" => ("image", "image/gif"),
        "webp" => ("image", "image/webp"),
        "avif" => ("image", "image/avif"),
        "bmp" => ("image", "image/bmp"),
        "ico" => ("image", "image/x-icon"),
        "svg" => ("image", "image/svg+xml"),
        "pdf" => ("pdf", "application/pdf"),
        "mp3" => ("audio", "audio/mpeg"),
        "wav" => ("audio", "audio/wav"),
        "ogg" | "opus" => ("audio", "audio/ogg"),
        "flac" => ("audio", "audio/flac"),
        "m4a" => ("audio", "audio/mp4"),
        "aac" => ("audio", "audio/aac"),
        "mp4" | "m4v" => ("video", "video/mp4"),
        "webm" => ("video", "video/webm"),
        "mov" => ("video", "video/quicktime"),
        "" | "txt" | "md" | "log" | "csv" | "tsv" | "json" | "xml" | "yml" | "yaml" | "toml" | "ini" | "conf" | "cfg"
        | "rs" | "py" | "js" | "ts" | "sh" | "c" | "h" | "cpp" | "go" | "java" | "rb" | "php" | "html" | "htm" | "css"
        | "sql" | "ps1" => ("text", "text/plain; charset=utf-8"),
        _ => return None,
    })
}

/// The preview kind of an entry, empty for none.
fn preview_kind(name: &str, attrs: &Attrs) -> &'static str {
    if attrs.dir() {
        return "";
    }
    match preview_of(name) {
        Some((kind, _)) => kind,
        None => "",
    }
}

pub fn look(name: &str, attrs: &Attrs) -> Look {
    if attrs.dir() {
        return Look { tone: "folder", icon: "folder-simple", word: "Folder" };
    }
    if attrs.link() {
        return Look { tone: "", icon: "link-simple", word: "Link" };
    }
    let ext = ext_of(name);
    let (tone, icon, word) = match ext.as_str() {
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "bmp" | "ico" | "svg" | "tif" | "tiff" | "heic" => {
            ("image", "file-image", "Image")
        }
        "pdf" => ("pdf", "file-pdf", "PDF"),
        "zip" | "tar" | "gz" | "tgz" | "bz2" | "xz" | "zst" | "7z" | "rar" => ("zip", "file-zip", "Archive"),
        "txt" | "md" | "log" | "csv" | "tsv" | "json" | "xml" | "yml" | "yaml" | "toml" | "ini" | "conf" | "cfg" => {
            ("text", "file-text", "Text")
        }
        "rs" | "py" | "js" | "ts" | "sh" | "c" | "h" | "cpp" | "go" | "java" | "rb" | "php" | "html" | "htm" | "css"
        | "sql" | "ps1" => ("code", "file-code", "Code"),
        "mp3" | "wav" | "flac" | "ogg" | "m4a" | "aac" | "opus" => ("media", "file-audio", "Audio"),
        "mp4" | "webm" | "mov" | "mkv" | "avi" | "m4v" => ("media", "file-video", "Video"),
        _ => ("", "file", "File"),
    };
    Look { tone, icon, word }
}

fn kind_of(attrs: &Attrs) -> &'static str {
    if attrs.dir() {
        "dir"
    } else if attrs.link() {
        "link"
    } else {
        "file"
    }
}

fn stamp(secs: Option<u64>, format: fn(u64) -> String) -> String {
    match secs {
        Some(t) => format(t),
        None => String::new(),
    }
}

fn plural(n: usize, word: &str) -> String {
    if n == 1 { format!("1 {word}") } else { format!("{n} {word}s") }
}

/// What a folder holds, in words.
fn holds<'a>(entries: impl Iterator<Item = &'a Entry>) -> String {
    let (mut folders, mut files) = (0, 0);
    for e in entries {
        if e.attrs.dir() {
            folders += 1;
        } else {
            files += 1;
        }
    }
    if folders == 0 && files == 0 {
        return "Nothing".into();
    }
    format!("{} and {}", plural(folders, "folder"), plural(files, "file"))
}

/// A row of a folder's listing, and a tile of its grid.
pub struct Row {
    pub name: String,
    pub path: String,
    /// dir, file or link.
    pub kind: &'static str,
    pub look: Look,
    /// image, pdf, audio, video or text; empty for no preview.
    pub preview: &'static str,
    /// A zip archive, which opens in the archive window.
    pub archive: bool,
    pub size: String,
    /// The size and the time changed, for sorting; an unknown one sorts first.
    bytes: Option<u64>,
    secs: Option<u64>,
    pub modified: String,
    pub iso: String,
}

impl Row {
    fn of(folder: &str, e: Entry) -> Row {
        let kind = kind_of(&e.attrs);
        Row {
            path: child(folder, &e.name),
            kind,
            look: look(&e.name, &e.attrs),
            preview: preview_kind(&e.name, &e.attrs),
            archive: kind == "file" && archive_of(&e.name).is_some(),
            size: match (kind, e.attrs.size) {
                ("file", Some(n)) => crate::pages::size_label(n),
                (_, Some(_) | None) => String::new(),
            },
            bytes: e.attrs.size,
            secs: e.attrs.modified,
            modified: stamp(e.attrs.modified, sftp_webui::timefmt::display),
            iso: stamp(e.attrs.modified, sftp_webui::timefmt::iso),
            name: e.name,
        }
    }

    /// Where its name links: a folder opens, a file downloads, and a link
    /// goes wherever its target does.
    pub fn href(&self) -> String {
        match self.kind {
            "dir" => format!("./?path={}", query_text(&self.path)),
            "link" => format!("./open?path={}", query_text(&self.path)),
            _ => format!("./download?path={}", query_text(&self.path)),
        }
    }

    pub fn preview_href(&self) -> String {
        format!("./preview?path={}", query_text(&self.path))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SortBy {
    Name,
    Size,
    Modified,
}

impl SortBy {
    fn of(text: &str) -> SortBy {
        match text {
            "size" => SortBy::Size,
            "modified" => SortBy::Modified,
            _ => SortBy::Name,
        }
    }

    fn key(self) -> &'static str {
        match self {
            SortBy::Name => "name",
            SortBy::Size => "size",
            SortBy::Modified => "modified",
        }
    }
}

/// Folders first, then by the chosen column.
fn sort_rows(rows: &mut [Row], by: SortBy, descending: bool) {
    rows.sort_by(|a, b| {
        let folders_first = (b.kind == "dir").cmp(&(a.kind == "dir"));
        let ord = match by {
            SortBy::Name => natural(&a.name, &b.name),
            SortBy::Size => a.bytes.cmp(&b.bytes).then_with(|| natural(&a.name, &b.name)),
            SortBy::Modified => a.secs.cmp(&b.secs).then_with(|| natural(&a.name, &b.name)),
        };
        folders_first.then(if descending { ord.reverse() } else { ord })
    });
}

/// A folder's page, relative, so it stays below /m/<account>/ when the page
/// that links it is there.
fn list_href(path: &str, by: SortBy, descending: bool, page: usize) -> String {
    let mut out = format!("./?path={}", query_text(path));
    if by != SortBy::Name {
        out.push_str("&sort=");
        out.push_str(by.key());
    }
    if descending {
        out.push_str("&order=desc");
    }
    if page > 1 {
        out.push_str(&format!("&page={page}"));
    }
    out
}

/// A column heading, a link that sorts by it.
pub struct Column {
    pub label: &'static str,
    pub class: &'static str,
    pub href: String,
    /// ascending, descending, or empty when the list is not sorted by it.
    pub sort: &'static str,
}

/// A folder in the tree beside the listing.
pub struct TreeItem {
    pub name: String,
    pub path: String,
    pub depth: usize,
    pub current: bool,
    pub open: bool,
}

impl TreeItem {
    /// The indent class; folders deeper than eight levels share the last.
    pub fn indent(&self) -> usize {
        self.depth.min(8)
    }
}

/// Every folder from the top down to `path`, each with the folders it
/// holds, so the tree shows the path open and what lies beside it.
async fn tree(s: &mut Sftp, path: &str, here: &[Entry]) -> Result<Vec<TreeItem>> {
    let mut chain = vec!["/".to_string()];
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let next = match chain.last() {
            Some(last) => child(last, part),
            None => format!("/{part}"),
        };
        chain.push(next);
    }
    let mut kids: Vec<Vec<String>> = Vec::new();
    for (i, folder) in chain.iter().enumerate() {
        let next = chain.get(i + 1);
        let keep = |e: &Entry| e.attrs.dir() || next == Some(&child(folder, &e.name));
        let mut names: Vec<String> = if next.is_none() {
            here.iter().filter(|e| keep(e)).map(|e| e.name.clone()).collect()
        } else {
            match s.list(folder).await {
                Ok(entries) => entries.iter().filter(|e| keep(e)).map(|e| e.name.clone()).collect(),
                // A folder the account may pass through but not list shows
                // only the way down.
                Err(e) if !sftp::broken(&e) => match next {
                    Some(n) => vec![name_of(n).to_string()],
                    None => Vec::new(),
                },
                Err(e) => return Err(e),
            }
        };
        names.sort_by(|a, b| natural(a, b));
        kids.push(names);
    }
    let mut out = vec![TreeItem { name: "Home".into(), path: "/".into(), depth: 0, current: path == "/", open: true }];
    grow(0, &chain, &kids, path, &mut out);
    Ok(out)
}

fn grow(level: usize, chain: &[String], kids: &[Vec<String>], here: &str, out: &mut Vec<TreeItem>) {
    let (Some(names), Some(folder)) = (kids.get(level), chain.get(level)) else { return };
    for name in names {
        let path = child(folder, name);
        let open = chain.get(level + 1) == Some(&path);
        out.push(TreeItem { name: name.clone(), depth: level + 1, current: path == here, open, path });
        if open {
            grow(level + 1, chain, kids, here, out);
        }
    }
}

pub struct Crumb {
    pub name: String,
    pub path: String,
}

fn crumbs(path: &str) -> Vec<Crumb> {
    let mut out = Vec::new();
    let mut at = String::from("/");
    for part in path.split('/').filter(|p| !p.is_empty()) {
        at = child(&at, part);
        out.push(Crumb { name: part.to_string(), path: at.clone() });
    }
    out
}

/// The kinds of archive the archive window opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Archive {
    Zip,
    Tar,
    TarGz,
}

/// The kind of archive a file is, by its name, in any case.
fn archive_of(name: &str) -> Option<Archive> {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".zip") {
        Some(Archive::Zip)
    } else if lower.ends_with(".tar") {
        Some(Archive::Tar)
    } else if lower.ends_with(".tar.gz") || lower.ends_with(".tgz") {
        Some(Archive::TarGz)
    } else {
        None
    }
}

/// One item's details, or the folder's own when nothing is selected.
pub struct Details {
    pub name: String,
    pub path: String,
    pub kind: &'static str,
    pub look: Look,
    /// image, pdf, audio, video or text; empty for no preview.
    pub preview: &'static str,
    /// A zip archive, which opens in the archive window.
    pub archive: bool,
    /// The folder shown, which the page itself acts on.
    pub here: bool,
    /// A file's size, or what a folder holds.
    pub size: String,
    pub modified: String,
    pub iso: String,
    pub permissions: String,
    /// Where a link points.
    pub target: String,
    /// The latest event that put something at the path.
    pub added: Option<crate::pages::EventRow>,
    /// The events that name the path, newest first, a page at a time.
    pub history: Vec<crate::pages::EventRow>,
    /// Where the next older page starts.
    pub older: Option<i64>,
    /// Why the history cannot be shown, when it cannot.
    pub history_note: String,
}

fn details_of(path: &str, attrs: &Attrs, folder_holds: String, target: String, here: bool) -> Details {
    let name = if path == "/" { "The top folder".to_string() } else { name_of(path).to_string() };
    let kind = kind_of(attrs);
    Details {
        look: look(&name, attrs),
        preview: preview_kind(&name, attrs),
        archive: kind == "file" && archive_of(&name).is_some(),
        size: match (kind, attrs.size) {
            ("dir", _) => folder_holds,
            (_, Some(n)) => crate::pages::size_label(n),
            (_, None) => String::new(),
        },
        modified: stamp(attrs.modified, sftp_webui::timefmt::display),
        iso: stamp(attrs.modified, sftp_webui::timefmt::iso),
        permissions: attrs.permissions(),
        name,
        path: path.to_string(),
        kind,
        here,
        target,
        added: None,
        history: Vec::new(),
        older: None,
        history_note: String::new(),
    }
}

/// The history of a path in the files the page shows, from the helper.
async fn history(who: &Who, path: &str, before: Option<i64>) -> Result<sftp_webui::proto::FileHistory> {
    let acting = if who.acting == who.account { None } else { Some(who.acting.clone()) };
    let request = sftp_webui::proto::FilesRequest::FileHistory {
        session: sftp_webui::proto::Secret(who.helper_session()),
        acting,
        path: path.to_string(),
        before,
    };
    let reply = crate::browser::ask(&request).await?;
    if !reply.ok {
        anyhow::bail!("{}", reply.error);
    }
    serde_json::from_value(reply.data).map_err(|e| anyhow::anyhow!("the helper's answer cannot be read: {e}"))
}

/// Whose files a page shows and what else the person may open, for the
/// sidebar and the header.
pub struct Place {
    /// The account whose files these are.
    pub acting: String,
    /// The accounts the signed-in account manages.
    pub managed: Vec<String>,
    /// What the top folder is called: My files, or the account's files.
    pub top: String,
}

impl Place {
    pub fn own(&self, account: &str) -> bool {
        self.acting == account
    }
}

/// The page's place, and why the accounts managed cannot be listed if not.
pub(crate) async fn place_of(who: &Who) -> (Place, String) {
    let (managed, problem) = match crate::browser::managed(who).await {
        Ok(list) => (list, String::new()),
        Err(e) => (Vec::new(), format!("The accounts you manage cannot be listed: {e:#}")),
    };
    let top = if who.acting == who.account { "My files".to_string() } else { format!("Files of {}", who.acting) };
    (Place { acting: who.acting.clone(), managed, top }, problem)
}

/// A length the share dialog offers.
pub struct DayOption {
    pub days: u32,
    pub label: String,
    pub selected: bool,
}

/// The share dialog as the server's policy shapes it.
pub struct ShareChoice {
    pub allowed: bool,
    pub options: Vec<DayOption>,
    pub password_required: bool,
}

/// One day, a week, thirty days, the default and the longest, each within
/// the longest allowed, with the default chosen.
fn share_choice(p: &sftp_webui::proto::SharePolicy) -> ShareChoice {
    let mut days: Vec<u32> = [1, 7, 30, p.default_days, p.max_days].into_iter().filter(|d| *d <= p.max_days).collect();
    days.sort_unstable();
    days.dedup();
    ShareChoice {
        allowed: p.allowed,
        password_required: p.password_required,
        options: days
            .into_iter()
            .map(|d| DayOption { days: d, label: plural(d as usize, "day"), selected: d == p.default_days })
            .collect(),
    }
}

#[derive(Template)]
#[template(path = "files_home.html")]
pub struct Home {
    pub l: Layout,
    pub files_js: String,
    pub account: String,
    pub place: Place,
    pub share: ShareChoice,
    pub path: String,
    /// The folder's name, or My files at the top.
    pub here: String,
    pub crumbs: Vec<Crumb>,
    pub tree: Vec<TreeItem>,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
    pub count: String,
    pub page: usize,
    pub pages: usize,
    pub prev: String,
    pub next: String,
    pub d: Details,
    pub error: String,
}

#[derive(Template)]
#[template(path = "files_details.html")]
struct DetailsPart {
    d: Details,
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    sort: String,
    #[serde(default)]
    order: String,
    #[serde(default)]
    page: Option<usize>,
}

impl ListQuery {
    fn at(path: &str) -> ListQuery {
        ListQuery { path: path.into(), sort: String::new(), order: String::new(), page: None }
    }
}

#[derive(Deserialize)]
pub struct PathQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    here: bool,
    /// Where the details pane's page of history starts.
    #[serde(default)]
    before: Option<i64>,
}

/// Runs `work` on the session's connection. A broken connection is dropped,
/// so the next request makes a new one; a refusal leaves it in place.
pub async fn with_sftp<T>(who: &Who, work: impl AsyncFnOnce(&mut Sftp) -> Result<T>) -> Result<T> {
    let mut held = sftp_of(who).await?;
    let result = match held.as_mut() {
        Some(conn) => work(&mut conn.sftp).await,
        None => Err(anyhow!("the file browser has no connection")),
    };
    if let Err(e) = &result
        && sftp::broken(e)
    {
        *held = None;
    }
    result
}

fn refused(e: &anyhow::Error) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, capitalized(&format!("{e:#}"))).into_response()
}

pub async fn home(State(b): Shared, Extension(who): Extension<Who>, Query(q): Query<ListQuery>) -> Response {
    crate::browser::record(&who, sftp_webui::events::Kind::Browse, &clean(&q.path), "", 0);
    page_of(&b, &who, &q, String::new(), StatusCode::OK).await
}

/// The three-pane page of a folder, with `error` above it.
async fn page_of(b: &Browser, who: &Who, q: &ListQuery, error: String, status: StatusCode) -> Response {
    let path = clean(&q.path);
    let by = SortBy::of(&q.sort);
    let descending = q.order == "desc";
    let gathered = with_sftp(who, async |s| {
        let entries = s.list(&path).await?;
        let tree = tree(s, &path, &entries).await?;
        let folder = s.stat(&path).await?;
        Ok((entries, tree, folder))
    })
    .await;
    let (entries, tree, folder, error) = match gathered {
        Ok((entries, tree, folder)) => (entries, tree, folder, error),
        Err(e) => {
            crate::log(&format!("file browser: listing {path}: {e:#}"));
            let shown = if error.is_empty() { capitalized(&format!("{e:#}")) } else { error };
            let top = vec![TreeItem { name: "Home".into(), path: "/".into(), depth: 0, current: false, open: true }];
            (Vec::new(), top, Attrs::default(), shown)
        }
    };
    let count = holds(entries.iter());
    let mut rows: Vec<Row> = entries.into_iter().map(|e| Row::of(&path, e)).collect();
    sort_rows(&mut rows, by, descending);
    let pages = rows.len().div_ceil(PAGE_ROWS).max(1);
    let page = match q.page {
        Some(n) if n >= 1 => n.min(pages),
        Some(_) | None => 1,
    };
    let rows: Vec<Row> = rows.into_iter().skip((page - 1) * PAGE_ROWS).take(PAGE_ROWS).collect();
    let column = |label: &'static str, class: &'static str, key: SortBy| {
        let on = by == key;
        Column {
            label,
            class,
            href: list_href(&path, key, on && !descending, 1),
            sort: match (on, descending) {
                (true, false) => "ascending",
                (true, true) => "descending",
                (false, _) => "",
            },
        }
    };
    let columns = vec![
        column("Name", "", SortBy::Name),
        column("Size", "opt-sm num", SortBy::Size),
        column("Modified", "", SortBy::Modified),
    ];
    let (place, listing_problem) = place_of(who).await;
    let error = if error.is_empty() { listing_problem } else { error };
    let (share, error) = match crate::share::policy(who).await {
        Ok(p) => (share_choice(&p), error),
        Err(e) => {
            let off = ShareChoice { allowed: false, options: Vec::new(), password_required: false };
            let problem = format!("Share links cannot be offered: {e:#}");
            (off, if error.is_empty() { problem } else { error })
        }
    };
    let here = if path == "/" { place.top.clone() } else { name_of(&path).to_string() };
    let mut l = layout(b, &here, &who.csrf);
    l.admin = who.account.clone();
    l.initials = who.account.chars().take(1).flat_map(char::to_uppercase).collect();
    let home = Home {
        l,
        files_js: b.assets.files_js.clone(),
        account: who.account.clone(),
        place,
        share,
        d: details_of(&path, &folder, count.clone(), String::new(), true),
        crumbs: crumbs(&path),
        tree,
        columns,
        rows,
        count,
        prev: if page > 1 { list_href(&path, by, descending, page - 1) } else { String::new() },
        next: if page < pages { list_href(&path, by, descending, page + 1) } else { String::new() },
        page,
        pages,
        here,
        path,
        error,
    };
    app::render(status, &home)
}

/// The details pane for one item.
pub async fn details(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    let found = with_sftp(&who, async |s| {
        let attrs = s.lstat(&path).await?;
        let folder_holds = if attrs.dir() { holds(s.list(&path).await?.iter()) } else { String::new() };
        let target = if attrs.link() { s.readlink(&path).await? } else { String::new() };
        Ok((attrs, folder_holds, target))
    })
    .await;
    let (attrs, folder_holds, target) = match found {
        Ok(found) => found,
        Err(e) => return refused(&e),
    };
    let mut d = details_of(&path, &attrs, folder_holds, target, q.here);
    match history(&who, &path, q.before).await {
        Ok(h) => {
            d.added = h.added.map(crate::pages::event_row);
            d.history = h.events.into_iter().map(crate::pages::event_row).collect();
            d.older = h.older;
        }
        Err(e) => d.history_note = capitalized(&format!("its history cannot be read: {e:#}")),
    }
    app::render(StatusCode::OK, &DetailsPart { d })
}

/// Follows a link, or any path: a folder opens and a file downloads.
pub async fn open(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    match with_sftp(&who, async |s| s.stat(&path).await).await {
        Ok(attrs) if attrs.dir() => app::redirect(&list_href(&path, SortBy::Name, false, 1)),
        Ok(_) => app::redirect(&format!("./download?path={}", query_text(&path))),
        Err(e) => refused(&e),
    }
}

/// A file's size on the server, so an upload that stopped can go on.
pub async fn size(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    match with_sftp(&who, async |s| s.stat(&path).await).await {
        Ok(attrs) if attrs.dir() => (StatusCode::UNPROCESSABLE_ENTITY, format!("{path} is a folder")).into_response(),
        Ok(attrs) => match attrs.size {
            Some(n) => (StatusCode::OK, n.to_string()).into_response(),
            None => (StatusCode::UNPROCESSABLE_ENTITY, format!("The server gives no size for {path}.")).into_response(),
        },
        Err(e) => refused(&e),
    }
}

/// The form of a change, its fields in order; a bulk change repeats `path`.
struct Fields(Vec<(String, String)>);

impl Fields {
    fn read(body: &[u8]) -> Result<Fields> {
        match serde_urlencoded::from_bytes(body) {
            Ok(pairs) => Ok(Fields(pairs)),
            Err(e) => Err(anyhow!("the form cannot be read: {e}")),
        }
    }

    fn one(&self, key: &str) -> String {
        match self.0.iter().find(|(k, _)| k == key) {
            Some((_, v)) => v.clone(),
            None => String::new(),
        }
    }

    fn paths(&self) -> Vec<String> {
        self.0.iter().filter(|(k, _)| k == "path").map(|(_, v)| clean(v)).collect()
    }
}

/// After a change: the folder it was made from, or the same page with what
/// went wrong above it.
async fn after(b: &Browser, who: &Who, folder: &str, problems: Vec<String>) -> Response {
    if problems.is_empty() {
        return app::redirect(&list_href(folder, SortBy::Name, false, 1));
    }
    let text = problems.iter().map(|p| capitalized(p)).collect::<Vec<_>>().join(" ");
    page_of(b, who, &ListQuery::at(folder), text, StatusCode::UNPROCESSABLE_ENTITY).await
}

pub async fn mkdir(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let folder = clean(&form.one("path"));
    let problems = match plain_name(&form.one("name")) {
        Ok(name) => {
            let target = child(&folder, name);
            match with_sftp(&who, async |s| s.mkdir(&target).await).await {
                Ok(()) => {
                    crate::browser::record(&who, sftp_webui::events::Kind::Mkdir, &target, "", 0);
                    Vec::new()
                }
                Err(e) => vec![format!("the folder {name} was not made: {e:#}")],
            }
        }
        Err(e) => vec![format!("{e:#}")],
    };
    after(&b, &who, &folder, problems).await
}

/// Makes every folder down to `path` that is missing; `path` itself too
/// when `last`.
async fn make_folders(s: &mut Sftp, path: &str, last: bool) -> Result<()> {
    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    let upto = if last { parts.len() } else { parts.len().saturating_sub(1) };
    let mut at = String::from("/");
    for part in &parts[..upto] {
        at = child(&at, part);
        if !s.exists(&at).await? {
            s.mkdir(&at).await?;
        }
    }
    Ok(())
}

/// A folder and the folders above it, for a folder that is uploaded.
pub async fn mkdirs(Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let path = clean(&form.one("path"));
    match with_sftp(&who, async |s| make_folders(s, &path, true).await).await {
        Ok(()) => {
            crate::browser::record(&who, sftp_webui::events::Kind::Mkdir, &path, "", 0);
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => refused(&e),
    }
}

pub async fn rename(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let path = clean(&form.one("path"));
    let folder = parent_of(&path);
    let problems = match plain_name(&form.one("name")) {
        Ok(_) if path == "/" => vec!["the home folder cannot be renamed".to_string()],
        Ok(name) => {
            let to = child(&folder, name);
            let renamed = with_sftp(&who, async |s| {
                if to == path {
                    return Ok(());
                }
                if s.exists(&to).await? {
                    bail!("{name} already exists here");
                }
                s.rename(&path, &to).await
            })
            .await;
            match renamed {
                Ok(()) => {
                    if to != path {
                        crate::browser::record(&who, sftp_webui::events::Kind::Rename, &path, &to, 0);
                    }
                    Vec::new()
                }
                Err(e) => vec![format!("{} was not renamed: {e:#}", name_of(&path))],
            }
        }
        Err(e) => vec![format!("{e:#}")],
    };
    after(&b, &who, &folder, problems).await
}

/// Deletes a file, a link or a folder with everything in it. A link is
/// removed as a link and never followed, so nothing outside is touched.
async fn remove_tree(s: &mut Sftp, path: &str) -> Result<()> {
    if !s.lstat(path).await?.dir() {
        return s.remove(path).await;
    }
    let mut stack = vec![(path.to_string(), false)];
    while let Some((dir, emptied)) = stack.pop() {
        if emptied {
            s.rmdir(&dir).await?;
            continue;
        }
        stack.push((dir.clone(), true));
        // The server describes listed entries as lstat does, links as links.
        for e in s.list(&dir).await? {
            let p = child(&dir, &e.name);
            if e.attrs.dir() {
                stack.push((p, false));
            } else {
                s.remove(&p).await?;
            }
        }
    }
    Ok(())
}

pub async fn delete(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let folder = clean(&form.one("folder"));
    let mut problems = Vec::new();
    for path in form.paths() {
        if path == "/" {
            problems.push("the home folder cannot be deleted".to_string());
            continue;
        }
        match with_sftp(&who, async |s| remove_tree(s, &path).await).await {
            Ok(()) => crate::browser::record(&who, sftp_webui::events::Kind::Delete, &path, "", 0),
            Err(e) => problems.push(format!("{} was not deleted: {e:#}", name_of(&path))),
        }
    }
    after(&b, &who, &folder, problems).await
}

/// `name` in `folder`, or when that is taken the first free one of
/// `name copy`, `name copy 2` and on, an extension kept at the end.
async fn free_name(s: &mut Sftp, folder: &str, name: &str) -> Result<String> {
    let first = child(folder, name);
    if !s.exists(&first).await? {
        return Ok(first);
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => (stem, format!(".{ext}")),
        Some(_) | None => (name, String::new()),
    };
    let mut n: u64 = 1;
    loop {
        let candidate = if n == 1 { format!("{stem} copy{ext}") } else { format!("{stem} copy {n}{ext}") };
        let path = child(folder, &candidate);
        if !s.exists(&path).await? {
            return Ok(path);
        }
        n += 1;
    }
}

/// Copies a file's bytes to `to`, which is made new.
async fn copy_file(s: &mut Sftp, from: &str, to: &str) -> Result<()> {
    let src = s.open_read(from).await?;
    let dst = match s.open_write(to, Write::New).await {
        Ok(h) => h,
        Err(e) => {
            return match s.close(&src).await {
                Ok(()) => Err(e),
                Err(closing) => Err(e.context(format!("and {from} did not close: {closing:#}"))),
            };
        }
    };
    let mut offset = 0u64;
    let copied = loop {
        match s.read(&src, offset).await {
            Ok(Some(chunk)) => {
                if let Err(e) = s.write(&dst, offset, &chunk).await {
                    break Err(e);
                }
                offset += chunk.len() as u64;
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e),
        }
    };
    let closed_src = s.close(&src).await;
    let closed_dst = s.close(&dst).await;
    copied?;
    closed_src?;
    closed_dst
}

/// Copies a file, a link as a link, or a folder with everything in it, to
/// `to`, which must be free.
async fn copy_tree(s: &mut Sftp, from: &str, to: &str) -> Result<()> {
    let first = s.lstat(from).await?;
    let mut stack = vec![(from.to_string(), to.to_string(), kind_of(&first))];
    while let Some((src, dst, kind)) = stack.pop() {
        match kind {
            "dir" => {
                s.mkdir(&dst).await?;
                for e in s.list(&src).await? {
                    stack.push((child(&src, &e.name), child(&dst, &e.name), kind_of(&e.attrs)));
                }
            }
            "link" => {
                let target = s.readlink(&src).await?;
                s.symlink(&target, &dst).await?;
            }
            _ => copy_file(s, &src, &dst).await?,
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Bulk {
    Move,
    Copy,
}

async fn bulk(b: &Browser, who: &Who, body: &[u8], what: Bulk) -> Response {
    let form = match Fields::read(body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let folder = clean(&form.one("folder"));
    let to = clean(&form.one("to"));
    let (verb, done) = match what {
        Bulk::Move => ("moved", "move"),
        Bulk::Copy => ("copied", "copy"),
    };
    let mut problems = Vec::new();
    for path in form.paths() {
        let name = name_of(&path).to_string();
        if path == "/" {
            problems.push(format!("the home folder cannot be {verb}"));
            continue;
        }
        if within(&to, &path) {
            problems.push(format!("{name} cannot {done} into itself"));
            continue;
        }
        let result = with_sftp(who, async |s| {
            if !s.stat(&to).await?.dir() {
                bail!("{to} is not a folder");
            }
            match what {
                Bulk::Move => {
                    let dest = child(&to, &name);
                    if dest == path {
                        return Ok(None);
                    }
                    if s.exists(&dest).await? {
                        bail!("{name} already exists in {to}");
                    }
                    s.rename(&path, &dest).await?;
                    Ok(Some(dest))
                }
                Bulk::Copy => {
                    let dest = free_name(s, &to, &name).await?;
                    copy_tree(s, &path, &dest).await?;
                    Ok(Some(dest))
                }
            }
        })
        .await;
        match (result, what) {
            (Ok(None), _) => {}
            (Ok(Some(dest)), Bulk::Move) => crate::browser::record(who, sftp_webui::events::Kind::Rename, &path, &dest, 0),
            (Ok(Some(dest)), Bulk::Copy) => crate::browser::record(who, sftp_webui::events::Kind::Copy, &dest, &path, 0),
            (Err(e), _) => problems.push(format!("{name} was not {verb}: {e:#}")),
        }
    }
    after(b, who, &folder, problems).await
}

pub async fn move_to(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    bulk(&b, &who, &body, Bulk::Move).await
}

pub async fn copy_to(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    bulk(&b, &who, &body, Bulk::Copy).await
}

#[derive(Deserialize)]
pub struct UploadQuery {
    #[serde(default)]
    path: String,
    /// Where an upload that stopped goes on: the size the server holds.
    #[serde(default)]
    offset: Option<u64>,
    /// Make the folders above the file that are missing, for a folder that
    /// is uploaded.
    #[serde(default)]
    parents: bool,
}

/// Streams `body` into the file at `path`, piece by piece as it arrives: a
/// new file, or with `offset` the rest of one whose upload stopped there.
/// The file's size after.
async fn receive(s: &mut Sftp, path: &str, offset: Option<u64>, parents: bool, mut body: Body) -> Result<u64> {
    use http_body_util::BodyExt;
    if parents {
        make_folders(s, path, false).await?;
    }
    let (how, start) = match offset {
        None | Some(0) => (Write::Replace, 0),
        Some(from) => {
            let held = match s.stat(path).await?.size {
                Some(n) => n,
                None => bail!("the server gives no size for {path}"),
            };
            if held != from {
                bail!("the server holds {held} B of {}, so the upload goes on from there", name_of(path));
            }
            (Write::Resume, from)
        }
    };
    let file = s.open_write(path, how).await?;
    let mut at = start;
    let written = loop {
        match body.frame().await {
            None => break Ok(at),
            Some(Err(e)) => break Err(anyhow!("the upload stopped: {e}")),
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    if let Err(e) = s.write(&file, at, data).await {
                        break Err(e);
                    }
                    at += data.len() as u64;
                }
            }
        }
    };
    let closed = s.close(&file).await;
    let size = written?;
    closed?;
    Ok(size)
}

/// Writes a request's body to a file in the account's folder.
pub async fn upload(Extension(who): Extension<Who>, Query(q): Query<UploadQuery>, body: Body) -> Response {
    let path = clean(&q.path);
    let name = name_of(&path).to_string();
    if let Err(e) = plain_name(&name) {
        return refused(&e);
    }
    let mut held = match sftp_of(&who).await {
        Ok(h) => h,
        Err(e) => return failure(&e),
    };
    let written = match held.as_mut() {
        Some(conn) => receive(&mut conn.sftp, &path, q.offset, q.parents, body).await,
        None => Err(anyhow!("the file browser has no connection")),
    };
    match written {
        Ok(size) => {
            crate::browser::record(&who, sftp_webui::events::Kind::Upload, &path, "", size);
            (StatusCode::OK, format!("Uploaded {name} ({}).", crate::pages::size_label(size))).into_response()
        }
        Err(e) => {
            if sftp::broken(&e) {
                *held = None;
            }
            crate::log(&format!("file browser: uploading {path}: {e:#}"));
            refused(&e)
        }
    }
}

/// A body fed by the task that reads the file over sftp.
pub(crate) struct Chunks(pub(crate) tokio::sync::mpsc::Receiver<std::result::Result<Bytes, std::io::Error>>);

impl http_body::Body for Chunks {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<std::result::Result<http_body::Frame<Bytes>, std::io::Error>>> {
        self.0.poll_recv(cx).map(|item| item.map(|chunk| chunk.map(http_body::Frame::data)))
    }
}

/// A file opened to read on the session's connection, which it holds.
struct Opened {
    held: OwnedMutexGuard<Option<Conn>>,
    file: Vec<u8>,
    size: Option<u64>,
}

/// An answer that ends a request early, boxed so a Result stays small.
type Early = Box<Response>;

/// Opens a file to read; a folder is refused.
async fn open_file(who: &Who, path: &str) -> Result<Opened, Early> {
    let mut held = match sftp_of(who).await {
        Ok(h) => h,
        Err(e) => return Err(Box::new(failure(&e))),
    };
    let opened = match held.as_mut() {
        Some(conn) => match conn.sftp.stat(path).await {
            Ok(attrs) if attrs.dir() => Err(anyhow::Error::new(sftp::Refused(format!("{path} is a folder")))),
            Ok(attrs) => match conn.sftp.open_read(path).await {
                Ok(file) => Ok((file, attrs.size)),
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        },
        None => Err(anyhow!("the file browser has no connection")),
    };
    match opened {
        Ok((file, size)) => Ok(Opened { held, file, size }),
        Err(e) => {
            if sftp::broken(&e) {
                *held = None;
            }
            crate::log(&format!("file browser: opening {path}: {e:#}"));
            Err(Box::new((StatusCode::NOT_FOUND, capitalized(&format!("{e:#}"))).into_response()))
        }
    }
}

/// Closes a file that was opened and is not sent after all.
async fn close_unsent(opened: &mut Opened, path: &str) {
    let closed = match opened.held.as_mut() {
        Some(conn) => conn.sftp.close(&opened.file).await,
        None => Ok(()),
    };
    if let Err(e) = closed {
        crate::log(&format!("file browser: closing {path}: {e:#}"));
        if sftp::broken(&e) {
            *opened.held = None;
        }
    }
}

/// A body that reads the open file from `start` up to `end`, or to its end
/// with none, as the browser takes it; the connection is held until the
/// last piece is sent, then the file is closed.
fn stream(opened: Opened, path: String, start: u64, end: Option<u64>) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let Opened { mut held, file, .. } = opened;
        let Some(conn) = held.as_mut() else { return };
        let mut offset = start;
        let mut failed = false;
        while end.is_none_or(|end| offset < end) {
            match conn.sftp.read(&file, offset).await {
                Ok(Some(mut chunk)) => {
                    if let Some(end) = end {
                        let room = end - offset;
                        if chunk.len() as u64 > room {
                            // Less than the chunk, which is a usize.
                            chunk.truncate(room as usize);
                        }
                    }
                    offset += chunk.len() as u64;
                    if tx.send(Ok(Bytes::from(chunk))).await.is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    crate::log(&format!("file browser: reading {path}: {e:#}"));
                    failed = sftp::broken(&e);
                    if tx.send(Err(std::io::Error::other(format!("{e:#}")))).await.is_err() {
                        crate::log("file browser: the transfer ended before its error could be sent");
                    }
                    break;
                }
            }
        }
        let closed = conn.sftp.close(&file).await;
        if let Err(e) = &closed {
            crate::log(&format!("file browser: closing {path}: {e:#}"));
        }
        if failed || closed.as_ref().is_err_and(sftp::broken) {
            *held = None;
        }
    });
    Body::new(Chunks(rx))
}

fn header_value(text: String) -> Result<HeaderValue, Early> {
    match HeaderValue::from_str(&text) {
        Ok(v) => Ok(v),
        Err(e) => Err(Box::new(failure(&anyhow!("cannot write the header {text:?}: {e}")))),
    }
}

/// A Content-Disposition naming the file, as an attachment or inline.
fn disposition(how: &str, path: &str) -> Result<HeaderValue, Early> {
    let name = query_text(name_of(path)).replace('/', "%2F");
    header_value(format!("{how}; filename*=UTF-8''{name}"))
}

/// Streams a file to the browser as a download.
pub async fn download(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    let named = match disposition("attachment", &path) {
        Ok(v) => v,
        Err(res) => return *res,
    };
    let opened = match open_file(&who, &path).await {
        Ok(o) => o,
        Err(res) => return *res,
    };
    let size = opened.size;
    crate::browser::record(&who, sftp_webui::events::Kind::Download, &path, "", size.into_iter().sum());
    let mut res = stream(opened, path, 0, None).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, named);
    if let Some(n) = size {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
    }
    res
}

/// Where a streamed body's pieces go.
type Out = tokio::sync::mpsc::Sender<std::result::Result<Bytes, std::io::Error>>;

/// What goes in an archive: each path on the server with its name there.
type ZipItems = Vec<(String, String)>;

async fn put(tx: &Out, bytes: Vec<u8>) -> Result<()> {
    if tx.send(Ok(Bytes::from(bytes))).await.is_err() {
        bail!("the download was cancelled");
    }
    Ok(())
}

/// A file's or folder's permission bits as the archive records them; a
/// file whose mode the server does not give is recorded as readable.
fn zip_mode(attrs: &Attrs) -> u32 {
    match attrs.mode {
        Some(m) => m & 0o7777,
        None => 0o644,
    }
}

/// Writes each item into the archive as it goes out, a folder with
/// everything in it in name order; a link goes in as a link, never followed.
async fn write_zip(s: &mut Sftp, out: &mut zip::Writer, items: ZipItems, tx: &Out) -> Result<()> {
    let mut stack: ZipItems = items.into_iter().rev().collect();
    while let Some((path, name)) = stack.pop() {
        let attrs = s.lstat(&path).await?;
        let mode = zip_mode(&attrs);
        if attrs.dir() {
            put(tx, out.dir(&format!("{name}/"), mode, attrs.modified)?).await?;
            let mut kids = s.list(&path).await?;
            kids.sort_by(|a, b| natural(&a.name, &b.name));
            for e in kids.into_iter().rev() {
                stack.push((child(&path, &e.name), format!("{name}/{}", e.name)));
            }
        } else if attrs.link() {
            let target = s.readlink(&path).await?;
            put(tx, out.link(&name, attrs.modified, &target)?).await?;
        } else {
            put(tx, out.begin_file(&name, mode, attrs.modified, attrs.size)?).await?;
            let file = s.open_read(&path).await?;
            let mut crc = flate2::Crc::new();
            let mut offset = 0u64;
            let read = loop {
                match s.read(&file, offset).await {
                    Ok(Some(chunk)) => {
                        crc.update(&chunk);
                        offset += chunk.len() as u64;
                        if let Err(e) = put(tx, chunk).await {
                            break Err(e);
                        }
                    }
                    Ok(None) => break Ok(()),
                    Err(e) => break Err(e),
                }
            };
            let closed = s.close(&file).await;
            read?;
            closed?;
            put(tx, out.end_file(crc.sum(), offset)?).await?;
        }
    }
    Ok(())
}

/// Streams a zip archive of `items` named `file_name`, made while it is
/// sent; the session's connection is held until the last byte. Something
/// that cannot be read ends the download with an error, so an archive is
/// never quietly missing a file.
async fn zip_send(who: &Who, items: ZipItems, file_name: &str) -> Response {
    let named = match disposition("attachment", file_name) {
        Ok(v) => v,
        Err(res) => return *res,
    };
    let held = match sftp_of(who).await {
        Ok(h) => h,
        Err(e) => return failure(&e),
    };
    for (path, _) in &items {
        crate::browser::record(who, sftp_webui::events::Kind::Download, path, "", 0);
    }
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut held = held;
        let Some(conn) = held.as_mut() else { return };
        let mut out = zip::Writer::new();
        let wrote = match write_zip(&mut conn.sftp, &mut out, items, &tx).await {
            Ok(()) => match out.finish() {
                Ok(tail) => put(&tx, tail).await,
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        };
        if let Err(e) = wrote {
            crate::log(&format!("file browser: making an archive: {e:#}"));
            if tx.send(Err(std::io::Error::other(format!("{e:#}")))).await.is_err() {
                crate::log("file browser: the archive's download ended before its error could be sent");
            }
            if sftp::broken(&e) {
                *held = None;
            }
        }
    });
    let mut res = Body::new(Chunks(rx)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    h.insert(header::CONTENT_DISPOSITION, named);
    res
}

/// A folder, with everything in it, as a zip archive.
pub async fn zip_one(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    let name = if path == "/" { "My files".to_string() } else { name_of(&path).to_string() };
    let file_name = format!("{name}.zip");
    zip_send(&who, vec![(path, name)], &file_name).await
}

/// The items chosen in a folder as one zip archive named for the folder.
pub async fn zip_many(Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let folder = clean(&form.one("folder"));
    let items: ZipItems = form
        .paths()
        .into_iter()
        .filter(|p| p != "/")
        .map(|p| {
            let name = name_of(&p).to_string();
            (p, name)
        })
        .collect();
    if items.is_empty() {
        return (StatusCode::UNPROCESSABLE_ENTITY, "Choose something to download.").into_response();
    }
    let base = if folder == "/" { "My files" } else { name_of(&folder) };
    let file_name = format!("{base}.zip");
    zip_send(&who, items, &file_name).await
}

#[derive(Template)]
#[template(path = "files_search.html")]
struct SearchPage {
    l: Layout,
    files_js: String,
    account: String,
    place: Place,
    path: String,
    here: String,
    q: String,
    crumbs: Vec<Crumb>,
}

#[derive(Template)]
#[template(path = "files_search_row.html")]
struct SearchRow {
    r: Row,
    folder: String,
}

#[derive(Template)]
#[template(path = "files_search_summary.html")]
struct SearchSummary {
    q: String,
    found: usize,
    found_label: String,
    folders_label: String,
    unreadable_label: String,
    unreadable: Vec<String>,
    /// Why the search ended before the last folder; empty when it did not.
    failed: String,
}

#[derive(Deserialize)]
pub struct SearchQuery {
    #[serde(default)]
    path: String,
    #[serde(default)]
    q: String,
}

/// What a search found and saw.
#[derive(Default)]
struct Searched {
    found: usize,
    folders: usize,
    /// Folders the account may not list, each with the server's reason.
    unreadable: Vec<String>,
}

/// Walks every folder below `from`, nearest first, and sends a row for each
/// name that holds `needle`, as it is found. A link is not followed.
async fn walk(s: &mut Sftp, from: &str, needle: &str, tx: &Out, seen: &mut Searched) -> Result<()> {
    let mut queue = std::collections::VecDeque::from([from.to_string()]);
    while let Some(dir) = queue.pop_front() {
        let mut entries = match s.list(&dir).await {
            Ok(entries) => entries,
            Err(e) if !sftp::broken(&e) => {
                seen.unreadable.push(format!("{dir}: {e:#}"));
                continue;
            }
            Err(e) => return Err(e),
        };
        seen.folders += 1;
        entries.sort_by(|a, b| natural(&a.name, &b.name));
        for e in entries {
            if e.attrs.dir() {
                queue.push_back(child(&dir, &e.name));
            }
            if e.name.to_lowercase().contains(needle) {
                seen.found += 1;
                let row = SearchRow { r: Row::of(&dir, e), folder: dir.clone() };
                put(tx, row.render().map_err(|e| anyhow!("cannot show a result: {e}"))?.into_bytes()).await?;
            }
        }
    }
    Ok(())
}

/// Searches file and folder names below a folder, every one of them, and
/// streams the page as the results come, so the first show at once on a
/// large tree; leaving the page ends the search.
pub async fn search(State(b): Shared, Extension(who): Extension<Who>, Query(q): Query<SearchQuery>) -> Response {
    let path = clean(&q.path);
    let wanted = q.q.trim().to_string();
    if wanted.is_empty() {
        return app::redirect(&list_href(&path, SortBy::Name, false, 1));
    }
    let (place, listing_problem) = place_of(&who).await;
    if !listing_problem.is_empty() {
        crate::log(&format!("file browser: {listing_problem}"));
    }
    let here = if path == "/" { place.top.clone() } else { name_of(&path).to_string() };
    let mut l = layout(&b, &format!("Search {here}"), &who.csrf);
    l.admin = who.account.clone();
    l.initials = who.account.chars().take(1).flat_map(char::to_uppercase).collect();
    let page = SearchPage {
        l,
        files_js: b.assets.files_js.clone(),
        account: who.account.clone(),
        place,
        crumbs: crumbs(&path),
        path: path.clone(),
        here,
        q: wanted.clone(),
    };
    let rendered = match page.render() {
        Ok(text) => text,
        Err(e) => return failure(&anyhow!("cannot show the search: {e}")),
    };
    // The marker is in the template; text from a name or the query cannot
    // make one, since the template escapes the < it starts with.
    let Some((head, tail)) = rendered.split_once("<!--rows-->") else {
        return failure(&anyhow!("the search page has no place for its results"));
    };
    let (head, tail) = (head.to_string(), tail.to_string());
    let held = match sftp_of(&who).await {
        Ok(h) => h,
        Err(e) => return failure(&e),
    };
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    tokio::spawn(async move {
        let mut held = held;
        if put(&tx, head.into_bytes()).await.is_err() {
            return;
        }
        let needle = wanted.to_lowercase();
        let mut seen = Searched::default();
        let walked = match held.as_mut() {
            Some(conn) => walk(&mut conn.sftp, &path, &needle, &tx, &mut seen).await,
            None => Err(anyhow!("the file browser has no connection")),
        };
        let failed = match &walked {
            Ok(()) => String::new(),
            Err(e) => {
                crate::log(&format!("file browser: searching {path}: {e:#}"));
                if sftp::broken(e) {
                    *held = None;
                }
                format!("{e:#}")
            }
        };
        let summary = SearchSummary {
            q: wanted,
            found: seen.found,
            found_label: format!("{} found", plural(seen.found, "name")),
            folders_label: plural(seen.folders, "folder"),
            unreadable_label: plural(seen.unreadable.len(), "folder"),
            unreadable: seen.unreadable,
            failed,
        };
        let end = match summary.render() {
            Ok(text) => tail.replacen("<!--summary-->", &text, 1),
            Err(e) => {
                crate::log(&format!("file browser: cannot show the search's summary: {e}"));
                tail
            }
        };
        if put(&tx, end.into_bytes()).await.is_err() {
            crate::log("file browser: the search page closed before its end");
        }
    });
    let mut res = Body::new(Chunks(rx)).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    res
}

/// Up to `len` bytes of an open file from `offset`; fewer only at its end.
async fn read_at(s: &mut Sftp, file: &[u8], offset: u64, len: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while (out.len() as u64) < len {
        match s.read(file, offset + out.len() as u64).await? {
            Some(chunk) => out.extend_from_slice(&chunk),
            None => break,
        }
    }
    out.truncate(usize::try_from(len).map_err(|e| anyhow!("{len} B do not fit in memory here: {e}"))?);
    Ok(out)
}

/// A zip archive's entries, read from its end records and central
/// directory without unpacking anything.
async fn zip_entries(s: &mut Sftp, file: &[u8], size: u64) -> Result<Vec<zip::Listed>> {
    let span = size.min(zip::END_SPAN);
    let tail = read_at(s, file, size - span, span).await?;
    let dir = match zip::ending(&tail, size)? {
        zip::Ending::Directory(d) => d,
        zip::Ending::Zip64At(at) => zip::ending64(&read_at(s, file, at, 56).await?)?,
    };
    if dir.offset.checked_add(dir.size).is_none_or(|end| end > size) {
        bail!("this archive's directory lies past its end");
    }
    let cd = read_at(s, file, dir.offset, dir.size).await?;
    zip::entries(&cd, dir.count)
}

/// Where an unpacked entry goes: to the browser, or into a file on the
/// same connection, at the offset reached.
enum Sink<'a> {
    Send(&'a Out),
    File(&'a [u8], u64),
}

/// Unpacks a stored or deflated entry piece by piece into `sink`, checking
/// it unpacks to no more than its stated size and to its CRC.
async fn unpack_entry(s: &mut Sftp, file: &[u8], e: &zip::Listed, mut sink: Sink<'_>) -> Result<()> {
    if e.encrypted {
        bail!("{} is encrypted", e.name);
    }
    if e.method != 0 && e.method != 8 {
        bail!("{} is packed in a way this server does not unpack (method {})", e.name, e.method);
    }
    let header = read_at(s, file, e.offset, 30).await?;
    let mut at = zip::content_at(&header, e.offset)?;
    let end = at.checked_add(e.packed).ok_or_else(|| anyhow!("{} runs past the end of the archive", e.name))?;
    let mut inflate = flate2::Decompress::new(false);
    let mut crc = flate2::Crc::new();
    let mut made = 0u64;
    let mut finished = e.method == 0 && e.packed == 0;
    while at < end && !finished {
        let want = (end - at).min(u64::from(crate::sftp::CHUNK));
        let input = read_at(s, file, at, want).await?;
        if input.is_empty() {
            bail!("{} runs past the end of the archive", e.name);
        }
        at += input.len() as u64;
        let pieces = if e.method == 0 {
            vec![input]
        } else {
            let mut pieces = Vec::new();
            let mut used = 0usize;
            loop {
                let mut buf = vec![0u8; 64 * 1024];
                let (in_before, out_before) = (inflate.total_in(), inflate.total_out());
                let status = inflate
                    .decompress(&input[used..], &mut buf, flate2::FlushDecompress::None)
                    .map_err(|err| anyhow!("{} is damaged: {err}", e.name))?;
                let took = (inflate.total_in() - in_before) as usize;
                let gave = (inflate.total_out() - out_before) as usize;
                used += took;
                buf.truncate(gave);
                if !buf.is_empty() {
                    pieces.push(buf);
                }
                if status == flate2::Status::StreamEnd {
                    finished = true;
                    break;
                }
                if took == 0 && gave == 0 {
                    break;
                }
            }
            pieces
        };
        for piece in pieces {
            made += piece.len() as u64;
            if made > e.size {
                bail!("{} unpacks to more than the {} B it states", e.name, e.size);
            }
            crc.update(&piece);
            match &mut sink {
                Sink::Send(tx) => put(tx, piece).await?,
                Sink::File(out, at) => {
                    s.write(out, *at, &piece).await?;
                    *at += piece.len() as u64;
                }
            }
        }
    }
    if made != e.size || crc.sum() != e.crc {
        bail!("{} is damaged: what it unpacks to does not match what the archive states", e.name);
    }
    Ok(())
}

/// An entry of an archive as the archive window lists it.
pub struct ArchiveRow {
    pub index: usize,
    pub name: String,
    pub dir: bool,
    pub look: Look,
    pub size: String,
    /// Why it cannot be downloaded or unpacked, when it cannot.
    pub why: String,
}

#[derive(Template)]
#[template(path = "files_archive.html")]
struct ArchivePart {
    path: String,
    csrf: String,
    summary: String,
    rows: Vec<ArchiveRow>,
}

fn entry_problem(e: &zip::Listed) -> String {
    if zip::safe_path(&e.name).is_none() {
        "Its path would leave the folder, so it is never unpacked".into()
    } else if e.encrypted {
        "Encrypted".into()
    } else if e.kind == zip::Kind::Link {
        "A link, which is not unpacked".into()
    } else if e.kind == zip::Kind::File && e.method != 0 && e.method != 8 {
        format!("Packed with method {}, which this server does not unpack", e.method)
    } else {
        String::new()
    }
}

/// Opens a zip archive and reads its entries; the file stays open.
async fn open_zip(who: &Who, path: &str) -> Result<(Opened, Vec<zip::Listed>), Early> {
    let mut opened = open_file(who, path).await?;
    let Some(size) = opened.size else {
        close_unsent(&mut opened, path).await;
        return Err(Box::new((StatusCode::UNPROCESSABLE_ENTITY, "The server gives no size for this archive.").into_response()));
    };
    let listed = match opened.held.as_mut() {
        Some(conn) => zip_entries(&mut conn.sftp, &opened.file, size).await,
        None => Err(anyhow!("the file browser has no connection")),
    };
    match listed {
        Ok(entries) => Ok((opened, entries)),
        Err(e) => {
            if sftp::broken(&e) {
                *opened.held = None;
            } else {
                close_unsent(&mut opened, path).await;
            }
            Err(Box::new(refused(&e)))
        }
    }
}

/// How much of a tar stream is read at a time to stream or pass over an
/// entry's data.
const TAR_PIECE: u64 = 64 * 1024;

/// A tar stream read over sftp as it goes: a plain .tar straight from the
/// file, or a .tar.gz or .tgz inflated, the whole of it.
struct TarSource {
    /// The next byte of the file to read.
    pos: u64,
    size: u64,
    gz: Option<flate2::write::MultiGzDecoder<Vec<u8>>>,
    /// Bytes of the tar stream read and not yet taken.
    buf: Vec<u8>,
}

impl TarSource {
    fn new(size: u64, archive: Archive) -> TarSource {
        let gz = if archive == Archive::TarGz { Some(flate2::write::MultiGzDecoder::new(Vec::new())) } else { None };
        TarSource { pos: 0, size, gz, buf: Vec::new() }
    }

    /// Reads until `n` bytes wait, or the stream ends; whether they wait.
    async fn fill(&mut self, s: &mut Sftp, file: &[u8], n: usize) -> Result<bool> {
        while self.buf.len() < n {
            if self.pos >= self.size {
                if let Some(gz) = self.gz.as_mut() {
                    gz.try_finish().map_err(|e| anyhow!("the archive's compressed data ends early: {e}"))?;
                    self.buf.append(gz.get_mut());
                }
                return Ok(self.buf.len() >= n);
            }
            let Some(chunk) = s.read(file, self.pos).await? else { bail!("the archive is shorter than the server says") };
            self.pos += chunk.len() as u64;
            match self.gz.as_mut() {
                Some(gz) => {
                    std::io::Write::write_all(gz, &chunk).map_err(|e| anyhow!("the archive's compressed data is damaged: {e}"))?;
                    self.buf.append(gz.get_mut());
                }
                None => self.buf.extend_from_slice(&chunk),
            }
        }
        Ok(true)
    }

    /// Takes the next `n` bytes, which the stream must hold.
    async fn take(&mut self, s: &mut Sftp, file: &[u8], n: usize) -> Result<Vec<u8>> {
        if !self.fill(s, file, n).await? {
            bail!("the archive ends inside an entry");
        }
        Ok(self.buf.drain(..n).collect())
    }

    /// Passes over the next `n` bytes, a piece at a time.
    async fn skip(&mut self, s: &mut Sftp, file: &[u8], n: u64) -> Result<()> {
        let held = (self.buf.len() as u64).min(n);
        self.buf.drain(..held as usize);
        let mut rest = n - held;
        if self.gz.is_none() {
            self.pos += rest;
            if self.pos > self.size {
                bail!("the archive ends inside an entry");
            }
            return Ok(());
        }
        while rest > 0 {
            let piece = rest.min(TAR_PIECE);
            self.take(s, file, piece as usize).await?;
            rest -= piece;
        }
        Ok(())
    }

    /// The next entry, its data still to come; None at the end.
    async fn next(&mut self, s: &mut Sftp, file: &[u8], reader: &mut tar::Reader) -> Result<Option<tar::Entry>> {
        loop {
            if !self.fill(s, file, tar::BLOCK as usize).await? {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                bail!("the archive ends inside a header");
            }
            let block = self.take(s, file, tar::BLOCK as usize).await?;
            match reader.header(&block)? {
                tar::Step::End => return Ok(None),
                tar::Step::Extension { typeflag, size } => {
                    let len = usize::try_from(size).map_err(|e| anyhow!("an extension header of {size} B: {e}"))?;
                    let data = self.take(s, file, len).await?;
                    reader.extension(typeflag, &data)?;
                    self.skip(s, file, tar::padding(size)).await?;
                }
                tar::Step::Entry(e) => return Ok(Some(e)),
            }
        }
    }
}

/// Every entry of a tar archive, its data passed over.
async fn tar_entries(s: &mut Sftp, file: &[u8], size: u64, archive: Archive) -> Result<Vec<tar::Entry>> {
    let mut src = TarSource::new(size, archive);
    let mut reader = tar::Reader::default();
    let mut out = Vec::new();
    while let Some(e) = src.next(s, file, &mut reader).await? {
        src.skip(s, file, e.size + tar::padding(e.size)).await?;
        out.push(e);
    }
    Ok(out)
}

/// The entry at `index`, with the stream at the start of its data.
async fn tar_find(s: &mut Sftp, file: &[u8], size: u64, archive: Archive, index: usize) -> Result<Option<(TarSource, tar::Entry)>> {
    let mut src = TarSource::new(size, archive);
    let mut reader = tar::Reader::default();
    let mut at = 0;
    while let Some(e) = src.next(s, file, &mut reader).await? {
        if at == index {
            return Ok(Some((src, e)));
        }
        src.skip(s, file, e.size + tar::padding(e.size)).await?;
        at += 1;
    }
    Ok(None)
}

fn tar_problem(e: &tar::Entry) -> String {
    if zip::safe_path(&e.name).is_none() {
        "Its path would leave the folder, so it is never unpacked".into()
    } else if e.kind == tar::Kind::Link {
        "A link, which is not unpacked".into()
    } else if e.kind == tar::Kind::Other {
        "Not a file or a folder, so it is not unpacked".into()
    } else {
        String::new()
    }
}

/// Opens a tar archive and its size; the file stays open.
async fn open_tar(who: &Who, path: &str) -> Result<(Opened, u64), Early> {
    let mut opened = open_file(who, path).await?;
    match opened.size {
        Some(size) => Ok((opened, size)),
        None => {
            close_unsent(&mut opened, path).await;
            Err(Box::new((StatusCode::UNPROCESSABLE_ENTITY, "The server gives no size for this archive.").into_response()))
        }
    }
}

/// Ends a tar request that failed: a broken connection is dropped, else the
/// archive is closed.
async fn tar_failed(opened: &mut Opened, path: &str, e: &anyhow::Error) -> Response {
    if sftp::broken(e) {
        *opened.held = None;
    } else {
        close_unsent(opened, path).await;
    }
    refused(e)
}

/// The archive window's list of a tar archive's entries.
async fn tar_archive(who: &Who, path: String, archive: Archive) -> Response {
    let (mut opened, size) = match open_tar(who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    let listed = match opened.held.as_mut() {
        Some(conn) => tar_entries(&mut conn.sftp, &opened.file, size, archive).await,
        None => Err(anyhow!("the file browser has no connection")),
    };
    let entries = match listed {
        Ok(entries) => entries,
        Err(e) => return tar_failed(&mut opened, &path, &e).await,
    };
    close_unsent(&mut opened, &path).await;
    let files = entries.iter().filter(|e| e.kind != tar::Kind::Dir).count();
    let total: u64 = entries.iter().filter(|e| e.kind == tar::Kind::File).map(|e| e.size).sum();
    let rows = entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let dir = e.kind == tar::Kind::Dir;
            let attrs = Attrs { size: Some(e.size), mode: Some(if dir { 0o040_755 } else { 0o100_644 }), modified: None };
            ArchiveRow {
                index,
                name: e.name.clone(),
                dir,
                look: look(e.name.trim_end_matches('/'), &attrs),
                size: if dir { String::new() } else { crate::pages::size_label(e.size) },
                why: tar_problem(e),
            }
        })
        .collect();
    let summary = format!("{}, {} unpacked", plural(files, "file"), crate::pages::size_label(total));
    app::render(StatusCode::OK, &ArchivePart { path, csrf: who.csrf.clone(), summary, rows })
}

/// One file of a tar archive, streamed as it downloads.
async fn tar_entry(who: &Who, path: String, archive: Archive, index: usize) -> Response {
    let (mut opened, size) = match open_tar(who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    let found = match opened.held.as_mut() {
        Some(conn) => tar_find(&mut conn.sftp, &opened.file, size, archive, index).await,
        None => Err(anyhow!("the file browser has no connection")),
    };
    let (src, e) = match found {
        Ok(Some(found)) => found,
        Ok(None) => {
            close_unsent(&mut opened, &path).await;
            return (StatusCode::UNPROCESSABLE_ENTITY, "There is no such entry in this archive.").into_response();
        }
        Err(err) => return tar_failed(&mut opened, &path, &err).await,
    };
    let problem = if e.kind == tar::Kind::File { tar_problem(&e) } else { "Only a file in an archive downloads on its own.".to_string() };
    if !problem.is_empty() {
        close_unsent(&mut opened, &path).await;
        return (StatusCode::UNPROCESSABLE_ENTITY, problem).into_response();
    }
    let named = match disposition("attachment", name_of(&e.name)) {
        Ok(v) => v,
        Err(res) => {
            close_unsent(&mut opened, &path).await;
            return *res;
        }
    };
    crate::browser::record(who, sftp_webui::events::Kind::Download, &path, &e.name, e.size);
    let length = e.size;
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let Opened { mut held, file, .. } = opened;
        let Some(conn) = held.as_mut() else { return };
        let mut src = src;
        let mut rest = e.size;
        let mut sent: Result<()> = Ok(());
        while rest > 0 && sent.is_ok() {
            let piece = rest.min(TAR_PIECE);
            sent = match src.take(&mut conn.sftp, &file, piece as usize).await {
                Ok(bytes) => put(&tx, bytes).await,
                Err(err) => Err(err),
            };
            rest -= piece;
        }
        let closed = conn.sftp.close(&file).await;
        if let Err(err) = &sent {
            crate::log(&format!("file browser: unpacking {} from {path}: {err:#}", e.name));
            if tx.send(Err(std::io::Error::other(format!("{err:#}")))).await.is_err() {
                crate::log("file browser: the entry's download ended before its error could be sent");
            }
        }
        if let Err(err) = &closed {
            crate::log(&format!("file browser: closing {path}: {err:#}"));
        }
        if sent.as_ref().is_err_and(sftp::broken) || closed.as_ref().is_err_and(sftp::broken) {
            *held = None;
        }
    });
    let mut res = Body::new(Chunks(rx)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, named);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    res
}

/// Unpacks a tar archive into the folder that holds it, in one pass. An
/// entry whose path would leave that folder, a link, anything that is not a
/// file or a folder, and a name that is already taken are each refused by
/// name; everything else is unpacked.
async fn tar_extract(b: &Browser, who: &Who, path: String, archive: Archive) -> Response {
    let folder = parent_of(&path);
    let (mut opened, size) = match open_tar(who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    let mut problems = Vec::new();
    let mut broke = None;
    if let Some(conn) = opened.held.as_mut() {
        let s = &mut conn.sftp;
        let file = &opened.file;
        let mut src = TarSource::new(size, archive);
        let mut reader = tar::Reader::default();
        loop {
            let e = match src.next(s, file, &mut reader).await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    broke = Some(err);
                    break;
                }
            };
            let why = tar_problem(&e);
            let target = match zip::safe_path(&e.name) {
                Some(rel) if why.is_empty() => Some(child(&folder, &rel)),
                Some(_) | None => None,
            };
            // The outer error is the stream's, which ends the pass; the inner
            // one is this entry's alone.
            let done: Result<Result<()>> = match (&target, e.kind) {
                (None, _) => {
                    problems.push(format!("{} was not unpacked: {}", e.name, why.to_lowercase()));
                    src.skip(s, file, e.size + tar::padding(e.size)).await.map(Ok)
                }
                (Some(t), tar::Kind::Dir) => {
                    let made = make_folders(s, t, true).await;
                    match src.skip(s, file, e.size + tar::padding(e.size)).await {
                        Ok(()) => Ok(made.map(|()| crate::browser::record(who, sftp_webui::events::Kind::Mkdir, t, "", 0))),
                        Err(err) => Err(err),
                    }
                }
                (Some(t), _) => match tar_unpack_file(s, &mut src, file, &e, t).await {
                    Ok(wrote) => Ok(wrote.map(|()| crate::browser::record(who, sftp_webui::events::Kind::Copy, t, &path, e.size))),
                    Err(err) => Err(err),
                },
            };
            match done {
                Ok(Ok(())) => {}
                Ok(Err(err)) if sftp::broken(&err) => {
                    broke = Some(err);
                    break;
                }
                Ok(Err(err)) => problems.push(format!("{} was not unpacked: {err:#}", e.name)),
                Err(err) => {
                    broke = Some(err);
                    break;
                }
            }
        }
    }
    match broke {
        Some(err) if sftp::broken(&err) => {
            *opened.held = None;
            return refused(&err);
        }
        Some(err) => problems.push(format!("{err:#}")),
        None => {}
    }
    close_unsent(&mut opened, &path).await;
    // The folder's page reads over the same connection, so its lock goes first.
    drop(opened);
    after(b, who, &folder, problems).await
}

/// Writes the next `e.size` bytes of the stream to `target`, made new, and
/// leaves the stream after the entry's data and padding, written or not.
/// The outer error is the stream's; the inner one is the entry's alone.
async fn tar_unpack_file(s: &mut Sftp, src: &mut TarSource, file: &[u8], e: &tar::Entry, target: &str) -> Result<Result<()>> {
    let opened = match make_folders(s, target, false).await {
        Ok(()) => s.open_write(target, Write::New).await,
        Err(err) => Err(err),
    };
    let out = match opened {
        Ok(out) => out,
        Err(err) => {
            src.skip(s, file, e.size + tar::padding(e.size)).await?;
            return Ok(Err(err));
        }
    };
    let mut written = 0u64;
    let mut wrote: Result<()> = Ok(());
    while written < e.size {
        let piece = (e.size - written).min(TAR_PIECE);
        let bytes = src.take(s, file, piece as usize).await?;
        if wrote.is_ok() {
            wrote = s.write(&out, written, &bytes).await;
        }
        written += piece;
    }
    let closed = s.close(&out).await;
    src.skip(s, file, tar::padding(e.size)).await?;
    Ok(wrote.and(closed))
}

/// The archive window's list of an archive's entries, zip or tar.
pub async fn archive(Extension(who): Extension<Who>, Query(q): Query<PathQuery>) -> Response {
    let path = clean(&q.path);
    if let Some(kind @ (Archive::Tar | Archive::TarGz)) = archive_of(&path) {
        return tar_archive(&who, path, kind).await;
    }
    let (mut opened, entries) = match open_zip(&who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    close_unsent(&mut opened, &path).await;
    let files = entries.iter().filter(|e| e.kind != zip::Kind::Dir).count();
    let total: u64 = entries.iter().filter(|e| e.kind == zip::Kind::File).map(|e| e.size).sum();
    let rows = entries
        .iter()
        .enumerate()
        .map(|(index, e)| {
            let dir = e.kind == zip::Kind::Dir;
            let attrs = Attrs { size: Some(e.size), mode: Some(if dir { 0o040_755 } else { 0o100_644 }), modified: None };
            ArchiveRow {
                index,
                name: e.name.clone(),
                dir,
                look: look(e.name.trim_end_matches('/'), &attrs),
                size: if dir { String::new() } else { crate::pages::size_label(e.size) },
                why: entry_problem(e),
            }
        })
        .collect();
    let summary = format!("{}, {} unpacked", plural(files, "file"), crate::pages::size_label(total));
    app::render(StatusCode::OK, &ArchivePart { path, csrf: who.csrf.clone(), summary, rows })
}

#[derive(Deserialize)]
pub struct EntryQuery {
    #[serde(default)]
    path: String,
    entry: usize,
}

/// One file of an archive, zip or tar, unpacked as it downloads.
pub async fn archive_entry(Extension(who): Extension<Who>, Query(q): Query<EntryQuery>) -> Response {
    let path = clean(&q.path);
    if let Some(kind @ (Archive::Tar | Archive::TarGz)) = archive_of(&path) {
        return tar_entry(&who, path, kind, q.entry).await;
    }
    let (mut opened, mut entries) = match open_zip(&who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    let problem = match entries.get(q.entry) {
        None => "There is no such entry in this archive.".to_string(),
        Some(e) if e.kind != zip::Kind::File => "Only a file in an archive downloads on its own.".to_string(),
        Some(e) => entry_problem(e),
    };
    if !problem.is_empty() {
        close_unsent(&mut opened, &path).await;
        return (StatusCode::UNPROCESSABLE_ENTITY, problem).into_response();
    }
    let e = entries.swap_remove(q.entry);
    let named = match disposition("attachment", name_of(&e.name)) {
        Ok(v) => v,
        Err(res) => {
            close_unsent(&mut opened, &path).await;
            return *res;
        }
    };
    let size = e.size;
    crate::browser::record(&who, sftp_webui::events::Kind::Download, &path, &e.name, size);
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let Opened { mut held, file, .. } = opened;
        let Some(conn) = held.as_mut() else { return };
        let sent = unpack_entry(&mut conn.sftp, &file, &e, Sink::Send(&tx)).await;
        let closed = conn.sftp.close(&file).await;
        if let Err(err) = &sent {
            crate::log(&format!("file browser: unpacking {} from {path}: {err:#}", e.name));
            if tx.send(Err(std::io::Error::other(format!("{err:#}")))).await.is_err() {
                crate::log("file browser: the entry's download ended before its error could be sent");
            }
        }
        if let Err(err) = &closed {
            crate::log(&format!("file browser: closing {path}: {err:#}"));
        }
        if sent.as_ref().is_err_and(sftp::broken) || closed.as_ref().is_err_and(sftp::broken) {
            *held = None;
        }
    });
    let mut res = Body::new(Chunks(rx)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, named);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    res
}

/// Unpacks an archive into the folder that holds it; a tar goes to
/// `tar_extract`. Of a zip, an entry whose path
/// would leave that folder, a link, an encrypted entry and a name that is
/// already taken are each refused by name; everything else is unpacked.
pub async fn archive_extract(State(b): Shared, Extension(who): Extension<Who>, body: Bytes) -> Response {
    let form = match Fields::read(&body) {
        Ok(f) => f,
        Err(e) => return refused(&e),
    };
    let path = clean(&form.one("path"));
    if let Some(kind @ (Archive::Tar | Archive::TarGz)) = archive_of(&path) {
        return tar_extract(&b, &who, path, kind).await;
    }
    let folder = parent_of(&path);
    let (opened, entries) = match open_zip(&who, &path).await {
        Ok(found) => found,
        Err(res) => return *res,
    };
    let Opened { mut held, file, .. } = opened;
    let mut problems = Vec::new();
    let mut broke = None;
    if let Some(conn) = held.as_mut() {
        let s = &mut conn.sftp;
        for e in &entries {
            let why = entry_problem(e);
            if !why.is_empty() {
                problems.push(format!("{} was not unpacked: {}", e.name, why.to_lowercase()));
                continue;
            }
            let Some(rel) = zip::safe_path(&e.name) else { continue };
            let target = child(&folder, &rel);
            let dir = e.kind == zip::Kind::Dir;
            let done = if dir { make_folders(s, &target, true).await } else { unpack_to(s, &file, e, &target).await };
            match done {
                Ok(()) if dir => crate::browser::record(&who, sftp_webui::events::Kind::Mkdir, &target, "", 0),
                Ok(()) => crate::browser::record(&who, sftp_webui::events::Kind::Copy, &target, &path, e.size),
                Err(err) => {
                    if sftp::broken(&err) {
                        broke = Some(err);
                        break;
                    }
                    problems.push(format!("{} was not unpacked: {err:#}", e.name));
                }
            }
        }
        if broke.is_none()
            && let Err(err) = s.close(&file).await
        {
            crate::log(&format!("file browser: closing {path}: {err:#}"));
            if sftp::broken(&err) {
                broke = Some(err);
            }
        }
    }
    if let Some(err) = broke {
        *held = None;
        problems.push(format!("unpacking stopped: {err:#}"));
    }
    drop(held);
    after(&b, &who, &folder, problems).await
}

/// Unpacks one entry into a new file at `target`, making the folders above
/// it; a name already taken is refused.
async fn unpack_to(s: &mut Sftp, archive: &[u8], e: &zip::Listed, target: &str) -> Result<()> {
    make_folders(s, target, false).await?;
    let out = s.open_write(target, Write::New).await?;
    let wrote = unpack_entry(s, archive, e, Sink::File(&out, 0)).await;
    let closed = s.close(&out).await;
    wrote?;
    closed
}

/// What a Range header asks of a file.
#[derive(Debug, PartialEq, Eq)]
enum Want {
    Whole,
    /// From the first byte up to, not including, the second.
    Part(u64, u64),
    /// Nothing the file holds.
    Outside,
}

fn number(text: &str) -> Option<u64> {
    match text.parse::<u64>() {
        Ok(n) => Some(n),
        Err(e) => {
            crate::log(&format!("file browser: a range names {text:?}: {e}"));
            None
        }
    }
}

/// One range of bytes=first-last, bytes=first- or bytes=-count, of a file
/// of `size` bytes; anything else, several ranges among them, is answered
/// with the whole file.
fn wanted(header: Option<&str>, size: u64) -> Want {
    let Some(spec) = header.and_then(|h| h.trim().strip_prefix("bytes=")) else { return Want::Whole };
    if spec.contains(',') {
        return Want::Whole;
    }
    let Some((first, last)) = spec.split_once('-') else { return Want::Whole };
    let (first, last) = (first.trim(), last.trim());
    if first.is_empty() {
        return match number(last) {
            Some(0) => Want::Outside,
            Some(_) if size == 0 => Want::Outside,
            Some(count) => Want::Part(size.saturating_sub(count), size),
            None => Want::Whole,
        };
    }
    let Some(start) = number(first) else { return Want::Whole };
    if start >= size {
        return Want::Outside;
    }
    if last.is_empty() {
        return Want::Part(start, size);
    }
    match number(last) {
        Some(end) if end >= start => Want::Part(start, end.saturating_add(1).min(size)),
        Some(_) | None => Want::Whole,
    }
}

/// The policy of a preview. A picture, text or media sits in a sandbox that
/// runs no script, should it be opened as a page. A PDF opens in the
/// browser's own viewer, which a sandbox would block, and only after its
/// first bytes show it is a PDF. Only this server's pages may frame either.
const PREVIEW_CSP: &str = "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; \
    style-src 'unsafe-inline'; frame-ancestors 'self'";
const PDF_CSP: &str = "frame-ancestors 'self'";

fn preview_headers(h: &mut HeaderMap, kind: &str, content_type: &'static str, named: HeaderValue) {
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    h.insert(header::CONTENT_DISPOSITION, named);
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("SAMEORIGIN"));
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(if kind == "pdf" { PDF_CSP } else { PREVIEW_CSP }));
}

/// Serves a file for its preview, as the type its name says when that type
/// is one the browser shows, and a range of it when asked, as media players
/// and the text preview ask.
pub async fn preview(Extension(who): Extension<Who>, Query(q): Query<PathQuery>, headers: HeaderMap) -> Response {
    let path = clean(&q.path);
    let Some((kind, content_type)) = preview_of(name_of(&path)) else {
        return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "This kind of file has no preview; download it instead.").into_response();
    };
    // An SVG is shown only as a picture, which never runs its scripts.
    let dest = headers.get("sec-fetch-dest").map(app::header_text);
    if content_type == "image/svg+xml" && dest.as_deref().is_some_and(|d| d != "image") {
        return (StatusCode::FORBIDDEN, "An SVG file is shown only as a picture.").into_response();
    }
    let named = match disposition("inline", &path) {
        Ok(v) => v,
        Err(res) => return *res,
    };
    let mut opened = match open_file(&who, &path).await {
        Ok(o) => o,
        Err(res) => return *res,
    };
    crate::browser::record(&who, sftp_webui::events::Kind::Download, &path, "", opened.size.into_iter().sum());
    if kind == "pdf" {
        let head = match opened.held.as_mut() {
            Some(conn) => conn.sftp.read(&opened.file, 0).await,
            None => Err(anyhow!("the file browser has no connection")),
        };
        match head {
            Ok(first) if first.as_deref().is_some_and(|b| b.starts_with(b"%PDF-")) => {}
            Ok(_) => {
                close_unsent(&mut opened, &path).await;
                return (StatusCode::UNSUPPORTED_MEDIA_TYPE, "This file does not start as a PDF does; download it instead.")
                    .into_response();
            }
            Err(e) => {
                crate::log(&format!("file browser: reading {path}: {e:#}"));
                if sftp::broken(&e) {
                    *opened.held = None;
                } else {
                    close_unsent(&mut opened, &path).await;
                }
                return refused(&e);
            }
        }
    }
    let Some(size) = opened.size else {
        let mut res = stream(opened, path, 0, None).into_response();
        preview_headers(res.headers_mut(), kind, content_type, named);
        return res;
    };
    let range = headers.get(header::RANGE).map(app::header_text);
    let (status, start, end) = match wanted(range.as_deref(), size) {
        Want::Whole => (StatusCode::OK, 0, size),
        Want::Part(start, end) => (StatusCode::PARTIAL_CONTENT, start, end),
        Want::Outside => {
            close_unsent(&mut opened, &path).await;
            let unmet = match header_value(format!("bytes */{size}")) {
                Ok(v) => v,
                Err(res) => return *res,
            };
            let mut res = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
            res.headers_mut().insert(header::CONTENT_RANGE, unmet);
            return res;
        }
    };
    let part = if status == StatusCode::PARTIAL_CONTENT {
        match header_value(format!("bytes {start}-{}/{size}", end - 1)) {
            Ok(v) => Some(v),
            Err(res) => {
                close_unsent(&mut opened, &path).await;
                return *res;
            }
        }
    } else {
        None
    };
    let mut res = stream(opened, path, start, Some(end)).into_response();
    *res.status_mut() = status;
    let h = res.headers_mut();
    preview_headers(h, kind, content_type, named);
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(end - start));
    if let Some(v) = part {
        h.insert(header::CONTENT_RANGE, v);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_paths_and_keeps_them_inside() {
        assert_eq!(clean("/a/../../b/./c/"), "/b/c");
        assert_eq!(clean(""), "/");
        assert_eq!(parent_of("/a/b"), "/a");
        assert_eq!(parent_of("/a"), "/");
        assert!(within("/a/b", "/a"));
        assert!(within("/a", "/a"));
        assert!(!within("/ab", "/a"));
        assert!(within("/x", "/"));
    }

    #[test]
    fn sorts_numbers_as_numbers() {
        let mut names = vec!["file10", "File2", "file1", "a"];
        names.sort_by(|a, b| natural(a, b));
        assert_eq!(names, vec!["a", "file1", "File2", "file10"]);
        // Equal numbers fall back to the names as written, so two names
        // never compare equal.
        assert_ne!(natural("x007", "x7"), Ordering::Equal);
        assert_eq!(natural("b", "b"), Ordering::Equal);
    }

    #[test]
    fn reads_one_range_and_answers_anything_else_whole() {
        assert_eq!(wanted(None, 100), Want::Whole);
        assert_eq!(wanted(Some("bytes=0-9"), 100), Want::Part(0, 10));
        assert_eq!(wanted(Some("bytes=90-"), 100), Want::Part(90, 100));
        assert_eq!(wanted(Some("bytes=-10"), 100), Want::Part(90, 100));
        assert_eq!(wanted(Some("bytes=95-200"), 100), Want::Part(95, 100));
        assert_eq!(wanted(Some("bytes=100-"), 100), Want::Outside);
        assert_eq!(wanted(Some("bytes=-0"), 100), Want::Outside);
        assert_eq!(wanted(Some("bytes=0-0"), 0), Want::Outside);
        assert_eq!(wanted(Some("bytes=0-1,5-6"), 100), Want::Whole);
        assert_eq!(wanted(Some("bytes=9-3"), 100), Want::Whole);
        assert_eq!(wanted(Some("items=0-9"), 100), Want::Whole);
    }

    #[test]
    fn previews_only_what_a_browser_shows_safely() {
        assert_eq!(preview_of("a.PNG"), Some(("image", "image/png")));
        assert_eq!(preview_of("x.pdf"), Some(("pdf", "application/pdf")));
        assert_eq!(preview_of("page.html"), Some(("text", "text/plain; charset=utf-8")));
        assert_eq!(preview_of("Makefile"), Some(("text", "text/plain; charset=utf-8")));
        assert_eq!(preview_of(".bashrc"), Some(("text", "text/plain; charset=utf-8")));
        assert_eq!(preview_of("tool.exe"), None);
    }

    #[test]
    fn offers_lengths_within_the_longest_with_the_default_chosen() {
        let policy = sftp_webui::proto::SharePolicy { allowed: true, default_days: 14, max_days: 20, password_required: false };
        let offered: Vec<(u32, bool)> = share_choice(&policy).options.iter().map(|o| (o.days, o.selected)).collect();
        assert_eq!(offered, vec![(1, false), (7, false), (14, true), (20, false)]);
    }

    #[test]
    fn refuses_names_that_are_not_one_segment() {
        assert!(plain_name("ok.txt").is_ok());
        for bad in ["", " ", ".", "..", "a/b", "a\nb"] {
            assert!(plain_name(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn grows_the_tree_along_the_path() {
        let chain = vec!["/".to_string(), "/a".to_string()];
        let kids = vec![vec!["a".to_string(), "b".to_string()], vec!["c".to_string()]];
        let mut out = Vec::new();
        grow(0, &chain, &kids, "/a", &mut out);
        let seen: Vec<(String, usize, bool)> = out.iter().map(|t| (t.path.clone(), t.depth, t.current)).collect();
        assert_eq!(
            seen,
            vec![("/a".into(), 1, true), ("/a/c".into(), 2, false), ("/b".into(), 1, false)]
        );
    }
}
