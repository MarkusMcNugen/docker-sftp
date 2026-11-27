//! The file browser: accounts with web access sign in here, on a port of
//! their own, with a web password and a second factor that the root helper
//! checks. This process runs as its own system account, sftp-files, and
//! reaches the helper on a socket that takes only sign-in and certificate
//! requests, so it never holds the stored passwords or second factors.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

use crate::sftp::Sftp;

use anyhow::{Context, Result, anyhow, bail};
use askama::Template;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Path, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Form, Router};
use serde::Deserialize;
use sftp_webui::auth::{self, Refusal, Throttle};
use sftp_webui::proto::{self, FilesRequest, Reply, Secret, SignedIn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::app::{self, Client, Peer, lock};
use crate::assets::Assets;
use crate::config::Config;
use crate::fm;
use crate::pages::Layout;
use crate::server;
use crate::share;

const TLS_DIR: &str = "/config/browser/tls";
const COOKIE: &str = "__Host-sftp_files";
pub(crate) const LOGIN_COOKIE: &str = "__Host-sftp_files_login";
/// A session ends after half an hour unused or twelve hours in all, as the
/// helper's sessions do.
const IDLE: Duration = Duration::from_secs(30 * 60);
const LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const NEED_CODE: &str = "enter the code from the authenticator app";

struct Session {
    account: String,
    /// The helper's session, which certificates are asked for with.
    helper: String,
    csrf: String,
    started: Instant,
    used: Instant,
    /// An sftp connection for each account the session acts as: its own,
    /// and each it manages that it has opened.
    links: HashMap<String, Link>,
}

/// A session's sftp connection, made on first use.
type Link = Arc<AsyncMutex<Option<Conn>>>;

pub(crate) struct Conn {
    pub(crate) sftp: Sftp,
    /// Holds the session's key and certificate; removed with the connection.
    _keys: KeyDir,
    made: Instant,
}

/// A connection is made again once its certificate has expired, so a change
/// to the account's sftp settings reaches the file browser within that time.
const CONN_LIFE: Duration = Duration::from_secs(5 * 60);

/// A private directory that is removed when this value is dropped.
struct KeyDir(PathBuf);

impl Drop for KeyDir {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            crate::log(&format!("file browser: cannot remove {}: {e}", self.0.display()));
        }
    }
}

/// The session's connection: a new ed25519 key, a certificate for it from
/// the root helper, and ssh to the loopback sshd as the account.
async fn connect(who: &Who) -> Result<Conn> {
    let acting = if who.acting == who.account { None } else { Some(who.acting.clone()) };
    let helper = who.helper.clone();
    connect_signed(&who.acting, async |public_key| {
        let reply = ask(&FilesRequest::Certificate { session: Secret(helper), public_key, acting }).await?;
        if !reply.ok {
            bail!("{}", reply.error);
        }
        serde_json::from_value(reply.data).context("the helper sent no certificate")
    })
    .await
}

/// A connection as `account` with a new ed25519 key, which `certify` has
/// the root helper sign; the key lives in a private directory removed with
/// the connection.
pub(crate) async fn connect_signed(account: &str, certify: impl AsyncFnOnce(String) -> Result<String>) -> Result<Conn> {
    let dir = std::env::temp_dir().join(format!("sftp-files-{}", auth::token()?));
    std::fs::create_dir(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
    let keys = KeyDir(dir.clone());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("cannot set the mode of {}", dir.display()))?;
    let key = dir.join("key");
    let made = tokio::process::Command::new("/usr/bin/ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "sftp-files", "-f"])
        .arg(&key)
        .env_clear()
        .output()
        .await
        .context("cannot run ssh-keygen")?;
    if !made.status.success() {
        bail!("ssh-keygen: {}", String::from_utf8_lossy(&made.stderr).trim());
    }
    let public = std::fs::read_to_string(dir.join("key.pub")).context("ssh-keygen wrote no public key")?;
    let certificate = certify(public).await?;
    let cert_path = dir.join("key-cert.pub");
    std::fs::write(&cert_path, format!("{certificate}\n")).with_context(|| format!("cannot write {}", cert_path.display()))?;
    let sftp = Sftp::connect(account, &key, &cert_path).await?;
    Ok(Conn { sftp, _keys: keys, made: Instant::now() })
}

/// The session's connection, held for one request; made when there is none
/// or the one there has outlived its certificate.
pub(crate) async fn sftp_of(who: &Who) -> Result<OwnedMutexGuard<Option<Conn>>> {
    let mut held = Arc::clone(&who.link).lock_owned().await;
    if held.as_ref().is_some_and(|c| c.made.elapsed() >= CONN_LIFE) {
        *held = None;
    }
    if held.is_none() {
        *held = Some(connect(who).await?);
    }
    Ok(held)
}

pub struct Browser {
    config: Config,
    pub(crate) assets: Assets,
    sessions: Mutex<HashMap<String, Session>>,
    pub(crate) throttle: Mutex<Throttle>,
    check: app::CountryCheck,
}

type Shared = State<Arc<Browser>>;

/// The signed-in person, for the handlers behind the guard.
#[derive(Clone)]
pub(crate) struct Who {
    pub(crate) account: String,
    /// Whose files this request reads and changes: the account itself, or
    /// one it manages, under /m/<account>/.
    pub(crate) acting: String,
    pub(crate) csrf: String,
    /// The address the request came from.
    pub(crate) address: String,
    cookie: String,
    helper: String,
    link: Link,
}

impl Browser {
    /// The person a session cookie belongs to, while the session lives,
    /// acting as `acting` or, with none, as the account itself.
    fn who(&self, cookie: &str, acting: Option<&str>) -> Option<Who> {
        let now = Instant::now();
        let mut sessions = lock(&self.sessions);
        sessions.retain(|_, s| now.duration_since(s.used) < IDLE && now.duration_since(s.started) < LIFETIME);
        let s = sessions.get_mut(cookie)?;
        s.used = now;
        let acting = match acting {
            Some(other) => other.to_string(),
            None => s.account.clone(),
        };
        let link = Arc::clone(s.links.entry(acting.clone()).or_insert_with(|| Arc::new(AsyncMutex::new(None))));
        Some(Who {
            account: s.account.clone(),
            acting,
            csrf: s.csrf.clone(),
            address: String::new(),
            cookie: cookie.to_string(),
            helper: s.helper.clone(),
            link,
        })
    }
}

/// Logs to the auth log something done in the file browser, for the
/// history: what, by whom, in whose files and from where.
pub(crate) fn record(who: &Who, kind: sftp_webui::events::Kind, path: &str, other: &str, bytes: u64) {
    emit(&sftp_webui::events::WebEvent {
        kind,
        actor: who.account.clone(),
        account: who.acting.clone(),
        address: who.address.clone(),
        path: path.to_string(),
        other: other.to_string(),
        bytes,
    });
}

/// Logs a sign-in to the file browser, for the history; `account` is the
/// name given.
fn record_sign_in(kind: sftp_webui::events::Kind, account: &str, address: &str) {
    emit(&sftp_webui::events::WebEvent {
        kind,
        actor: account.to_string(),
        account: account.to_string(),
        address: address.to_string(),
        path: String::new(),
        other: String::new(),
        bytes: 0,
    });
}

pub(crate) fn emit(event: &sftp_webui::events::WebEvent) {
    match sftp_webui::events::web_event_message(event) {
        Ok(message) => crate::pages::syslog(false, &message),
        Err(why) => crate::log(&why),
    }
}

impl Who {
    /// The root helper's session, which requests about it name.
    pub(crate) fn helper_session(&self) -> String {
        self.helper.clone()
    }
}

/// The account a path acts as, under /m/<account>/, and the path below it;
/// None for a path outside that prefix.
fn acting_of(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("/m/")?;
    let (account, below) = match rest.split_once('/') {
        Some((account, below)) => (account, below),
        None => (rest, ""),
    };
    if account.is_empty() {
        return None;
    }
    Some((account, below))
}

pub async fn run(config: Config) -> Result<()> {
    let acceptor = server::acceptor(&config, TLS_DIR)?;
    let port = config.port;
    let trusted = config.trusted_proxies.clone();
    let browser = Arc::new(Browser {
        config,
        assets: Assets::new(),
        sessions: Mutex::new(HashMap::new()),
        throttle: Mutex::new(Throttle::new()),
        check: app::CountryCheck::default(),
    });
    let bulk = DefaultBodyLimit::max(fm::BULK_BODY);
    let router = Router::new()
        .route("/login", get(login_page).post(login))
        .route("/invite", get(invite_page).post(invite))
        .route("/logout", post(logout))
        .route("/static/{file}", get(static_file))
        .route("/links", get(share::links))
        .route("/links/revoke", post(share::revoke))
        .route("/s", get(share::page))
        .route("/s/info", post(share::info))
        .route("/s/get", post(share::get))
        .merge(file_routes("", bulk))
        .merge(file_routes("/m/{account}", bulk))
        .fallback(not_found)
        .layer(middleware::from_fn(page_policy))
        .layer(middleware::from_fn_with_state(Arc::clone(&browser), guard))
        .layer(DefaultBodyLimit::max(app::MAX_BODY))
        .layer(middleware::from_fn(app::headers))
        .with_state(browser);
    // No download survives a restart, so no share link stays claimed.
    match ask(&FilesRequest::ShareReset).await {
        Ok(reply) if reply.ok => {}
        Ok(reply) => crate::log(&format!("file browser: share links were not given back: {}", reply.error)),
        Err(e) => crate::log(&format!("file browser: share links were not given back: {e:#}")),
    }
    let listener = server::bind(port).await?;
    crate::log(&format!("file browser listening on port {port}"));
    server::accept_loop(listener, acceptor, router, trusted).await
}

/// The file manager's routes below `prefix`: the account's own files at the
/// top, and an account it manages below /m/<account>. The pages link
/// relatively, so the same pages work below either.
fn file_routes(prefix: &str, bulk: DefaultBodyLimit) -> Router<Arc<Browser>> {
    let at = |rest: &str| format!("{prefix}{rest}");
    Router::new()
        .route(&at("/"), get(fm::home))
        .route(&at("/details"), get(fm::details))
        .route(&at("/open"), get(fm::open))
        .route(&at("/size"), get(fm::size))
        .route(&at("/download"), get(fm::download))
        .route(&at("/mkdir"), post(fm::mkdir))
        .route(&at("/mkdirs"), post(fm::mkdirs))
        .route(&at("/rename"), post(fm::rename))
        .route(&at("/delete"), post(fm::delete).layer(bulk))
        .route(&at("/move"), post(fm::move_to).layer(bulk))
        .route(&at("/copy"), post(fm::copy_to).layer(bulk))
        .route(&at("/zip"), get(fm::zip_one).post(fm::zip_many).layer(bulk))
        .route(&at("/upload"), put(fm::upload))
        .route(&at("/preview"), get(fm::preview))
        .route(&at("/search"), get(fm::search))
        .route(&at("/archive"), get(fm::archive))
        .route(&at("/archive/entry"), get(fm::archive_entry))
        .route(&at("/archive/extract"), post(fm::archive_extract))
        .route(&at("/share"), post(crate::share::create))
}

/// The admin web UI's policy, with media and frames from this server for
/// the previews.
const PAGE_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
    media-src 'self'; frame-src 'self'; font-src 'self'; connect-src 'self'; form-action 'self'; \
    frame-ancestors 'none'; base-uri 'none'";

/// Gives a response the file browser's page policy unless it set its own.
async fn page_policy(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    if !res.headers().contains_key(header::CONTENT_SECURITY_POLICY) {
        res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(PAGE_CSP));
    }
    res
}

/// Every request: the client's address and the country rules, the
/// same-origin rule for changes, a session for every page but sign-in,
/// invites and assets, and a form token on every change, the sign-in form's
/// own before a session exists.
async fn guard(State(b): Shared, mut req: Request, next: Next) -> Response {
    let Some(peer) = req.extensions().get::<Peer>().map(|p| p.0) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "no peer address").into_response();
    };
    let client = app::client_address(&b.config, peer, req.headers());
    if !b.check.admits(client) {
        return app::forbidden("This server does not accept connections from your location.");
    }
    req.extensions_mut().insert(Client(client));
    let full_path = req.uri().path().to_string();
    // Below /m/<account>/ the session acts as an account it manages; the
    // rules below apply to the path inside that prefix.
    let (acting, path) = match acting_of(&full_path) {
        Some((account, below)) => (Some(account.to_string()), format!("/{below}")),
        None => (None, full_path.clone()),
    };
    let public = acting.is_none()
        && (matches!(path.as_str(), "/login" | "/invite" | "/s" | "/s/info" | "/s/get") || path.starts_with("/static/"));
    let change = req.method() != Method::GET && req.method() != Method::HEAD;
    if change && !app::same_origin(req.headers()) {
        return app::forbidden("This request came from another site.");
    }
    let who = match app::cookie(req.headers(), COOKIE) {
        Some(c) => b.who(&c, acting.as_deref()),
        None => None,
    };
    if !public {
        let Some(w) = &who else { return signed_out(req.headers()) };
        let check = |acting: Option<String>| FilesRequest::Check {
            session: Secret(w.helper.clone()),
            address: client.to_string(),
            acting,
        };
        match ask(&check(acting.clone())).await {
            Ok(reply) if reply.ok => {}
            Ok(reply) => {
                // Refused as the account it acts as, the session itself may
                // still be good; only a session that fails alone is ended.
                if acting.is_some() {
                    match ask(&check(None)).await {
                        Ok(own) if own.ok => return app::forbidden(&capitalized(&reply.error)),
                        Ok(_) => {}
                        Err(e) => return failure(&e),
                    }
                }
                lock(&b.sessions).remove(&w.cookie);
                crate::log(&format!("file browser: the session of {} ended: {}", w.account, reply.error));
                return signed_out(req.headers());
            }
            Err(e) => return failure(&e),
        }
    }
    // A change sent by the page's scripts, every upload among them, carries
    // the form token in a header, and its body is never read here; a plain
    // form carries it as a field.
    let header = req.headers().get("x-csrf-token").map(app::header_text);
    if change && !public && (header.is_some() || path == "/upload") {
        let valid = match (who.as_ref(), header) {
            (Some(w), Some(g)) => auth::same(w.csrf.as_bytes(), g.as_bytes()),
            (None, _) | (_, None) => false,
        };
        if !valid {
            return app::forbidden("This form has expired. Reload the page and try again.");
        }
    } else if change {
        let (parts, body) = req.into_parts();
        let limit = if fm::carries_selection(&path) { fm::BULK_BODY } else { app::MAX_BODY };
        let bytes = match axum::body::to_bytes(body, limit).await {
            Ok(b) => b,
            Err(e) => return (StatusCode::PAYLOAD_TOO_LARGE, format!("the request is too large: {e}")).into_response(),
        };
        let (expected, given) = if public {
            (app::cookie(&parts.headers, LOGIN_COOKIE), app::form_field(&bytes, "login_token"))
        } else {
            (who.as_ref().map(|w| w.csrf.clone()), app::form_field(&bytes, "csrf"))
        };
        let valid = match (expected, given) {
            (Some(e), Some(g)) => !e.is_empty() && auth::same(e.as_bytes(), g.as_bytes()),
            (None, _) | (_, None) => false,
        };
        if !valid {
            return app::forbidden("This form has expired. Reload the page and try again.");
        }
        req = Request::from_parts(parts, Body::from(bytes));
    }
    if let Some(mut w) = who {
        w.address = client.to_string();
        req.extensions_mut().insert(w);
    }
    next.run(req).await
}

/// Sends a person without a live session to the sign-in page. A page that
/// htmx swaps in is told to load the sign-in page whole; another script's
/// request gets the reason instead of the page.
fn signed_out(headers: &HeaderMap) -> Response {
    if headers.contains_key("hx-request") {
        let mut res = (StatusCode::UNAUTHORIZED, "Your session has ended. Sign in again.").into_response();
        res.headers_mut().insert("hx-redirect", HeaderValue::from_static("/login"));
        return res;
    }
    let navigating = match headers.get("sec-fetch-mode") {
        Some(mode) => mode == "navigate",
        None => true,
    };
    if navigating {
        app::redirect("/login")
    } else {
        (StatusCode::UNAUTHORIZED, "Your session has ended. Sign in again.").into_response()
    }
}

/// The accounts the signed-in account manages, for the sidebar.
pub(crate) async fn managed(who: &Who) -> Result<Vec<String>> {
    let reply = ask(&FilesRequest::Managed { session: Secret(who.helper.clone()) }).await?;
    if !reply.ok {
        bail!("{}", reply.error);
    }
    serde_json::from_value(reply.data).context("the helper sent no list of accounts")
}

/// Sends one request to the root helper on the file browser's socket.
pub(crate) async fn ask(request: &FilesRequest) -> Result<Reply> {
    let mut stream = tokio::net::UnixStream::connect(proto::FILES_SOCKET).await.context("cannot reach the root helper")?;
    let mut line = serde_json::to_vec(request).context("cannot encode the request")?;
    line.push(b'\n');
    stream.write_all(&line).await.context("cannot send the request")?;
    stream.shutdown().await.context("cannot finish the request")?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.context("cannot read the reply")?;
    serde_json::from_slice(&raw).context("the root helper's reply cannot be read")
}

#[derive(Template)]
#[template(path = "browser.html")]
struct Page {
    l: Layout,
    /// login, invite or invalid.
    mode: &'static str,
    error: String,
    notice: String,
    name: String,
    login_token: String,
    token: String,
    qr: String,
    secret: String,
    min_password: usize,
}

pub(crate) fn layout(b: &Browser, title: &str, csrf: &str) -> Layout {
    Layout {
        title: title.into(),
        heading: title.into(),
        initials: String::new(),
        tone: "",
        role_label: "",
        nav: "",
        admin: String::new(),
        full: false,
        csrf: csrf.into(),
        flash: Vec::new(),
        css: b.assets.css.clone(),
        js: b.assets.js.clone(),
        htmx: b.assets.htmx.clone(),
        favicon: b.assets.favicon.clone(),
    }
}

fn page(b: &Browser, mode: &'static str, title: &str) -> Page {
    Page {
        l: layout(b, title, ""),
        mode,
        error: String::new(),
        notice: String::new(),
        name: String::new(),
        login_token: String::new(),
        token: String::new(),
        qr: String::new(),
        secret: String::new(),
        min_password: auth::MIN_PASSWORD,
    }
}

pub(crate) fn failure(e: &anyhow::Error) -> Response {
    crate::log(&format!("file browser: {e:#}"));
    (StatusCode::INTERNAL_SERVER_ERROR, "The file browser cannot reach the server's helper. Try again shortly.").into_response()
}

/// A public form, with a fresh form token in the page and in a cookie.
fn public_form(status: StatusCode, mut p: Page) -> Response {
    let token = match auth::token() {
        Ok(t) => t,
        Err(e) => return failure(&e),
    };
    p.login_token = token.clone();
    let mut res = app::render(status, &p);
    match app::set_cookie(LOGIN_COOKIE, &token) {
        Ok(v) => {
            res.headers_mut().append(header::SET_COOKIE, v);
            res
        }
        Err(e) => failure(&e),
    }
}

async fn login_page(State(b): Shared, who: Option<Extension<Who>>) -> Response {
    if who.is_some() {
        return app::redirect("/");
    }
    public_form(StatusCode::OK, page(&b, "login", "Sign in"))
}

#[derive(Deserialize)]
struct LoginForm {
    name: String,
    password: String,
    #[serde(default)]
    code: String,
}

async fn login(State(b): Shared, Extension(client): Extension<Client>, Form(f): Form<LoginForm>) -> Response {
    let ip = client.0;
    let refused = |error: String| {
        let mut p = page(&b, "login", "Sign in");
        p.error = error;
        p.name = f.name.clone();
        public_form(StatusCode::UNAUTHORIZED, p)
    };
    if let Err(r) = lock(&b.throttle).check(ip, Instant::now()) {
        let wait = match r {
            Refusal::Locked(d) | Refusal::Busy(d) => d.as_secs().div_ceil(60),
        };
        return refused(format!("Too many failed sign-ins. Try again in {wait} minutes."));
    }
    let request = FilesRequest::SignIn {
        account: f.name.trim().to_string(),
        password: Secret(f.password.clone()),
        code: f.code.clone(),
        address: ip.to_string(),
    };
    let reply = match ask(&request).await {
        Ok(r) => r,
        Err(e) => return failure(&e),
    };
    if !reply.ok {
        let error = reply.error.as_str();
        if error == sftp_webui::signin::HELD {
            record_sign_in(sftp_webui::events::Kind::LoginHeld, f.name.trim(), &ip.to_string());
        } else if error == sftp_webui::signin::LOCKED {
            record_sign_in(sftp_webui::events::Kind::LoginRefused, f.name.trim(), &ip.to_string());
        } else if error != NEED_CODE {
            lock(&b.throttle).failure(ip, Instant::now());
            crate::pages::syslog(true, &format!("failed login from {ip} (file browser)"));
            record_sign_in(sftp_webui::events::Kind::LoginFailed, f.name.trim(), &ip.to_string());
        }
        return refused(capitalized(&reply.error));
    }
    lock(&b.throttle).success(ip);
    let signed: SignedIn = match serde_json::from_value(reply.data).context("the helper sent no session") {
        Ok(s) => s,
        Err(e) => return failure(&e),
    };
    record_sign_in(sftp_webui::events::Kind::LoginOk, &signed.account, &ip.to_string());
    let (cookie, csrf) = match (auth::token(), auth::token()) {
        (Ok(c), Ok(t)) => (c, t),
        (Err(e), _) | (_, Err(e)) => return failure(&e),
    };
    let now = Instant::now();
    lock(&b.sessions).insert(
        cookie.clone(),
        Session {
            account: signed.account,
            helper: signed.session,
            csrf,
            started: now,
            used: now,
            links: HashMap::new(),
        },
    );
    let mut res = app::redirect("/");
    for value in [app::set_cookie(COOKIE, &cookie), app::clear_cookie(LOGIN_COOKIE)] {
        match value {
            Ok(v) => {
                res.headers_mut().append(header::SET_COOKIE, v);
            }
            Err(e) => return failure(&e),
        }
    }
    res
}

/// The helper's message as a sentence on the page.
pub(crate) fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

#[derive(Deserialize)]
struct TokenQuery {
    #[serde(default)]
    token: String,
}

/// The invite form for the account a sign-in link is for, with a new
/// second-factor secret to scan.
fn invite_form(b: &Browser, account: &str, token: &str, secret: &[u8], error: String) -> Response {
    let (qr, base32) = match crate::pages::enrollment(secret, account) {
        Ok(pair) => pair,
        Err(e) => return failure(&e),
    };
    let mut p = page(b, "invite", "Set up your sign-in");
    p.name = account.to_string();
    p.token = token.to_string();
    p.qr = qr;
    p.secret = base32;
    p.error = error;
    public_form(StatusCode::OK, p)
}

async fn invite_page(State(b): Shared, Query(q): Query<TokenQuery>) -> Response {
    let reply = match ask(&FilesRequest::Invite { token: Secret(q.token.clone()) }).await {
        Ok(r) => r,
        Err(e) => return failure(&e),
    };
    if !reply.ok {
        return app::render(StatusCode::NOT_FOUND, &page(&b, "invalid", "Sign-in link"));
    }
    let account: String = match serde_json::from_value(reply.data) {
        Ok(a) => a,
        Err(e) => return failure(&anyhow!("the helper sent no account: {e}")),
    };
    let secret = match auth::random_bytes(20) {
        Ok(s) => s,
        Err(e) => return failure(&e),
    };
    invite_form(&b, &account, &q.token, &secret, String::new())
}

#[derive(Deserialize)]
struct InviteForm {
    token: String,
    name: String,
    password: String,
    confirm: String,
    secret: String,
    code: String,
}

async fn invite(State(b): Shared, Form(f): Form<InviteForm>) -> Response {
    let secret = match totp_rs::Secret::try_from_base32(&f.secret) {
        Ok(s) => s.to_vec(),
        Err(e) => return failure(&anyhow!("the form's second-factor secret cannot be read: {e}")),
    };
    if f.password != f.confirm {
        return invite_form(&b, &f.name, &f.token, &secret, "The two passwords differ.".into());
    }
    let request = FilesRequest::Enroll {
        token: Secret(f.token.clone()),
        password: Secret(f.password.clone()),
        totp_secret: Secret(f.secret.clone()),
        code: f.code.clone(),
    };
    let reply = match ask(&request).await {
        Ok(r) => r,
        Err(e) => return failure(&e),
    };
    if !reply.ok {
        return invite_form(&b, &f.name, &f.token, &secret, capitalized(&reply.error));
    }
    let mut p = page(&b, "login", "Sign in");
    p.notice = "Your sign-in is ready. Sign in with your new password and a code from the app.".into();
    p.name = f.name;
    public_form(StatusCode::OK, p)
}

async fn logout(State(b): Shared, Extension(who): Extension<Who>) -> Response {
    let helper = lock(&b.sessions).remove(&who.cookie).map(|s| s.helper);
    if let Some(session) = helper
        && let Err(e) = ask(&FilesRequest::SignOut { session: Secret(session) }).await
    {
        crate::log(&format!("file browser: cannot end the helper's session: {e:#}"));
    }
    let mut res = app::redirect("/login");
    match app::clear_cookie(COOKIE) {
        Ok(v) => {
            res.headers_mut().append(header::SET_COOKIE, v);
            res
        }
        Err(e) => failure(&e),
    }
}

async fn static_file(State(b): Shared, Path(file): Path<String>) -> Response {
    match b.assets.get(&file) {
        Some(asset) => {
            let mut res = asset.body.into_response();
            let h = res.headers_mut();
            h.insert(header::CONTENT_TYPE, HeaderValue::from_static(asset.content_type));
            h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=31536000, immutable"));
            res
        }
        None => (StatusCode::NOT_FOUND, "not found").into_response(),
    }
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "There is no such page.").into_response()
}
