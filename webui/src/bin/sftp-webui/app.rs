//! Shared state, the routes, and the guard every request passes: client
//! address, session, CSRF and origin checks, and the read-only role.

use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant, SystemTime};

use anyhow::Result;
use askama::Template;
use axum::Router;
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use sftp_webui::net;
use sftp_webui::proto::Actor;

use crate::assets::Assets;
use crate::auth::{self, Hasher, Throttle};
use crate::config::Config;
use crate::pages;
use crate::sessions::{self, Flash, Sessions};
use crate::store::{Role, Store};

/// Requests and form bodies are at most 64 KiB.
pub const MAX_BODY: usize = 64 * 1024;
const SETUP_LIFETIME: Duration = Duration::from_secs(60 * 60);

const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; \
    connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

/// The address a TCP connection comes from.
#[derive(Clone, Copy)]
pub struct Peer(pub IpAddr);

/// The client's address: the peer, or for a trusted proxy the address it
/// forwards in X-Forwarded-For.
#[derive(Clone, Copy)]
pub struct Client(pub IpAddr);

/// The logged-in admin, when there is one.
#[derive(Clone)]
pub struct Ctx {
    pub admin: String,
    pub role: Role,
    pub csrf: String,
    pub cookie: String,
}

#[derive(Clone)]
pub struct MaybeCtx(pub Option<Ctx>);

pub struct SetupToken {
    pub sha256: String,
    pub expires: Instant,
}

pub struct App {
    pub config: Config,
    pub store: Mutex<Store>,
    pub sessions: Mutex<Sessions>,
    pub throttle: Mutex<Throttle>,
    pub hasher: Hasher,
    pub setup: Mutex<Option<SetupToken>>,
    pub assets: Assets,
    pub check: CountryCheck,
}

/// The country database and its countries' names.
pub struct CountryData {
    /// None when no database could be read.
    pub db: Option<sftp_webui::geo::Countries>,
    /// Every country the database knows, by code, with its English name.
    pub names: Vec<(String, String)>,
    /// The first database file present when this was loaded, and when that
    /// file was written.
    seen: Option<(&'static str, SystemTime)>,
}

/// How often the web UI looks for a changed country database.
const COUNTRIES_TTL: Duration = Duration::from_secs(60);

/// The first country database file present, MaxMind's before DB-IP's, and
/// when it was written.
fn first_database() -> Option<(&'static str, SystemTime)> {
    for path in [sftp_webui::geo::MAXMIND_DB, sftp_webui::geo::DBIP_DB] {
        match std::fs::metadata(path).and_then(|m| m.modified()) {
            Ok(written) => return Some((path, written)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => eprintln!("countries: cannot inspect {path}: {e}"),
        }
    }
    None
}

/// MaxMind's database when present, else DB-IP's, with its countries'
/// names; a database that cannot be read is reported and the next one
/// tried.
fn load_countries() -> CountryData {
    let seen = first_database();
    for path in [sftp_webui::geo::MAXMIND_DB, sftp_webui::geo::DBIP_DB] {
        let path = std::path::Path::new(path);
        if !path.exists() {
            continue;
        }
        match sftp_webui::geo::Countries::open(path) {
            Ok(db) => {
                let names = match db.names() {
                    Ok(names) => names,
                    Err(e) => {
                        eprintln!("countries: {e:#}");
                        Vec::new()
                    }
                };
                return CountryData { db: Some(db), names, seen };
            }
            Err(e) => eprintln!("countries: {e:#}"),
        }
    }
    CountryData { db: None, names: Vec::new(), seen }
}

/// Reads a lock whose writer may have panicked; what it guards is replaced
/// whole or not at all.
fn read<T>(l: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    match l.read() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The country rules the entrypoint recorded, as last read.
#[derive(Default)]
pub struct GateCache {
    read: Option<Instant>,
    /// None while the rule is off.
    gate: Option<Arc<sftp_webui::geo::Gate>>,
    /// The last problem reported, so that a lasting one is reported once.
    problem: String,
}

/// How long the country rules read from the entrypoint's record are used
/// before the record is read again.
const GATE_TTL: Duration = Duration::from_secs(2);

/// Locks a mutex whose holder may have panicked; the data it guards is
/// written whole or not at all.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

impl App {
    pub fn new(config: Config) -> Result<App> {
        let store = Store::load(config.admin_file.as_deref())?;
        Ok(App {
            config,
            store: Mutex::new(store),
            sessions: Mutex::new(Sessions::default()),
            throttle: Mutex::new(Throttle::new()),
            hasher: Hasher::new()?,
            setup: Mutex::new(None),
            assets: Assets::new(),
            check: CountryCheck::default(),
        })
    }

    /// The country data; see CountryCheck::countries.
    pub fn countries(&self) -> Arc<CountryData> {
        self.check.countries()
    }

    /// Whether the country rules let `client` reach the web UI; see
    /// CountryCheck::admits.
    pub fn country_admits(&self, client: IpAddr) -> bool {
        self.check.admits(client)
    }
}

/// The country database and the country rules in force, as each web server
/// applies them to its clients.
pub struct CountryCheck {
    countries: RwLock<Arc<CountryData>>,
    /// When the country database files were last looked at.
    checked: Mutex<Instant>,
    gate: Mutex<GateCache>,
}

impl Default for CountryCheck {
    fn default() -> Self {
        CountryCheck {
            countries: RwLock::new(Arc::new(load_countries())),
            checked: Mutex::new(Instant::now()),
            gate: Mutex::new(GateCache::default()),
        }
    }
}

impl CountryCheck {
    /// The country data, loaded again once a database file changes, as
    /// when MaxMind GeoLite2 is downloaded or removed; the files are looked
    /// at once a minute.
    pub fn countries(&self) -> Arc<CountryData> {
        let due = {
            let mut checked = lock(&self.checked);
            let due = checked.elapsed() >= COUNTRIES_TTL;
            if due {
                *checked = Instant::now();
            }
            due
        };
        if due {
            let changed = first_database() != read(&self.countries).seen;
            if changed {
                let fresh = Arc::new(load_countries());
                match self.countries.write() {
                    Ok(mut current) => *current = fresh,
                    Err(poisoned) => *poisoned.into_inner() = fresh,
                }
            }
        }
        Arc::clone(&read(&self.countries))
    }

    /// Whether the country rules let `client` in, decided as the firewall
    /// decides. While the record of the rules in force cannot be read, only
    /// loopback, private and link-local addresses get in.
    pub fn admits(&self, client: IpAddr) -> bool {
        use sftp_webui::geo::{self, Gate};
        let gate = {
            let mut cache = lock(&self.gate);
            if cache.read.is_none_or(|t| t.elapsed() >= GATE_TTL) {
                let (gate, problem) = match geo::read_state(std::path::Path::new(geo::STATE_FILE)) {
                    Ok(None) => (None, String::new()),
                    Ok(Some(state)) => match Gate::new(Some(&state.input)) {
                        Ok(g) => (Some(g), String::new()),
                        Err(e) => (Some(Gate::sealed()), format!("{e:#}")),
                    },
                    Err(e) => match Gate::new(None) {
                        Ok(g) => (Some(g), format!("{e:#}")),
                        Err(again) => (Some(Gate::sealed()), format!("{e:#}; {again:#}")),
                    },
                };
                if !problem.is_empty() && problem != cache.problem {
                    eprintln!("country rules: {problem}");
                }
                cache.problem = problem;
                cache.gate = gate.map(Arc::new);
                cache.read = Some(Instant::now());
            }
            cache.gate.clone()
        };
        let Some(gate) = gate else { return true };
        let client = net::canonical(client);
        let data = self.countries();
        let country = match &data.db {
            Some(db) => match db.lookup(client) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("countries: {e:#}");
                    None
                }
            },
            None => None,
        };
        gate.admits(client, country.as_deref())
    }
}

impl App {
    /// With no admin at all, makes a one-hour setup token and prints its
    /// link, unless a valid one already exists.
    pub fn announce_setup(&self) {
        if !lock(&self.store).is_empty() {
            return;
        }
        let mut setup = lock(&self.setup);
        if setup.as_ref().is_some_and(|s| s.expires > Instant::now()) {
            return;
        }
        match auth::token() {
            Ok(token) => {
                *setup = Some(SetupToken {
                    sha256: auth::sha256_hex(token.as_bytes()),
                    expires: Instant::now() + SETUP_LIFETIME,
                });
                crate::log(&format!(
                    "no admin exists yet; within one hour, open https://<this server>:{}/setup?token={token} to create one",
                    self.config.port
                ));
            }
            Err(e) => crate::log(&format!("cannot make a setup link: {e:#}")),
        }
    }

    pub fn flash(&self, ctx: &Ctx, flash: Flash) {
        if let Some(session) = lock(&self.sessions).get(&ctx.cookie, false) {
            session.flash.push(flash);
        }
    }

    pub fn take_flash(&self, ctx: &Ctx) -> Vec<Flash> {
        match lock(&self.sessions).get(&ctx.cookie, false) {
            Some(session) => std::mem::take(&mut session.flash),
            None => Vec::new(),
        }
    }
}

pub fn actor(ctx: &Ctx, client: Client) -> Actor {
    Actor { admin: ctx.admin.clone(), address: client.0.to_string() }
}

pub fn render<T: Template>(status: StatusCode, page: &T) -> Response {
    match page.render() {
        Ok(html) => (status, Html(html)).into_response(),
        Err(e) => {
            crate::log(&format!("cannot render a page: {e}"));
            (StatusCode::INTERNAL_SERVER_ERROR, "the page could not be rendered").into_response()
        }
    }
}

pub fn redirect(to: &str) -> Response {
    Redirect::to(to).into_response()
}

/// A header's value as text; bytes that are not UTF-8 become U+FFFD.
pub fn header_text(value: &HeaderValue) -> String {
    String::from_utf8_lossy(value.as_bytes()).into_owned()
}

pub fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    for value in headers.get_all(header::COOKIE) {
        let text = header_text(value);
        for pair in text.split(';') {
            if let Some((k, v)) = pair.trim().split_once('=')
                && k == name
            {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// A cookie only HTTPS pages of this host can read or send.
pub fn set_cookie(name: &str, value: &str) -> Result<HeaderValue> {
    let text = format!("{name}={value}; Path=/; Secure; HttpOnly; SameSite=Strict");
    HeaderValue::from_str(&text).map_err(|e| anyhow::anyhow!("cannot set the {name} cookie: {e}"))
}

pub fn clear_cookie(name: &str) -> Result<HeaderValue> {
    let text = format!("{name}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    HeaderValue::from_str(&text).map_err(|e| anyhow::anyhow!("cannot clear the {name} cookie: {e}"))
}

pub(crate) fn client_address(config: &Config, peer: IpAddr, headers: &HeaderMap) -> IpAddr {
    if !net::any_contains(&config.trusted_proxies, peer) {
        return peer;
    }
    let mut client = peer;
    for value in headers.get_all("x-forwarded-for") {
        let text = header_text(value);
        for item in text.split(',').rev() {
            match item.trim().parse::<IpAddr>() {
                Ok(ip) => {
                    let ip = net::canonical(ip);
                    client = ip;
                    if !net::any_contains(&config.trusted_proxies, ip) {
                        return ip;
                    }
                }
                Err(e) => {
                    crate::log(&format!("ignoring the X-Forwarded-For entry {item:?} and those before it: {e}"));
                    return client;
                }
            }
        }
    }
    client
}

/// A browser marks a request from another site's page; refuse those.
pub(crate) fn same_origin(headers: &HeaderMap) -> bool {
    if let Some(site) = headers.get("sec-fetch-site") {
        return site.as_bytes() == b"same-origin";
    }
    match (headers.get(header::ORIGIN), headers.get(header::HOST)) {
        (Some(origin), Some(host)) => {
            let origin = header_text(origin);
            let host = header_text(host);
            origin == format!("https://{host}") || origin == format!("http://{host}")
        }
        (Some(_), None) => false,
        (None, _) => true,
    }
}

pub(crate) fn form_field(body: &[u8], name: &str) -> Option<String> {
    let pairs: Vec<(String, String)> = match serde_urlencoded::from_bytes(body) {
        Ok(p) => p,
        Err(e) => {
            crate::log(&format!("unreadable form: {e}"));
            return None;
        }
    };
    pairs.into_iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

pub(crate) fn forbidden(message: &str) -> Response {
    (StatusCode::FORBIDDEN, Html(pages::error_html(message))).into_response()
}

/// Paths a read-only admin may post to: its own credentials and logout.
fn read_only_allows(path: &str) -> bool {
    path == "/logout" || path.starts_with("/me/")
}

async fn guard(State(app): State<Arc<App>>, mut req: Request, next: Next) -> Response {
    let peer = match req.extensions().get::<Peer>() {
        Some(p) => p.0,
        None => return (StatusCode::INTERNAL_SERVER_ERROR, "no peer address").into_response(),
    };
    let client = client_address(&app.config, peer, req.headers());
    if !app.country_admits(client) {
        return forbidden("This server does not accept connections from your location.");
    }
    req.extensions_mut().insert(Client(client));
    let path = req.uri().path().to_string();
    let public = matches!(path.as_str(), "/login" | "/setup" | "/invite") || path.starts_with("/static/");
    let unsafe_method = req.method() != Method::GET && req.method() != Method::HEAD;
    if unsafe_method && !same_origin(req.headers()) {
        return forbidden("This request came from another site.");
    }
    let polling = req
        .headers()
        .get("hx-trigger")
        .is_some_and(|v| v.as_bytes().starts_with(b"poll-"));
    let ctx = match cookie(req.headers(), sessions::COOKIE) {
        Some(c) => lock(&app.sessions).get(&c, !polling).map(|s| Ctx {
            admin: s.admin.clone(),
            role: s.role,
            csrf: s.csrf.clone(),
            cookie: c.clone(),
        }),
        None => None,
    };
    if !public && ctx.is_none() {
        if req.headers().contains_key("hx-request") {
            let mut res = StatusCode::OK.into_response();
            res.headers_mut().insert("hx-redirect", HeaderValue::from_static("/login"));
            return res;
        }
        return redirect("/login");
    }
    if unsafe_method {
        let (parts, body) = req.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_BODY).await {
            Ok(b) => b,
            Err(e) => return (StatusCode::PAYLOAD_TOO_LARGE, format!("the request is too large: {e}")).into_response(),
        };
        if public {
            let expected = cookie(&parts.headers, sessions::LOGIN_COOKIE);
            let given = form_field(&bytes, "login_token");
            let valid = match (&expected, &given) {
                (Some(e), Some(g)) => !e.is_empty() && auth::same(e.as_bytes(), g.as_bytes()),
                (None, _) | (_, None) => false,
            };
            if !valid {
                return forbidden("This form has expired. Reload the page and try again.");
            }
        } else if let Some(ctx) = &ctx {
            let given = match parts.headers.get("x-csrf-token") {
                Some(h) => Some(header_text(h)),
                None => form_field(&bytes, "csrf"),
            };
            if !given.is_some_and(|g| auth::same(g.as_bytes(), ctx.csrf.as_bytes())) {
                return forbidden("This form has expired. Reload the page and try again.");
            }
            if ctx.role == Role::ReadOnly && !read_only_allows(&path) {
                return forbidden("Your admin role is read-only.");
            }
        }
        req = Request::from_parts(parts, Body::from(bytes));
    }
    req.extensions_mut().insert(MaybeCtx(ctx.clone()));
    if let Some(ctx) = ctx {
        req.extensions_mut().insert(ctx);
    }
    next.run(req).await
}

/// The security headers of every response. A response that sets its own
/// content security policy or framing rule, such as a file browser preview
/// with a sandbox, keeps it.
pub(crate) async fn headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    if !h.contains_key(header::CONTENT_SECURITY_POLICY) {
        h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    if !h.contains_key(header::X_FRAME_OPTIONS) {
        h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    }
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(header::STRICT_TRANSPORT_SECURITY, HeaderValue::from_static("max-age=31536000"));
    h.insert("cross-origin-opener-policy", HeaderValue::from_static("same-origin"));
    h.insert("cross-origin-resource-policy", HeaderValue::from_static("same-origin"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()"),
    );
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/login", get(pages::login_page).post(pages::login_submit))
        .route("/logout", post(pages::logout))
        .route("/setup", get(pages::setup_page).post(pages::setup_submit))
        .route("/invite", get(pages::invite_page).post(pages::invite_submit))
        .route("/static/{file}", get(pages::static_file))
        .route("/", get(pages::status_page))
        .route("/sessions", get(pages::sessions_fragment))
        .route("/sessions/end", post(pages::session_end))
        .route("/accounts", get(pages::accounts_page))
        .route("/accounts/new", get(pages::account_new).post(pages::account_create))
        .route("/accounts/hash-passwords", post(pages::hash_passwords))
        .route("/accounts/{name}", get(pages::account_page).post(pages::account_update))
        .route("/accounts/{name}/delete", post(pages::account_delete))
        .route("/accounts/{name}/keys", post(pages::key_add))
        .route("/accounts/{name}/keys/delete", post(pages::key_delete))
        .route("/groups", get(pages::groups_page))
        .route("/groups/new", get(pages::group_new).post(pages::group_create))
        .route("/groups/{name}", get(pages::group_page).post(pages::group_update))
        .route("/groups/{name}/delete", post(pages::group_delete))
        .route("/bans", get(pages::bans_page))
        .route("/bans/ban", post(pages::ban))
        .route("/bans/unban", post(pages::unban))
        .route("/bans/holds", post(pages::hold_decide))
        .route("/bans/lockdowns/lift", post(pages::lockdown_lift))
        .route("/bans/lift", post(pages::lift))
        .route("/bans/rules", post(pages::ban_rules))
        .route("/bans/countries", post(pages::country_rules))
        .route("/accounts/{name}/files-invite", post(pages::files_invite))
        .route("/accounts/{name}/files-reset", post(pages::files_reset))
        .route("/settings", get(pages::settings_page).post(pages::settings_save))
        .route("/settings/maxmind", post(pages::maxmind_save))
        .route("/settings/maxmind/delete", post(pages::maxmind_delete))
        .route("/activity", get(pages::activity_page))
        .route("/activity/rows", get(pages::activity_rows))
        .route("/activity/people", get(pages::activity_people))
        .route("/logs", get(pages::logs_page))
        .route("/logs/rows", get(pages::logs_rows))
        .route("/audit", get(pages::audit_page))
        .route("/admins", get(pages::admins_page))
        .route("/admins/invite", post(pages::admin_invite))
        .route("/admins/invites/revoke", post(pages::invite_revoke))
        .route("/admins/{name}/role", post(pages::admin_role))
        .route("/admins/{name}/totp-reset", post(pages::admin_totp_reset))
        .route("/admins/{name}/delete", post(pages::admin_delete))
        .route("/me", get(pages::me_page))
        .route("/me/password", post(pages::me_password))
        .route("/me/totp/start", post(pages::totp_start))
        .route("/me/totp/confirm", post(pages::totp_confirm))
        .route("/me/totp/disable", post(pages::totp_disable))
        .fallback(pages::not_found)
        .layer(middleware::from_fn_with_state(Arc::clone(&app), guard))
        .layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn(headers))
        .with_state(app)
}
