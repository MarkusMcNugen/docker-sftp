//! The pages and the form handlers behind them.

use std::sync::Arc;
use std::time::Instant;

use askama::Template;
use axum::Extension;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sftp_webui::net;
use sftp_webui::proto::{
    AccountInput, AccountView, Accounts, AuditPage, BanRules, BanView, Bans, GroupInput, Groups, LogPage,
    PasswordChange, Request, SettingValue, Settings, Status,
};
use sftp_webui::spec::{self, Perm};
use sftp_webui::timefmt;

use crate::app::{self, App, Client, Ctx, MaybeCtx, lock};
use crate::charts;
use crate::auth::{self, Refusal};
use crate::helper;
use crate::sessions::{self, Flash};
use crate::store::{Invite, Role, Totp};

type AppState = State<Arc<App>>;

const INVITE_LIFETIME: u64 = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Layout and shared helpers
// ---------------------------------------------------------------------------

pub struct Layout {
    pub title: String,
    /// What the page shows, in its header; an entity page uses its name.
    pub heading: String,
    pub initials: String,
    pub tone: &'static str,
    pub role_label: &'static str,
    pub nav: &'static str,
    pub admin: String,
    pub full: bool,
    pub csrf: String,
    pub flash: Vec<Flash>,
    pub css: String,
    pub js: String,
    pub htmx: String,
    pub favicon: String,
}

fn layout(app: &App, ctx: Option<&Ctx>, title: &str, nav: &'static str) -> Layout {
    let (admin, full, csrf, flash) = match ctx {
        Some(c) => (c.admin.clone(), c.role == Role::Full, c.csrf.clone(), app.take_flash(c)),
        None => (String::new(), false, String::new(), Vec::new()),
    };
    let heading = match heading_for(nav) {
        "" => title.to_string(),
        text => text.to_string(),
    };
    Layout {
        title: title.into(),
        heading,
        initials: initials(&admin),
        tone: tone(&admin),
        role_label: if full { "Full access" } else { "Read-only" },
        nav,
        admin,
        full,
        csrf,
        flash,
        css: app.assets.css.clone(),
        js: app.assets.js.clone(),
        htmx: app.assets.htmx.clone(),
        favicon: app.assets.favicon.clone(),
    }
}

/// What each page shows, for its header; the sidebar already names the page.
fn heading_for(nav: &str) -> &'static str {
    match nav {
        "status" => "Health, traffic and who is connected",
        "accounts" => "SFTP accounts and how they log in",
        "groups" => "Shared defaults for sets of accounts",
        "bans" => "Blocked addresses and the rules",
        "shares" => "Files shared by link and their state",
        "activity" => "Who is doing what, as it happens",
        "audit" => "Every change an admin made",
        "logs" => "The server's own log lines",
        "settings" => "How the server and links behave",
        "admins" => "Who can manage this server, and how",
        "me" => "Your password and two-factor sign-in",
        _ => "",
    }
}

/// Up to two letters standing for a name, for its avatar.
pub fn initials(name: &str) -> String {
    name.chars().filter(char::is_ascii_alphanumeric).take(2).collect::<String>().to_ascii_uppercase()
}

/// One of six avatar tones, always the same one for a given name.
pub fn tone(name: &str) -> &'static str {
    const TONES: [&str; 6] = ["t0", "t1", "t2", "t3", "t4", "t5"];
    let sum = name.bytes().fold(0usize, |a, b| a.wrapping_mul(31).wrapping_add(usize::from(b)));
    TONES[sum % TONES.len()]
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorPage {
    l: Layout,
    message: String,
    detail: Vec<String>,
}

/// A bare error page, for refusals before any layout exists.
pub fn error_html(message: &str) -> String {
    let page = BareError { message: message.into() };
    match page.render() {
        Ok(h) => h,
        Err(e) => format!("{message} ({e})"),
    }
}

#[derive(Template)]
#[template(path = "bare_error.html")]
struct BareError {
    message: String,
}

fn error_page(app: &App, ctx: &Ctx, nav: &'static str, message: &str) -> Response {
    let page = ErrorPage { l: layout(app, Some(ctx), "Error", nav), message: message.into(), detail: Vec::new() };
    app::render(StatusCode::INTERNAL_SERVER_ERROR, &page)
}

pub async fn not_found(State(app): AppState, Extension(m): Extension<MaybeCtx>) -> Response {
    match m.0 {
        Some(ctx) => {
            let page = ErrorPage {
                l: layout(&app, Some(&ctx), "Not found", ""),
                message: "There is no such page.".into(),
                detail: Vec::new(),
            };
            app::render(StatusCode::NOT_FOUND, &page)
        }
        None => (StatusCode::NOT_FOUND, axum::response::Html(error_html("There is no such page."))).into_response(),
    }
}

pub async fn static_file(State(app): AppState, Path(file): Path<String>) -> Response {
    match app.assets.get(&file) {
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

/// Sends a line to the auth log, which fail2ban's sftp-webui jail reads.
pub(crate) fn syslog(warning: bool, message: &str) {
    let priority = if warning { 36 } else { 38 };
    let line = format!("<{priority}>sftp-webui[{}]: {message}", std::process::id());
    let sent = std::os::unix::net::UnixDatagram::unbound().and_then(|s| s.send_to(line.as_bytes(), "/dev/log"));
    if let Err(e) = sent {
        crate::log(&format!("cannot reach syslog ({e}): {message}"));
    }
}

async fn audit(actor: sftp_webui::proto::Actor, action: &str, target: &str, outcome: &str) {
    let request = Request::Audit { actor, action: action.into(), target: target.into(), outcome: outcome.into() };
    match helper::call(&request).await {
        Ok(reply) if reply.ok => {}
        Ok(reply) => crate::log(&format!("audit entry refused: {}", reply.error)),
        Err(e) => crate::log(&format!("cannot write an audit entry: {e:#}")),
    }
}

/// Runs a change through the helper, records the outcome as a flash and
/// goes back to `back`.
async fn change(app: &App, ctx: &Ctx, request: Request, done: &str, back: &str) -> Response {
    match helper::call(&request).await {
        Ok(reply) if reply.ok => app.flash(ctx, Flash::ok(done, reply.messages)),
        Ok(reply) => app.flash(ctx, Flash::error(reply.error, reply.messages)),
        Err(e) => app.flash(ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect(back)
}

/// A local path to go back to; anything else becomes `fallback`.
fn local(path: &str, fallback: &str) -> String {
    if path.starts_with('/') && !path.starts_with("//") && !path.contains('\\') {
        path.into()
    } else {
        fallback.into()
    }
}

fn checked(field: &Option<String>) -> bool {
    field.as_deref().is_some_and(|v| !v.is_empty())
}

/// `n` with the word that fits it: "1 day", "3 days".
fn count(n: u64, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

/// A length of time in its largest whole unit: "Under a minute", "5 minutes", "2 days".
fn span(d: u64) -> String {
    match d {
        0..60 => "Under a minute".into(),
        60..3600 => count(d / 60, "minute", "minutes"),
        3600..86_400 => count(d / 3600, "hour", "hours"),
        _ => count(d / 86_400, "day", "days"),
    }
}

/// A time left in at most two units: "48 minutes", "1 hour 20 minutes", "4 days".
fn remaining(d: u64) -> String {
    let (big, small) = match d {
        0..60 => return "Under a minute".into(),
        60..3600 => return count(d / 60, "minute", "minutes"),
        3600..86_400 => (count(d / 3600, "hour", "hours"), count(d % 3600 / 60, "minute", "minutes")),
        _ => (count(d / 86_400, "day", "days"), count(d % 86_400 / 3600, "hour", "hours")),
    };
    if small.starts_with("0 ") { big } else { format!("{big} {small}") }
}

/// How long ago `secs` was: "Just now", "5 minutes ago".
fn ago(secs: u64) -> String {
    let d = timefmt::now().saturating_sub(secs);
    if d < 60 { "Just now".into() } else { format!("{} ago", span(d)) }
}

fn source_label(source: &str) -> &'static str {
    match source {
        "users.conf" => "users.conf",
        "legacy" => "/etc/sftp-users.conf",
        "users-file" => "SFTP_USERS_FILE",
        "arguments" => "container arguments",
        "environment" => "SFTP_USERS",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Login, setup, invites, logout
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "login.html")]
struct LoginPage {
    l: Layout,
    /// login, none, setup, invite or invalid.
    mode: &'static str,
    login_token: String,
    error: String,
    name: String,
    token: String,
    invite_role: String,
    min_password: usize,
}

fn login_response(status: StatusCode, mut page: LoginPage) -> Response {
    let token = match auth::token() {
        Ok(t) => t,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    };
    page.login_token = token.clone();
    let mut res = app::render(status, &page);
    match app::set_cookie(sessions::LOGIN_COOKIE, &token) {
        Ok(v) => {
            res.headers_mut().append(header::SET_COOKIE, v);
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
    .into_response()
}

fn login_view(app: &App, mode: &'static str, error: &str, name: &str) -> LoginPage {
    LoginPage {
        l: layout(app, None, "Sign in", ""),
        mode,
        login_token: String::new(),
        error: error.into(),
        name: name.into(),
        token: String::new(),
        invite_role: String::new(),
        min_password: auth::MIN_PASSWORD,
    }
}

pub async fn login_page(State(app): AppState, Extension(m): Extension<MaybeCtx>) -> Response {
    if m.0.is_some() {
        return app::redirect("/");
    }
    if lock(&app.store).is_empty() {
        app.announce_setup();
        return login_response(StatusCode::OK, login_view(&app, "none", "", ""));
    }
    login_response(StatusCode::OK, login_view(&app, "login", "", ""))
}

#[derive(Deserialize)]
pub struct LoginForm {
    name: String,
    password: String,
    #[serde(default)]
    code: String,
}

fn minutes(d: std::time::Duration) -> u64 {
    d.as_secs().div_ceil(60).max(1)
}

pub async fn login_submit(State(app): AppState, Extension(client): Extension<Client>, Form(form): Form<LoginForm>) -> Response {
    let ip = client.0;
    let name = form.name.trim().to_string();
    let refusal = lock(&app.throttle).check(ip, Instant::now());
    if let Err(refusal) = refusal {
        let text = match refusal {
            Refusal::Locked(d) => format!(
                "Too many failed logins from your address. Try again in {} minutes.",
                minutes(d)
            ),
            Refusal::Busy(d) => format!(
                "Too many failed logins on this server right now. Try again in {} seconds.",
                d.as_secs().max(1)
            ),
        };
        syslog(false, &format!("login refused from {ip}: throttled"));
        return login_response(StatusCode::TOO_MANY_REQUESTS, login_view(&app, "login", &text, &name));
    }
    let admin = lock(&app.store).get(&name);
    let verified = match app.hasher.verify(admin.as_ref().map(|a| a.hash.clone()), form.password).await {
        Ok(v) => v,
        Err(e) => {
            crate::log(&format!("login check failed: {e:#}"));
            false
        }
    };
    let mut reason = match &admin {
        Some(_) if verified => None,
        Some(a) => Some(format!("wrong password for admin {}", a.name)),
        None => Some("unknown admin name".to_string()),
    };
    if reason.is_none()
        && let Some(a) = &admin
        && let Some(t) = &a.totp
        && !net::any_contains(&app.config.trusted_networks, ip)
    {
        let step = URL_SAFE_NO_PAD
            .decode(&t.secret)
            .map_err(|e| anyhow::anyhow!("bad TOTP secret: {e}"))
            .and_then(|secret| auth::totp(&secret, &a.name))
            .map(|totp| auth::check_code(&totp, &form.code, t.last_step, timefmt::now()));
        match step {
            Ok(Some(step)) => {
                let saved = lock(&app.store).set_totp(&a.name, Some(Totp { secret: t.secret.clone(), last_step: step }));
                if let Err(e) = saved {
                    crate::log(&format!("cannot record the TOTP step: {e:#}"));
                }
            }
            Ok(None) => reason = Some(format!("wrong or reused code for admin {}", a.name)),
            Err(e) => {
                crate::log(&format!("{e:#}"));
                reason = Some(format!("unusable TOTP secret for admin {}", a.name));
            }
        }
    }
    let actor = sftp_webui::proto::Actor { admin: name.clone(), address: ip.to_string() };
    if let Some(reason) = reason {
        let locked = lock(&app.throttle).failure(ip, Instant::now());
        syslog(true, &format!("failed login from {ip} ({reason})"));
        audit(actor, "login failed", &name, &reason).await;
        let text = if locked {
            "The name, password or code is wrong. Your address is now locked out for 15 minutes.".to_string()
        } else {
            "The name, password or code is wrong.".to_string()
        };
        return login_response(StatusCode::UNAUTHORIZED, login_view(&app, "login", &text, &name));
    }
    let Some(admin) = admin else {
        return app::redirect("/login");
    };
    lock(&app.throttle).success(ip);
    start_session(&app, &admin.name, admin.role, ip, "/").await
}

/// Logs an admin in with a fresh session id and goes to `to`.
async fn start_session(app: &App, name: &str, role: Role, ip: std::net::IpAddr, to: &str) -> Response {
    let cookie = match lock(&app.sessions).create(name, role) {
        Ok(c) => c,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    };
    if let Err(e) = lock(&app.store).logged_in(name, timefmt::now()) {
        crate::log(&format!("cannot record the login: {e:#}"));
    }
    syslog(false, &format!("login of admin {name} from {ip}"));
    audit(sftp_webui::proto::Actor { admin: name.into(), address: ip.to_string() }, "login", name, "ok").await;
    let mut res = app::redirect(to);
    let set = app::set_cookie(sessions::COOKIE, &cookie).and_then(|session| {
        app::clear_cookie(sessions::LOGIN_COOKIE).map(|login| (session, login))
    });
    match set {
        Ok((session, login)) => {
            res.headers_mut().append(header::SET_COOKIE, session);
            res.headers_mut().append(header::SET_COOKIE, login);
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

pub async fn logout(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
) -> Response {
    lock(&app.sessions).remove(&ctx.cookie);
    audit(app::actor(&ctx, client), "logout", &ctx.admin, "ok").await;
    let mut res = app::redirect("/login");
    match app::clear_cookie(sessions::COOKIE) {
        Ok(v) => {
            res.headers_mut().append(header::SET_COOKIE, v);
            res
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct TokenQuery {
    #[serde(default)]
    token: String,
}

fn setup_token_valid(app: &App, token: &str) -> bool {
    let digest = auth::sha256_hex(token.as_bytes());
    lock(&app.setup)
        .as_ref()
        .is_some_and(|s| s.expires > Instant::now() && auth::same(s.sha256.as_bytes(), digest.as_bytes()))
}

pub async fn setup_page(State(app): AppState, Query(q): Query<TokenQuery>) -> Response {
    if !lock(&app.store).is_empty() {
        return app::redirect("/login");
    }
    if !setup_token_valid(&app, &q.token) {
        app.announce_setup();
        return login_response(StatusCode::NOT_FOUND, login_view(&app, "invalid", "", ""));
    }
    let mut page = login_view(&app, "setup", "", "admin");
    page.token = q.token;
    login_response(StatusCode::OK, page)
}

#[derive(Deserialize)]
pub struct NewAdminForm {
    token: String,
    #[serde(default)]
    name: String,
    password: String,
    confirm: String,
}

fn new_password(password: &str, confirm: &str) -> Result<(), String> {
    auth::check_password_rules(password)?;
    if password != confirm {
        return Err("the two passwords differ".into());
    }
    Ok(())
}

pub async fn setup_submit(State(app): AppState, Extension(client): Extension<Client>, Form(form): Form<NewAdminForm>) -> Response {
    if !lock(&app.store).is_empty() || !setup_token_valid(&app, &form.token) {
        return app::redirect("/login");
    }
    let name = form.name.trim().to_string();
    let checked = spec::validate_name(&name).and_then(|()| new_password(&form.password, &form.confirm));
    if let Err(e) = checked {
        let mut page = login_view(&app, "setup", &e, &name);
        page.token = form.token;
        return login_response(StatusCode::UNPROCESSABLE_ENTITY, page);
    }
    let added = app.hasher.hash(&form.password).and_then(|hash| lock(&app.store).add(&name, Role::Full, hash, timefmt::now()));
    if let Err(e) = added {
        let mut page = login_view(&app, "setup", &format!("{e:#}"), &name);
        page.token = form.token;
        return login_response(StatusCode::UNPROCESSABLE_ENTITY, page);
    }
    *lock(&app.setup) = None;
    audit(
        sftp_webui::proto::Actor { admin: name.clone(), address: client.0.to_string() },
        "first admin created",
        &name,
        "ok",
    )
    .await;
    crate::log(&format!("admin {name} created with the setup link"));
    start_session(&app, &name, Role::Full, client.0, "/me").await
}

fn find_invite(app: &App, token: &str) -> Option<Invite> {
    lock(&app.store).find_invite(&auth::sha256_hex(token.as_bytes()), timefmt::now())
}

pub async fn invite_page(State(app): AppState, Query(q): Query<TokenQuery>) -> Response {
    let Some(invite) = find_invite(&app, &q.token) else {
        return login_response(StatusCode::NOT_FOUND, login_view(&app, "invalid", "", ""));
    };
    let mut page = login_view(&app, "invite", "", &invite.name);
    page.token = q.token;
    page.invite_role = invite.role.name().into();
    login_response(StatusCode::OK, page)
}

pub async fn invite_submit(State(app): AppState, Extension(client): Extension<Client>, Form(form): Form<NewAdminForm>) -> Response {
    let Some(invite) = find_invite(&app, &form.token) else {
        return login_response(StatusCode::NOT_FOUND, login_view(&app, "invalid", "", ""));
    };
    if let Err(e) = new_password(&form.password, &form.confirm) {
        let mut page = login_view(&app, "invite", &e, &invite.name);
        page.token = form.token;
        page.invite_role = invite.role.name().into();
        return login_response(StatusCode::UNPROCESSABLE_ENTITY, page);
    }
    let added = app.hasher.hash(&form.password).and_then(|hash| {
        let mut store = lock(&app.store);
        store.remove_invite(&invite.name)?;
        store.add(&invite.name, invite.role, hash, timefmt::now())
    });
    if let Err(e) = added {
        let mut page = login_view(&app, "invite", &format!("{e:#}"), &invite.name);
        page.token = form.token;
        return login_response(StatusCode::UNPROCESSABLE_ENTITY, page);
    }
    audit(
        sftp_webui::proto::Actor { admin: invite.name.clone(), address: client.0.to_string() },
        "invite accepted",
        &invite.name,
        "ok",
    )
    .await;
    start_session(&app, &invite.name, invite.role, client.0, "/me").await
}

// ---------------------------------------------------------------------------
// Status and sessions
// ---------------------------------------------------------------------------

pub struct SessionRow {
    pub pid: u32,
    pub account: String,
    pub address: String,
    pub since: String,
    pub since_iso: String,
}

fn session_rows(status: &Status) -> Vec<SessionRow> {
    status
        .sessions
        .iter()
        .map(|s| SessionRow {
            pid: s.pid,
            account: s.account.clone(),
            address: s.address.clone(),
            since: ago(s.since),
            since_iso: timefmt::iso(s.since),
        })
        .collect()
}

#[derive(Template)]
#[template(path = "status.html")]
struct StatusPage {
    l: Layout,
    s: Status,
    uptime: String,
    sessions: Vec<SessionRow>,
    ranges: Vec<RangeChoice>,
    charts: Vec<ChartCard>,
    history_error: Option<String>,
}

/// A time range a chart page offers.
pub struct RangeChoice {
    pub value: &'static str,
    pub label: &'static str,
    pub on: bool,
}

/// A chart with its legend and the same numbers as a table.
pub struct ChartCard {
    pub title: &'static str,
    pub icon: &'static str,
    /// The chart drawn for a wide card and for a narrow one; the stylesheet
    /// shows the one that fits.
    pub wide: String,
    pub narrow: String,
    /// The legend: each series' key class and name.
    pub keys: Vec<(&'static str, &'static str)>,
    /// The table's headings: its first column, then one per value.
    pub first_column: &'static str,
    pub columns: Vec<&'static str>,
    /// Each row's label and its values in column order.
    pub rows: Vec<(String, Vec<u64>)>,
}

/// Value, label, length in seconds and bucket size in seconds.
const RANGES: [(&str, &str, u64, u64); 4] = [
    ("24h", "24 hours", 86_400, 3_600),
    ("7d", "7 days", 604_800, 21_600),
    ("30d", "30 days", 2_592_000, 86_400),
    ("90d", "90 days", 7_776_000, 86_400),
];

#[derive(Deserialize)]
pub struct RangeQuery {
    #[serde(default)]
    range: String,
}

fn range_choices(range: &str) -> (Vec<RangeChoice>, u64, u64) {
    let pick = match RANGES.iter().find(|r| r.0 == range) {
        Some(r) => *r,
        None => RANGES[0],
    };
    let choices = RANGES.iter().map(|r| RangeChoice { value: r.0, label: r.1, on: r.0 == pick.0 }).collect();
    (choices, pick.2, pick.3)
}

/// The sign-in and transfer charts over `length` seconds up to now.
async fn activity_charts(length: u64, size: u64) -> anyhow::Result<Vec<ChartCard>> {
    let now = timefmt::now();
    let to = now - now % size + size;
    let from = to.saturating_sub(length.div_ceil(size) * size);
    let series = helper::data::<sftp_webui::proto::Series>(&Request::HistorySeries { from, to, size }).await?;
    let labels: Vec<String> = series.buckets.iter().map(|b| charts::ago_label(to.saturating_sub(b.start + size))).collect();
    let pick = |f: fn(&sftp_webui::proto::Bucket) -> u64| -> Vec<u64> { series.buckets.iter().map(f).collect() };
    let card = |title, icon, a: (&'static str, &'static str, Vec<u64>), b: (&'static str, &'static str, Vec<u64>)| {
        let rows = labels.iter().enumerate().map(|(i, l)| (l.clone(), vec![a.2[i], b.2[i]])).collect();
        let key_b = if b.1 == "c2" { "s2" } else { "s3" };
        let series = [charts::Series { name: a.0, class: "c1", values: a.2 }, charts::Series { name: b.0, class: b.1, values: b.2 }];
        let wide = charts::lines(title, &labels, &series, 600.0, "wide");
        let narrow = charts::lines(title, &labels, &series, 320.0, "narrow");
        ChartCard {
            title,
            icon,
            wide,
            narrow,
            keys: vec![("", a.0), (key_b, b.0)],
            first_column: "When",
            columns: vec![a.0, b.0],
            rows,
        }
    };
    Ok(vec![
        card(
            "Sign-ins",
            "sign-in",
            ("Signed in", "c1", pick(|b| b.logins)),
            ("Failed sign-ins", "c2", pick(|b| b.failed)),
        ),
        card(
            "Transfers",
            "arrows-down-up",
            ("Uploads", "c1", pick(|b| b.uploads)),
            ("Downloads", "c3", pick(|b| b.downloads)),
        ),
    ])
}

pub async fn status_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Query(q): Query<RangeQuery>) -> Response {
    let (ranges, length, size) = range_choices(&q.range);
    let (charts, history_error) = match activity_charts(length, size).await {
        Ok(c) => (c, None),
        Err(e) => (Vec::new(), Some(format!("{e:#}"))),
    };
    match helper::data::<Status>(&Request::Status).await {
        Ok(s) => {
            let page = StatusPage {
                uptime: if s.started > 0 { span(timefmt::now().saturating_sub(s.started)) } else { "Unknown".into() },
                sessions: session_rows(&s),
                l: layout(&app, Some(&ctx), "Status", "status"),
                ranges,
                charts,
                history_error,
                s,
            };
            app::render(StatusCode::OK, &page)
        }
        Err(e) => error_page(&app, &ctx, "status", &format!("{e:#}")),
    }
}

/// What a fragment needs of the layout: the role and the CSRF token.
pub struct Mini {
    pub full: bool,
    pub csrf: String,
}

#[derive(Template)]
#[template(path = "sessions_rows.html")]
struct SessionsRows {
    l: Mini,
    sessions: Vec<SessionRow>,
}

pub async fn sessions_fragment(Extension(ctx): Extension<Ctx>) -> Response {
    match helper::data::<Status>(&Request::Status).await {
        Ok(s) => app::render(
            StatusCode::OK,
            &SessionsRows { l: Mini { full: ctx.role == Role::Full, csrf: ctx.csrf.clone() }, sessions: session_rows(&s) },
        ),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

#[derive(Deserialize)]
pub struct PidForm {
    pid: u32,
    #[serde(default)]
    back: String,
}

pub async fn session_end(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<PidForm>,
) -> Response {
    let request = Request::SessionEnd { actor: app::actor(&ctx, client), pid: form.pid };
    change(&app, &ctx, request, "Session ended.", &local(&form.back, "/")).await
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

pub struct AccountRow {
    pub name: String,
    pub source: &'static str,
    pub editable: bool,
    pub uid: u32,
    pub gid: u32,
    pub dirs: String,
    pub preset: &'static str,
    pub rsync: bool,
    pub disabled: bool,
    pub expired: bool,
    pub expires: String,
    pub limited: bool,
    pub password: String,
    pub keys: usize,
    pub sessions: usize,
}

fn preset_label(perms: &[Perm]) -> &'static str {
    match spec::preset_of(perms) {
        "full" => "Full access",
        "readonly" => "Read-only",
        "uploadonly" => "Upload-only",
        _ => "Custom",
    }
}

#[derive(Template)]
#[template(path = "accounts.html")]
struct AccountsPage {
    l: Layout,
    rows: Vec<AccountRow>,
    plain: usize,
}

pub async fn accounts_page(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    let data = match helper::data::<Accounts>(&Request::Accounts).await {
        Ok(d) => d,
        Err(e) => return error_page(&app, &ctx, "accounts", &format!("{e:#}")),
    };
    let rows = data
        .accounts
        .iter()
        .map(|a| AccountRow {
            name: a.name.clone(),
            source: source_label(&a.source),
            editable: a.editable,
            uid: a.uid,
            gid: a.gid,
            dirs: a.dirs.join(", "),
            preset: preset_label(&a.options.perms),
            rsync: a.options.rsync || a.rsync_from_env,
            disabled: a.options.disabled,
            expired: a.expired && !a.options.disabled,
            expires: match &a.options.expires {
                Some(d) => d.clone(),
                None => String::new(),
            },
            limited: !a.options.from.is_empty(),
            password: a.password.clone(),
            keys: a.keys.len(),
            sessions: a.sessions.len(),
        })
        .collect();
    let page = AccountsPage { l: layout(&app, Some(&ctx), "Accounts", "accounts"), rows, plain: data.plain_passwords };
    app::render(StatusCode::OK, &page)
}

pub struct PermBox {
    pub name: &'static str,
    pub label: &'static str,
    pub checked: bool,
}

/// The account form's fields, as submitted or as loaded.
#[derive(Clone, Default, Deserialize)]
pub struct AccountForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    password_mode: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password2: String,
    #[serde(default)]
    uid: String,
    #[serde(default)]
    gid: String,
    #[serde(default)]
    dirs: String,
    #[serde(default)]
    preset: String,
    perm_list: Option<String>,
    perm_download: Option<String>,
    perm_upload: Option<String>,
    perm_delete: Option<String>,
    perm_rename: Option<String>,
    perm_mkdir: Option<String>,
    perm_attributes: Option<String>,
    perm_links: Option<String>,
    rsync: Option<String>,
    web: Option<String>,
    disabled: Option<String>,
    #[serde(default)]
    expires: String,
    #[serde(default)]
    from: String,
    #[serde(default)]
    umask: String,
    noshare: Option<String>,
    #[serde(default)]
    sharedays: String,
    sharepassword: Option<String>,
    /// The account's groups in order, from the repeated groups fields.
    #[serde(skip)]
    groups: Vec<String>,
    /// Accounts and @groups whose files it may open, from the repeated manage fields.
    #[serde(skip)]
    manage: Vec<String>,
}

/// Splits a submitted form into the values of its repeated fields and the
/// single-valued rest, read as `T`.
fn split_form<T: serde::de::DeserializeOwned>(
    pairs: Vec<(String, String)>,
    repeated: &[&str],
) -> Result<(T, Vec<(String, String)>), String> {
    let (multi, single): (Vec<_>, Vec<_>) = pairs.into_iter().partition(|(k, _)| repeated.contains(&k.as_str()));
    let encoded = serde_urlencoded::to_string(&single).map_err(|e| format!("the form: {e}"))?;
    let form = serde_urlencoded::from_str(&encoded).map_err(|e| format!("the form: {e}"))?;
    let multi = multi.into_iter().filter(|(_, v)| !v.trim().is_empty()).map(|(k, v)| (k, v.trim().to_string())).collect();
    Ok((form, multi))
}

/// The longest share link a form sets, in days; None when the field is empty.
fn share_days(text: &str) -> Result<Option<u32>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    match spec::day_count(text) {
        Some(days) => Ok(Some(days)),
        None => Err(format!("the longest share link, {text}, is not a number of days from 1 to 999999999")),
    }
}

/// The values of one repeated field, in order, each once.
fn values_of(multi: &[(String, String)], key: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (k, v) in multi {
        if k == key && !out.contains(v) {
            out.push(v.clone());
        }
    }
    out
}

impl AccountForm {
    fn perm_fields(&self) -> [(Perm, bool); 8] {
        [
            (Perm::List, checked(&self.perm_list)),
            (Perm::Download, checked(&self.perm_download)),
            (Perm::Upload, checked(&self.perm_upload)),
            (Perm::Delete, checked(&self.perm_delete)),
            (Perm::Rename, checked(&self.perm_rename)),
            (Perm::Mkdir, checked(&self.perm_mkdir)),
            (Perm::Attributes, checked(&self.perm_attributes)),
            (Perm::Links, checked(&self.perm_links)),
        ]
    }

    fn perms(&self) -> Vec<Perm> {
        match self.preset.as_str() {
            "readonly" => spec::READONLY.to_vec(),
            "uploadonly" => spec::UPLOADONLY.to_vec(),
            "custom" => self.perm_fields().into_iter().filter(|(_, on)| *on).map(|(p, _)| p).collect(),
            _ => Perm::ALL.to_vec(),
        }
    }

    /// The form for an account as it is: its own line's options when it is in
    /// users.conf, so saving never copies what its groups give into the line.
    fn from_view(a: &AccountView) -> AccountForm {
        let o = match &a.own {
            Some(own) => own,
            None => &a.options,
        };
        let has = |p: Perm| if o.perms.contains(&p) { Some("on".to_string()) } else { None };
        let preset = if !o.perms_set && !o.groups.is_empty() { "groups" } else { spec::preset_of(&o.perms) };
        AccountForm {
            name: a.name.clone(),
            password_mode: "keep".into(),
            uid: a.uid.to_string(),
            gid: match (a.own_gid, a.own.is_some()) {
                (Some(gid), _) => gid.to_string(),
                (None, true) => String::new(),
                (None, false) => a.gid.to_string(),
            },
            dirs: a.dirs.join("\n"),
            preset: preset.into(),
            groups: o.groups.clone(),
            manage: o.manage.clone(),
            perm_list: has(Perm::List),
            perm_download: has(Perm::Download),
            perm_upload: has(Perm::Upload),
            perm_delete: has(Perm::Delete),
            perm_rename: has(Perm::Rename),
            perm_mkdir: has(Perm::Mkdir),
            perm_attributes: has(Perm::Attributes),
            perm_links: has(Perm::Links),
            rsync: if o.rsync { Some("on".into()) } else { None },
            web: if o.web { Some("on".into()) } else { None },
            disabled: if o.disabled { Some("on".into()) } else { None },
            expires: match &o.expires {
                Some(d) => d.clone(),
                None => String::new(),
            },
            from: o.from.join("\n"),
            umask: match &o.umask {
                Some(u) => u.clone(),
                None => String::new(),
            },
            noshare: if o.noshare { Some("on".into()) } else { None },
            sharedays: match o.share_days {
                Some(days) => days.to_string(),
                None => String::new(),
            },
            sharepassword: if o.share_password { Some("on".into()) } else { None },
            ..AccountForm::default()
        }
    }

    fn input(&self, create: bool) -> Result<AccountInput, String> {
        let id = |text: &str, what: &str| -> Result<Option<u32>, String> {
            let text = text.trim();
            if text.is_empty() {
                return Ok(None);
            }
            let value: u64 = text.parse().map_err(|e| format!("{what} \"{text}\" is not a number: {e}"))?;
            spec::check_id(value, what).map(Some)
        };
        let password = match self.password_mode.as_str() {
            "set" => {
                if self.password != self.password2 {
                    return Err("the two passwords differ".into());
                }
                if self.password.is_empty() {
                    return Err("type the new password twice".into());
                }
                PasswordChange::Set { value: self.password.clone() }
            }
            "clear" => PasswordChange::Clear,
            _ if create => return Err("choose a password, or public-key login only".into()),
            _ => PasswordChange::Keep,
        };
        if self.preset == "groups" && self.groups.is_empty() {
            return Err("permissions from its groups need at least one group".into());
        }
        let mut options = spec::Options {
            perms: self.perms(),
            perms_set: self.preset != "groups",
            rsync: checked(&self.rsync),
            web: checked(&self.web),
            disabled: checked(&self.disabled),
            expires: if self.expires.trim().is_empty() { None } else { Some(self.expires.trim().into()) },
            from: self.from.split(|c: char| c == ',' || c.is_whitespace()).filter(|s| !s.is_empty()).map(str::to_string).collect(),
            umask: if self.umask.trim().is_empty() { None } else { Some(self.umask.trim().into()) },
            groups: self.groups.clone(),
            manage: self.manage.clone(),
            noshare: checked(&self.noshare),
            share_days: share_days(&self.sharedays)?,
            share_password: checked(&self.sharepassword),
        };
        options.normalize()?;
        Ok(AccountInput {
            name: self.name.trim().into(),
            password,
            uid: id(&self.uid, "uid")?,
            gid: id(&self.gid, "gid")?,
            dirs: self.dirs.lines().map(str::trim).filter(|d| !d.is_empty()).map(str::to_string).collect(),
            options,
        })
    }
}

#[derive(Template)]
#[template(path = "account.html")]
struct AccountPage {
    l: Layout,
    create: bool,
    f: AccountForm,
    perms: Vec<PermBox>,
    view: Option<AccountView>,
    source: &'static str,
    editable: bool,
    sessions: Vec<SessionRow>,
    /// Groups the account is not in yet, to add.
    more_groups: Vec<String>,
    /// Accounts and @groups the account cannot open yet, to add.
    more_manage: Vec<String>,
    /// The access its groups give, when its own line leaves it to them.
    from_groups: String,
    /// The account's file browser sign-in, while the file browser is on.
    files: Option<FilesCard>,
}

/// An account's file browser sign-in, as its page shows it.
pub struct FilesCard {
    /// Web access, from its own line or its groups.
    pub web: bool,
    pub enrolled: bool,
    /// When its open sign-in link stops working, in words; empty without one.
    pub invite: String,
    pub last: String,
}

/// The host a request named, without its port; a bracketed IPv6 address
/// keeps its brackets.
fn host_without_port(host: &str) -> &str {
    if let Some(end) = host.rfind(']') {
        return &host[..=end];
    }
    match host.rsplit_once(':') {
        Some((name, _)) => name,
        None => host,
    }
}

/// Makes a file browser sign-in link for an account and shows it once.
pub async fn files_invite(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    headers: axum::http::HeaderMap,
    Path(name): Path<String>,
) -> Response {
    let back = format!("/accounts/{name}");
    let Some(port) = app.config.files_port else {
        app.flash(&ctx, Flash::error("The file browser is off; set WEBUI_FILES_ENABLED=true to use it.", Vec::new()));
        return app::redirect(&back);
    };
    let request = Request::FilesInvite { actor: app::actor(&ctx, client), account: name.clone() };
    let invite = match helper::data::<sftp_webui::proto::FilesInvite>(&request).await {
        Ok(i) => i,
        Err(e) => {
            app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new()));
            return app::redirect(&back);
        }
    };
    let host = match headers.get(header::HOST) {
        Some(h) => host_without_port(&app::header_text(h)).to_string(),
        None => "<this server>".to_string(),
    };
    let link = format!("https://{host}:{port}/invite?token={}", invite.token);
    app.flash(
        &ctx,
        Flash {
            kind: "invite",
            text: format!("Sign-in link for {name}'s file browser. Send it over a safe channel; it works once, for 24 hours:"),
            detail: vec![link],
        },
    );
    app::redirect(&back)
}

/// Removes an account's web password and second factor; it needs a new
/// sign-in link to use the file browser again.
pub async fn files_reset(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
) -> Response {
    let request = Request::FilesReset { actor: app::actor(&ctx, client), account: name.clone() };
    change(&app, &ctx, request, "File browser sign-in reset.", &format!("/accounts/{name}")).await
}

/// Every group, and every account, that the account form can offer.
struct Pickable {
    groups: Vec<String>,
    accounts: Vec<String>,
}

async fn load_pickable() -> anyhow::Result<Pickable> {
    let groups = helper::data::<Groups>(&Request::Groups).await?;
    let accounts = helper::data::<Accounts>(&Request::Accounts).await?;
    Ok(Pickable {
        groups: groups.groups.into_iter().map(|g| g.group.name).collect(),
        accounts: accounts.accounts.into_iter().map(|a| a.name).collect(),
    })
}

/// The account form from a submission; groups and manage repeat, in order.
fn account_form(pairs: Vec<(String, String)>) -> Result<AccountForm, String> {
    let (mut f, multi): (AccountForm, _) = split_form(pairs, &["groups", "manage"])?;
    f.groups = values_of(&multi, "groups");
    f.manage = values_of(&multi, "manage");
    Ok(f)
}

fn account_view(
    app: &App,
    ctx: &Ctx,
    create: bool,
    f: AccountForm,
    view: Option<AccountView>,
    pick: Pickable,
) -> AccountPage {
    let more_groups: Vec<String> = pick.groups.iter().filter(|g| !f.groups.contains(g)).cloned().collect();
    let more_manage: Vec<String> = pick
        .accounts
        .iter()
        .filter(|a| **a != f.name)
        .cloned()
        .chain(pick.groups.iter().map(|g| format!("@{g}")))
        .filter(|t| !f.manage.contains(t))
        .collect();
    let from_groups = match &view {
        Some(v) if f.preset == "groups" => preset_label(&v.options.perms).to_string(),
        _ => String::new(),
    };
    let fields = f.perm_fields();
    let perms = Perm::ALL
        .iter()
        .map(|p| PermBox {
            name: p.name(),
            label: p.label(),
            checked: if f.preset == "custom" {
                fields.iter().any(|(q, on)| q == p && *on)
            } else {
                f.perms().contains(p)
            },
        })
        .collect();
    let (source, editable, sessions) = match &view {
        Some(v) => (
            source_label(&v.source),
            v.editable,
            v.sessions
                .iter()
                .map(|s| SessionRow {
                    pid: s.pid,
                    account: s.account.clone(),
                    address: s.address.clone(),
                    since: ago(s.since),
                    since_iso: timefmt::iso(s.since),
                })
                .collect(),
        ),
        None => ("users.conf", true, Vec::new()),
    };
    let title = if create { "New account".to_string() } else { format!("Account {}", f.name) };
    let mut l = layout(app, Some(ctx), &title, "accounts");
    l.heading = if create { "Create an SFTP account".to_string() } else { f.name.clone() };
    AccountPage { l, create, f, perms, view, source, editable, sessions, more_groups, more_manage, from_groups, files: None }
}

/// The account's file browser sign-in, while the file browser is on.
async fn files_card(app: &App, view: &AccountView) -> anyhow::Result<Option<FilesCard>> {
    if app.config.files_port.is_none() {
        return Ok(None);
    }
    let logins = helper::data::<Vec<sftp_webui::proto::FilesLogin>>(&Request::FilesLogins).await?;
    let login = logins.into_iter().find(|l| l.account == view.name);
    Ok(Some(FilesCard {
        web: view.options.web,
        enrolled: login.as_ref().is_some_and(|l| l.enrolled),
        invite: match login.as_ref().and_then(|l| l.invite_expires) {
            Some(t) => remaining(t.saturating_sub(timefmt::now())),
            None => String::new(),
        },
        last: match login.as_ref().and_then(|l| l.last_sign_in) {
            Some(t) => ago(t),
            None => "Never".to_string(),
        },
    }))
}

async fn load_account(name: &str) -> anyhow::Result<Option<AccountView>> {
    let data = helper::data::<Accounts>(&Request::Accounts).await?;
    Ok(data.accounts.into_iter().find(|a| a.name == name))
}

pub async fn account_new(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    let pick = match load_pickable().await {
        Ok(p) => p,
        Err(e) => return error_page(&app, &ctx, "accounts", &format!("{e:#}")),
    };
    let f = AccountForm { preset: "full".into(), password_mode: "set".into(), ..AccountForm::default() };
    app::render(StatusCode::OK, &account_view(&app, &ctx, true, f, None, pick))
}

pub async fn account_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Path(name): Path<String>) -> Response {
    let pick = match load_pickable().await {
        Ok(p) => p,
        Err(e) => return error_page(&app, &ctx, "accounts", &format!("{e:#}")),
    };
    match load_account(&name).await {
        Ok(Some(view)) => {
            let files = match files_card(&app, &view).await {
                Ok(card) => card,
                Err(e) => return error_page(&app, &ctx, "accounts", &format!("{e:#}")),
            };
            let f = AccountForm::from_view(&view);
            let mut page = account_view(&app, &ctx, false, f, Some(view), pick);
            page.files = files;
            app::render(StatusCode::OK, &page)
        }
        Ok(None) => error_page(&app, &ctx, "accounts", &format!("There is no account named {name}.")),
        Err(e) => error_page(&app, &ctx, "accounts", &format!("{e:#}")),
    }
}

/// Shows the account form again with the values just submitted.
async fn form_again(app: &App, ctx: &Ctx, create: bool, mut f: AccountForm, flash: Flash) -> Response {
    f.password.clear();
    f.password2.clear();
    let view = if create {
        None
    } else {
        match load_account(&f.name).await {
            Ok(v) => v,
            Err(e) => return error_page(app, ctx, "accounts", &format!("{e:#}")),
        }
    };
    let pick = match load_pickable().await {
        Ok(p) => p,
        Err(e) => return error_page(app, ctx, "accounts", &format!("{e:#}")),
    };
    let mut page = account_view(app, ctx, create, f, view, pick);
    page.l.flash.push(flash);
    app::render(StatusCode::UNPROCESSABLE_ENTITY, &page)
}

async fn save_account(app: &App, ctx: &Ctx, client: Client, create: bool, f: AccountForm) -> Response {
    let input = match f.input(create) {
        Ok(i) => i,
        Err(e) => return form_again(app, ctx, create, f, Flash::error(e, Vec::new())).await,
    };
    let name = input.name.clone();
    let request = Request::AccountPut { actor: app::actor(ctx, client), create, account: input };
    match helper::call(&request).await {
        Ok(reply) if reply.ok => {
            let done = if create { format!("Account {name} created.") } else { format!("Account {name} saved.") };
            app.flash(ctx, Flash::ok(done, reply.messages));
            app::redirect(&format!("/accounts/{name}"))
        }
        Ok(reply) => form_again(app, ctx, create, f, Flash::error(reply.error, reply.messages)).await,
        Err(e) => error_page(app, ctx, "accounts", &format!("{e:#}")),
    }
}

pub async fn account_create(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match account_form(pairs) {
        Ok(f) => save_account(&app, &ctx, client, true, f).await,
        Err(e) => error_page(&app, &ctx, "accounts", &e),
    }
}

pub async fn account_update(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match account_form(pairs) {
        Ok(mut f) => {
            f.name = name;
            save_account(&app, &ctx, client, false, f).await
        }
        Err(e) => error_page(&app, &ctx, "accounts", &e),
    }
}

#[derive(Deserialize)]
pub struct DeleteForm {
    delete_keys: Option<String>,
}

pub async fn account_delete(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(form): Form<DeleteForm>,
) -> Response {
    let request = Request::AccountDelete {
        actor: app::actor(&ctx, client),
        name: name.clone(),
        delete_keys: checked(&form.delete_keys),
    };
    match helper::call(&request).await {
        Ok(reply) if reply.ok => {
            app.flash(&ctx, Flash::ok(format!("Account {name} deleted; /home/{name} is kept."), reply.messages));
            app::redirect("/accounts")
        }
        Ok(reply) => {
            app.flash(&ctx, Flash::error(reply.error, reply.messages));
            app::redirect(&format!("/accounts/{name}"))
        }
        Err(e) => error_page(&app, &ctx, "accounts", &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
pub struct KeyForm {
    #[serde(default)]
    key: String,
    #[serde(default)]
    fingerprint: String,
}

pub async fn key_add(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(form): Form<KeyForm>,
) -> Response {
    let keys: Vec<&str> = form.key.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    if keys.is_empty() {
        app.flash(&ctx, Flash::error("Paste a public key first.", Vec::new()));
        return app::redirect(&format!("/accounts/{name}"));
    }
    let mut added = 0;
    for key in keys {
        let request = Request::KeyAdd { actor: app::actor(&ctx, client), name: name.clone(), key: key.into() };
        match helper::call(&request).await {
            Ok(reply) if reply.ok => added += 1,
            Ok(reply) => app.flash(&ctx, Flash::error(reply.error, reply.messages)),
            Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
        }
    }
    if added > 0 {
        app.flash(&ctx, Flash::ok(format!("Added {added} key(s) to {name}."), Vec::new()));
    }
    app::redirect(&format!("/accounts/{name}"))
}

pub async fn key_delete(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(form): Form<KeyForm>,
) -> Response {
    let request = Request::KeyDelete { actor: app::actor(&ctx, client), name: name.clone(), fingerprint: form.fingerprint };
    change(&app, &ctx, request, "Key removed.", &format!("/accounts/{name}")).await
}

pub async fn hash_passwords(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
) -> Response {
    let request = Request::HashPasswords { actor: app::actor(&ctx, client) };
    change(&app, &ctx, request, "Plain-text passwords hashed.", "/accounts").await
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

pub struct GroupRow {
    pub name: String,
    pub members: usize,
    pub access: &'static str,
    pub gid: String,
}

#[derive(Template)]
#[template(path = "groups.html")]
struct GroupsPage {
    l: Layout,
    rows: Vec<GroupRow>,
}

pub async fn groups_page(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    let data = match helper::data::<Groups>(&Request::Groups).await {
        Ok(d) => d,
        Err(e) => return error_page(&app, &ctx, "groups", &format!("{e:#}")),
    };
    let rows = data
        .groups
        .into_iter()
        .map(|v| GroupRow {
            access: if v.group.options.perms_set { preset_label(&v.group.options.perms) } else { "No default" },
            gid: match v.group.gid {
                Some(gid) => gid.to_string(),
                None => String::new(),
            },
            members: v.members.len(),
            name: v.group.name,
        })
        .collect();
    app::render(StatusCode::OK, &GroupsPage { l: layout(&app, Some(&ctx), "Groups", "groups"), rows })
}

/// The group form's fields, as submitted or as loaded.
#[derive(Clone, Default, Deserialize)]
pub struct GroupForm {
    #[serde(default)]
    name: String,
    #[serde(default)]
    gid: String,
    /// Empty for no default, or full, readonly, uploadonly or custom.
    #[serde(default)]
    preset: String,
    /// A custom permission list from groups.conf, kept as written.
    #[serde(default)]
    perms: String,
    rsync: Option<String>,
    web: Option<String>,
    disabled: Option<String>,
    #[serde(default)]
    expires: String,
    #[serde(default)]
    umask: String,
    noshare: Option<String>,
    #[serde(default)]
    sharedays: String,
    sharepassword: Option<String>,
    #[serde(skip)]
    from: Vec<String>,
    #[serde(skip)]
    manage: Vec<String>,
    #[serde(skip)]
    members: Vec<String>,
}

impl GroupForm {
    fn from_view(v: &sftp_webui::proto::GroupView) -> GroupForm {
        let o = &v.group.options;
        GroupForm {
            name: v.group.name.clone(),
            gid: match v.group.gid {
                Some(gid) => gid.to_string(),
                None => String::new(),
            },
            preset: if o.perms_set { spec::preset_of(&o.perms).into() } else { String::new() },
            perms: o.perms.iter().map(|p| p.name()).collect::<Vec<_>>().join("+"),
            rsync: if o.rsync { Some("on".into()) } else { None },
            web: if o.web { Some("on".into()) } else { None },
            disabled: if o.disabled { Some("on".into()) } else { None },
            expires: match &o.expires {
                Some(d) => d.clone(),
                None => String::new(),
            },
            umask: match &o.umask {
                Some(u) => u.clone(),
                None => String::new(),
            },
            noshare: if o.noshare { Some("on".into()) } else { None },
            sharedays: match o.share_days {
                Some(days) => days.to_string(),
                None => String::new(),
            },
            sharepassword: if o.share_password { Some("on".into()) } else { None },
            from: o.from.clone(),
            manage: o.manage.clone(),
            members: v.members.clone(),
        }
    }

    fn input(&self) -> Result<GroupInput, String> {
        let gid = match self.gid.trim() {
            "" => None,
            text => {
                let value: u64 = text.parse().map_err(|e| format!("gid \"{text}\" is not a number: {e}"))?;
                Some(spec::check_id(value, "gid")?)
            }
        };
        let perms = match self.preset.as_str() {
            "readonly" => spec::READONLY.to_vec(),
            "uploadonly" => spec::UPLOADONLY.to_vec(),
            "custom" => spec::parse_options(&format!("perms={}", self.perms))?.perms,
            _ => Perm::ALL.to_vec(),
        };
        let mut options = spec::Options {
            perms,
            perms_set: !self.preset.is_empty(),
            rsync: checked(&self.rsync),
            web: checked(&self.web),
            disabled: checked(&self.disabled),
            expires: if self.expires.trim().is_empty() { None } else { Some(self.expires.trim().into()) },
            from: self.from.clone(),
            umask: if self.umask.trim().is_empty() { None } else { Some(self.umask.trim().into()) },
            groups: Vec::new(),
            manage: self.manage.clone(),
            noshare: checked(&self.noshare),
            share_days: share_days(&self.sharedays)?,
            share_password: checked(&self.sharepassword),
        };
        options.normalize()?;
        Ok(GroupInput {
            group: spec::Group { name: self.name.trim().into(), gid, options },
            members: self.members.clone(),
        })
    }
}

#[derive(Template)]
#[template(path = "group.html")]
struct GroupPage {
    l: Layout,
    create: bool,
    f: GroupForm,
    /// Members defined outside users.conf, shown but not changeable.
    fixed: Vec<String>,
    /// Accounts in users.conf that are not members yet, to add.
    more_members: Vec<String>,
    /// Accounts and @groups the members cannot open yet, to add.
    more_manage: Vec<String>,
}

/// The group page with the form's values; a flash, when given, says why a
/// save was refused.
async fn group_view(app: &App, ctx: &Ctx, create: bool, f: GroupForm, flash: Option<Flash>) -> Response {
    let (groups, accounts) = match (
        helper::data::<Groups>(&Request::Groups).await,
        helper::data::<Accounts>(&Request::Accounts).await,
    ) {
        (Ok(g), Ok(a)) => (g, a),
        (Err(e), _) | (_, Err(e)) => return error_page(app, ctx, "groups", &format!("{e:#}")),
    };
    let fixed = match groups.groups.iter().find(|g| !create && g.group.name == f.name) {
        Some(g) => g.fixed_members.clone(),
        None => Vec::new(),
    };
    let more_members =
        accounts.accounts.iter().filter(|a| a.editable && !f.members.contains(&a.name)).map(|a| a.name.clone()).collect();
    let more_manage = accounts
        .accounts
        .iter()
        .map(|a| a.name.clone())
        .chain(groups.groups.iter().map(|g| format!("@{}", g.group.name)))
        .filter(|t| !f.manage.contains(t) && *t != format!("@{}", f.name))
        .collect();
    let title = if create { "New group".to_string() } else { format!("Group {}", f.name) };
    let mut l = layout(app, Some(ctx), &title, "groups");
    l.heading = if create { "Create a group".to_string() } else { f.name.clone() };
    let status = match flash {
        Some(flash) => {
            l.flash.push(flash);
            StatusCode::UNPROCESSABLE_ENTITY
        }
        None => StatusCode::OK,
    };
    app::render(status, &GroupPage { l, create, f, fixed, more_members, more_manage })
}

pub async fn group_new(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    group_view(&app, &ctx, true, GroupForm::default(), None).await
}

pub async fn group_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Path(name): Path<String>) -> Response {
    match helper::data::<Groups>(&Request::Groups).await {
        Ok(data) => match data.groups.iter().find(|g| g.group.name == name) {
            Some(v) => group_view(&app, &ctx, false, GroupForm::from_view(v), None).await,
            None => error_page(&app, &ctx, "groups", &format!("There is no group named {name}.")),
        },
        Err(e) => error_page(&app, &ctx, "groups", &format!("{e:#}")),
    }
}

/// The group form from a submission; from, manage and members repeat.
fn group_form(pairs: Vec<(String, String)>) -> Result<GroupForm, String> {
    let (mut f, multi): (GroupForm, _) = split_form(pairs, &["from", "manage", "members"])?;
    f.from = values_of(&multi, "from");
    f.manage = values_of(&multi, "manage");
    f.members = values_of(&multi, "members");
    Ok(f)
}

async fn save_group(app: &App, ctx: &Ctx, client: Client, create: bool, f: GroupForm) -> Response {
    let input = match f.input() {
        Ok(i) => i,
        Err(e) => return group_view(app, ctx, create, f, Some(Flash::error(e, Vec::new()))).await,
    };
    let name = input.group.name.clone();
    let request = Request::GroupPut { actor: app::actor(ctx, client), create, group: input };
    match helper::call(&request).await {
        Ok(reply) if reply.ok => {
            let done = if create { format!("Group {name} created.") } else { format!("Group {name} saved.") };
            app.flash(ctx, Flash::ok(done, reply.messages));
            app::redirect(&format!("/groups/{name}"))
        }
        Ok(reply) => group_view(app, ctx, create, f, Some(Flash::error(reply.error, reply.messages))).await,
        Err(e) => error_page(app, ctx, "groups", &format!("{e:#}")),
    }
}

pub async fn group_create(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match group_form(pairs) {
        Ok(f) => save_group(&app, &ctx, client, true, f).await,
        Err(e) => error_page(&app, &ctx, "groups", &e),
    }
}

pub async fn group_update(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match group_form(pairs) {
        Ok(mut f) => {
            f.name = name;
            save_group(&app, &ctx, client, false, f).await
        }
        Err(e) => error_page(&app, &ctx, "groups", &e),
    }
}

pub async fn group_delete(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
) -> Response {
    let request = Request::GroupDelete { actor: app::actor(&ctx, client), name: name.clone() };
    match helper::call(&request).await {
        Ok(reply) if reply.ok => {
            app.flash(&ctx, Flash::ok(format!("Group {name} deleted; its members keep their own settings."), reply.messages));
            app::redirect("/groups")
        }
        Ok(reply) => {
            app.flash(&ctx, Flash::error(reply.error, reply.messages));
            app::redirect(&format!("/groups/{name}"))
        }
        Err(e) => error_page(&app, &ctx, "groups", &format!("{e:#}")),
    }
}

// ---------------------------------------------------------------------------
// Bans
// ---------------------------------------------------------------------------

/// One option of a dropdown chip.
pub struct Choice {
    pub value: String,
    pub label: String,
    pub selected: bool,
}

/// Seconds in a fail2ban time such as 600, 600s, 10m, 1h, 2d or 1w; -1 is forever.
fn seconds(text: &str) -> Option<i64> {
    let text = text.trim();
    if text == "-1" || text == "-1s" {
        return Some(-1);
    }
    let (digits, unit) = text.split_at(text.bytes().take_while(u8::is_ascii_digit).count());
    if digits.is_empty() {
        return None;
    }
    let mut n: i64 = 0;
    for b in digits.bytes() {
        n = n.checked_mul(10)?.checked_add(i64::from(b - b'0'))?;
    }
    let scale = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3_600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return None,
    };
    n.checked_mul(scale)
}

/// A fail2ban time in words, in its largest whole unit: "1 hour", "2 weeks"; negative is "Forever".
fn duration_label(secs: i64) -> String {
    if secs < 0 {
        return "Forever".into();
    }
    let secs = secs.unsigned_abs();
    for (size, one, many) in [(604_800, "week", "weeks"), (86_400, "day", "days"), (3_600, "hour", "hours"), (60, "minute", "minutes")] {
        if secs >= size && secs.is_multiple_of(size) {
            return count(secs / size, one, many);
        }
    }
    count(secs, "second", "seconds")
}

/// The presets with `current` selected. A current value that is no preset
/// joins the list in order of length, so saving the form keeps it.
fn duration_choices(presets: &[(&str, &str)], current: &str, prefix: &str) -> Vec<Choice> {
    let now = seconds(current);
    let rank = |s: Option<i64>| match s {
        Some(n) if n >= 0 => n,
        _ => i64::MAX,
    };
    let mut out: Vec<Choice> = presets
        .iter()
        .map(|(value, label)| Choice {
            value: (*value).into(),
            label: (*label).into(),
            selected: now.is_some() && seconds(value) == now,
        })
        .collect();
    if !out.iter().any(|c| c.selected) {
        let label = match now {
            Some(n) => format!("{prefix}{}", duration_label(n)),
            None => current.to_string(),
        };
        let at = out.iter().filter(|c| rank(seconds(&c.value)) <= rank(now)).count();
        out.insert(at, Choice { value: current.into(), label, selected: true });
    }
    out
}

fn failure_choices(current: u32) -> Vec<Choice> {
    const PRESETS: [u32; 4] = [3, 5, 10, 20];
    let choice = |n: u32| Choice { value: n.to_string(), label: count(u64::from(n), "failure", "failures"), selected: n == current };
    let mut out: Vec<Choice> = PRESETS.iter().map(|&n| choice(n)).collect();
    if !PRESETS.contains(&current) {
        out.insert(PRESETS.iter().filter(|&&n| n < current).count(), choice(current));
    }
    out
}

/// "Not doubled", or doubling each repeat ban up to the longest ban.
fn repeat_choices(increment: bool, maxtime: &str) -> Vec<Choice> {
    const PRESETS: [(&str, &str); 4] =
        [("1d", "Doubling to 1 day"), ("1w", "Doubling to 1 week"), ("30d", "Doubling to 1 month"), ("365d", "Doubling to 1 year")];
    let mut out = vec![Choice { value: "off".into(), label: "Not doubled".into(), selected: !increment }];
    if increment {
        out.extend(duration_choices(&PRESETS, maxtime, "Doubling to "));
    } else {
        out.extend(PRESETS.iter().map(|(value, label)| Choice { value: (*value).into(), label: (*label).into(), selected: false }));
    }
    out
}

/// The ISO code of an address's country, or empty when unknown; a failed
/// lookup is reported.
fn country_of(geo: &app::CountryData, address: &str) -> String {
    let Some(db) = &geo.db else { return String::new() };
    let ip: std::net::IpAddr = match address.parse() {
        Ok(ip) => ip,
        Err(e) => {
            eprintln!("countries: {address}: {e}");
            return String::new();
        }
    };
    match db.lookup(ip) {
        Ok(Some(code)) => code,
        Ok(None) => String::new(),
        Err(e) => {
            eprintln!("countries: {e:#}");
            String::new()
        }
    }
}

/// A country's English name, or its code when the database does not know it.
fn country_name(geo: &app::CountryData, code: &str) -> String {
    match geo.names.iter().find(|(c, _)| c == code) {
        Some((_, name)) => name.clone(),
        None => code.to_string(),
    }
}

/// Who the countries shown come from, to credit: dbip or maxmind; empty
/// with no database.
fn geo_credit(geo: &app::CountryData) -> &'static str {
    match &geo.db {
        Some(db) if db.kind().contains("GeoLite") => "maxmind",
        Some(_) => "dbip",
        None => "",
    }
}

/// One banned address in the table of bans.
pub struct BanRow {
    pub address: String,
    /// ISO code, or empty when unknown.
    pub country: String,
    pub jail: String,
    /// "ssh", "web" or "other", which the door filter matches.
    pub door: &'static str,
    /// "auto", "repeat", "admin", or empty when fail2ban kept no record.
    pub kind: &'static str,
    pub count: u32,
    pub since: String,
    pub since_iso: String,
    pub since_sort: u64,
    pub left: String,
    pub ends_iso: String,
    pub left_sort: u64,
    pub forever: bool,
    /// The failed logins behind the ban, "None" for an admin's ban, or "Unknown".
    pub failures: String,
    pub failures_muted: bool,
    pub failures_sort: u32,
}

fn ban_row(jail: &str, b: BanView, now: u64) -> BanRow {
    let door = match jail {
        "sshd" => "ssh",
        "sftp-webui" => "web",
        _ => "other",
    };
    let kind = match (b.since, b.failures, b.count) {
        (None, _, _) => "",
        (_, Some(0), _) => "admin",
        (_, _, n) if n > 1 => "repeat",
        _ => "auto",
    };
    let (since, since_iso, since_sort) = match b.since {
        Some(t) => (ago(t), timefmt::iso(t), t),
        None => ("Unknown".into(), String::new(), 0),
    };
    let (left, ends_iso, left_sort) = match b.since {
        _ if b.length < 0 => ("Forever".to_string(), String::new(), u64::MAX),
        Some(t) => {
            let end = t.saturating_add(b.length.unsigned_abs());
            let rest = end.saturating_sub(now);
            (remaining(rest), timefmt::iso(end), rest)
        }
        None => ("Unknown".into(), String::new(), 0),
    };
    let (failures, failures_muted, failures_sort) = match b.failures {
        Some(0) => ("None".to_string(), true, 0),
        Some(n) => (n.to_string(), false, n),
        None => ("Unknown".to_string(), true, 0),
    };
    BanRow {
        address: b.address,
        country: String::new(),
        jail: jail.into(),
        door,
        kind,
        count: b.count,
        since,
        since_iso,
        since_sort,
        left,
        ends_iso,
        left_sort,
        forever: b.length < 0,
        failures,
        failures_muted,
        failures_sort,
    }
}

/// The rules fail2ban is using, in words, when another file in
/// /config/fail2ban sets ones that differ from the saved rules.
fn drift(b: &Bans) -> Option<String> {
    let (s, e) = (&b.saved, &b.effective);
    let same = s.maxretry == e.maxretry && seconds(&s.bantime) == seconds(&e.bantime) && seconds(&s.findtime) == seconds(&e.findtime);
    if !b.enabled || same {
        return None;
    }
    let words = |t: &str| match seconds(t) {
        Some(n) => duration_label(n).to_lowercase(),
        None => t.to_string(),
    };
    let ban = match seconds(&e.bantime) {
        Some(n) if n < 0 => "a ban that never ends".to_string(),
        _ => format!("a ban of {}", words(&e.bantime)),
    };
    Some(format!(
        "fail2ban counts {} within {}, then gives {ban}. Another file in /config/fail2ban sets these.",
        count(u64::from(e.maxretry), "failure", "failures"),
        words(&e.findtime)
    ))
}

#[derive(Template)]
#[template(path = "bans.html")]
struct BansPage {
    l: Layout,
    enabled: bool,
    rows: Vec<BanRow>,
    banned_ssh: usize,
    banned_web: usize,
    repeat_now: usize,
    failing_now: u64,
    failed_total: u64,
    bans_total: u64,
    records_error: Option<String>,
    drift: Option<String>,
    failures: Vec<Choice>,
    window: Vec<Choice>,
    length: Vec<Choice>,
    repeat: Vec<Choice>,
    maxtime: String,
    ignore: Vec<String>,
    /// History mode: every ban the permanent store keeps, a page at a time.
    show_history: bool,
    history: Vec<BanHistoryRow>,
    history_first: bool,
    older: Option<i64>,
    history_error: Option<String>,
    ranges: Vec<RangeChoice>,
    chart: Option<ChartCard>,
    names: Option<ChartCard>,
    chart_error: Option<String>,
    /// dbip or maxmind: whose data the countries come from, to credit.
    geo_credit: &'static str,
    countries: CountriesCard,
}

/// One ban from the permanent store, ended or not.
pub struct BanHistoryRow {
    pub address: String,
    pub country: String,
    pub door: &'static str,
    pub jail: String,
    pub since: String,
    pub since_iso: String,
    pub since_sort: u64,
    pub length: String,
    pub length_sort: i64,
    pub active: bool,
    pub failures: String,
    pub failures_muted: bool,
    pub kind: &'static str,
    pub count: i64,
    pub names: Vec<String>,
}

fn history_row(b: sftp_webui::proto::BanRecord, now: u64) -> BanHistoryRow {
    let door = match b.jail.as_str() {
        "sshd" => "ssh",
        "sftp-webui" => "web",
        _ => "other",
    };
    let kind = match (b.failures, b.count) {
        (Some(0), _) => "admin",
        (_, n) if n > 1 => "repeat",
        _ => "auto",
    };
    let (failures, failures_muted) = match b.failures {
        Some(0) => ("None".to_string(), true),
        Some(n) => (n.to_string(), false),
        None => ("Unknown".to_string(), true),
    };
    BanHistoryRow {
        door,
        kind,
        since: ago(b.time),
        since_iso: timefmt::iso(b.time),
        since_sort: b.time,
        length: duration_label(b.length),
        length_sort: if b.length < 0 { i64::MAX } else { b.length },
        active: b.length < 0 || b.time.saturating_add(b.length.unsigned_abs()) > now,
        failures,
        failures_muted,
        count: b.count,
        names: b.names,
        address: b.address,
        country: String::new(),
        jail: b.jail,
    }
}

#[derive(Deserialize)]
pub struct BansQuery {
    #[serde(default)]
    show: String,
    before: Option<i64>,
    #[serde(default)]
    range: String,
}

/// Bans per period over `length` seconds up to now, from the ban store.
async fn bans_chart(length: u64, size: u64) -> anyhow::Result<ChartCard> {
    let now = timefmt::now();
    let to = now - now % size + size;
    let from = to.saturating_sub(length.div_ceil(size) * size);
    let series = helper::data::<sftp_webui::proto::Series>(&Request::HistorySeries { from, to, size }).await?;
    let labels: Vec<String> = series.buckets.iter().map(|b| charts::ago_label(to.saturating_sub(b.start + size))).collect();
    let values: Vec<u64> = series.buckets.iter().map(|b| b.bans).collect();
    let rows = labels.iter().zip(&values).map(|(label, v)| (label.clone(), vec![*v])).collect();
    let lines = [charts::Series { name: "Bans", class: "c2", values }];
    Ok(ChartCard {
        title: "Bans",
        icon: "prohibit",
        wide: charts::lines("Bans", &labels, &lines, 600.0, "wide"),
        narrow: charts::lines("Bans", &labels, &lines, 320.0, "narrow"),
        keys: vec![("s2", "Bans")],
        first_column: "When",
        columns: vec!["Bans"],
        rows,
    })
}

/// The names tried in failed sign-ins since `since`: the nine most tried
/// as bars, the rest summed into one, and every name in the table.
async fn names_chart(since: u64) -> anyhow::Result<ChartCard> {
    const SHOWN: usize = 9;
    let names = helper::data::<Vec<sftp_webui::proto::NameCount>>(&Request::NamesTried { since }).await?;
    let rows = names
        .iter()
        .map(|n| (if n.known { format!("{}, an account here", n.name) } else { n.name.clone() }, vec![n.count]))
        .collect();
    let mut items: Vec<charts::Bar> = names
        .iter()
        .take(SHOWN)
        .map(|n| charts::Bar { label: n.name.clone(), value: n.count, class: if n.known { "c1" } else { "c0" } })
        .collect();
    let others = names.len().saturating_sub(SHOWN);
    if others > 0 {
        let rest = names.iter().skip(SHOWN).map(|n| n.count).sum();
        items.push(charts::Bar { label: count(others as u64, "other name", "other names"), value: rest, class: "c0" });
    }
    let (wide, narrow) = if items.is_empty() {
        let none = r#"<p class="muted">No failed sign-ins in this period.</p>"#.to_string();
        (none.clone(), none)
    } else {
        (
            charts::bars("Names tried", &items, "failed sign-ins", 600.0, "wide"),
            charts::bars("Names tried", &items, "failed sign-ins", 320.0, "narrow"),
        )
    };
    Ok(ChartCard {
        title: "Names tried",
        icon: "user",
        wide,
        narrow,
        keys: vec![("", "An account here"), ("s0", "No such account")],
        first_column: "Name",
        columns: vec!["Failed sign-ins"],
        rows,
    })
}

const WINDOW_PRESETS: [(&str, &str); 5] =
    [("5m", "5 minutes"), ("10m", "10 minutes"), ("30m", "30 minutes"), ("1h", "1 hour"), ("1d", "1 day")];
const LENGTH_PRESETS: [(&str, &str); 5] = [("10m", "10 minutes"), ("1h", "1 hour"), ("1d", "1 day"), ("1w", "1 week"), ("-1", "Forever")];

pub async fn bans_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Query(q): Query<BansQuery>) -> Response {
    let b = match helper::data::<Bans>(&Request::Bans).await {
        Ok(b) => b,
        Err(e) => return error_page(&app, &ctx, "bans", &format!("{e:#}")),
    };
    let drift = drift(&b);
    let now = timefmt::now();
    let geo = app.countries();
    let show_history = q.show == "history";
    let (history, older, history_error) = if show_history {
        match helper::data::<sftp_webui::proto::BanPage>(&Request::BanHistory { before: q.before }).await {
            Ok(page) => {
                let rows = page
                    .bans
                    .into_iter()
                    .map(|r| {
                        let mut row = history_row(r, now);
                        row.country = country_of(&geo, &row.address);
                        row
                    })
                    .collect();
                (rows, page.older, None)
            }
            Err(e) => (Vec::new(), None, Some(format!("{e:#}"))),
        }
    } else {
        (Vec::new(), None, None)
    };
    let (ranges, length, size) = range_choices(&q.range);
    let (chart, chart_error) = match bans_chart(length, size).await {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let (names, names_error) = match names_chart(now.saturating_sub(length)).await {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };
    let chart_error = match (chart_error, names_error) {
        (Some(a), Some(b)) => Some(format!("{a}; {b}")),
        (Some(a), None) | (None, Some(a)) => Some(a),
        (None, None) => None,
    };
    let logins = helper::data::<Vec<sftp_webui::proto::CountryCount>>(&Request::LoginsByCountry {
        since: now.saturating_sub(length),
    })
    .await;
    let range = ranges.iter().find(|r| r.on).map_or(RANGES[0].1, |r| r.label);
    let countries = countries_card(&geo, b.countries, logins, range);
    let mut rows = Vec::new();
    let (mut failing_now, mut failed_total, mut bans_total) = (0, 0, 0);
    for jail in b.jails {
        failing_now += jail.failed;
        failed_total += jail.total_failed;
        bans_total += jail.total_banned;
        rows.extend(jail.banned.into_iter().map(|ban| {
            let mut row = ban_row(&jail.name, ban, now);
            row.country = country_of(&geo, &row.address);
            row
        }));
    }
    rows.sort_by_key(|r| std::cmp::Reverse(r.since_sort));
    let page = BansPage {
        l: layout(&app, Some(&ctx), "Bans", "bans"),
        enabled: b.enabled,
        banned_ssh: rows.iter().filter(|r| r.door == "ssh").count(),
        banned_web: rows.iter().filter(|r| r.door == "web").count(),
        repeat_now: rows.iter().filter(|r| r.kind == "repeat").count(),
        rows,
        failing_now,
        failed_total,
        bans_total,
        records_error: b.records_error,
        drift,
        failures: failure_choices(b.saved.maxretry),
        window: duration_choices(&WINDOW_PRESETS, &b.saved.findtime, ""),
        length: duration_choices(&LENGTH_PRESETS, &b.saved.bantime, ""),
        repeat: repeat_choices(b.saved.increment, &b.saved.maxtime),
        maxtime: b.saved.maxtime,
        ignore: b.saved.ignoreip,
        show_history,
        history,
        history_first: q.before.is_none(),
        older,
        history_error,
        ranges,
        chart,
        names,
        chart_error,
        geo_credit: geo_credit(&geo),
        countries,
    };
    app::render(StatusCode::OK, &page)
}

/// A country as a chip or an Add choice.
pub struct CountryChoice {
    pub code: String,
    /// Its English name from the country database, or the code.
    pub name: String,
}

/// A country the server's own failed logins suggest blocking.
pub struct Suggestion {
    pub country: CountryChoice,
    /// Its share of the failed logins in the range, in percent.
    pub share: u64,
}

/// The Countries card on the Bans page.
pub struct CountriesCard {
    /// off, block or allow.
    pub rule: String,
    pub rule_locked: bool,
    pub list_locked: bool,
    pub listed: Vec<CountryChoice>,
    /// The countries not listed, by name, for Add.
    pub others: Vec<CountryChoice>,
    /// The state pill's look, words and tooltip.
    pub pill: (&'static str, String, String),
    /// Why the rules are not enforced, when they are not.
    pub problem: Option<String>,
    /// Never-ban entries the rules cannot exempt, each with the reason.
    pub skipped: Vec<String>,
    pub suggestion: Option<Suggestion>,
    pub chart: Option<ChartCard>,
    pub chart_error: Option<String>,
    /// The chart's range in words, such as "7 days".
    pub range: &'static str,
    /// True when no country database could be read.
    pub no_database: bool,
}

/// The codes of a country list, in capitals, each once.
fn country_codes(text: &str) -> Vec<String> {
    let mut codes: Vec<String> = Vec::new();
    for word in text.split(|c: char| c == ',' || c.is_whitespace()).filter(|w| !w.is_empty()) {
        let code = word.to_ascii_uppercase();
        if !codes.contains(&code) {
            codes.push(code);
        }
    }
    codes
}

/// Failed logins by country: the nine most failed as bars, listed ones in
/// the series color and the rest summed into one; every country in the
/// table, with its successful logins.
fn countries_chart(geo: &app::CountryData, logins: &[sftp_webui::proto::CountryCount], listed: &[String]) -> ChartCard {
    const SHOWN: usize = 9;
    let label = |c: &sftp_webui::proto::CountryCount| match &c.code {
        Some(code) => country_name(geo, code),
        None => "No country".to_string(),
    };
    let is_listed = |c: &sftp_webui::proto::CountryCount| c.code.as_ref().is_some_and(|code| listed.contains(code));
    let failing: Vec<&sftp_webui::proto::CountryCount> = logins.iter().filter(|c| c.failed > 0).collect();
    let mut items: Vec<charts::Bar> = failing
        .iter()
        .take(SHOWN)
        .map(|c| charts::Bar { label: label(c), value: c.failed, class: if is_listed(c) { "c1" } else { "c0" } })
        .collect();
    if failing.len() > SHOWN {
        let rest = failing[SHOWN..].iter().map(|c| c.failed).sum();
        let others = (failing.len() - SHOWN) as u64;
        items.push(charts::Bar { label: count(others, "other country", "other countries"), value: rest, class: "c0" });
    }
    let rows = logins
        .iter()
        .map(|c| (if is_listed(c) { format!("{}, listed", label(c)) } else { label(c) }, vec![c.failed, c.ok]))
        .collect();
    let (wide, narrow) = if items.is_empty() {
        let none = r#"<p class="muted">No failed logins in this period.</p>"#.to_string();
        (none.clone(), none)
    } else {
        (
            charts::bars("Failed logins by country", &items, "failed logins", 600.0, "wide"),
            charts::bars("Failed logins by country", &items, "failed logins", 320.0, "narrow"),
        )
    };
    ChartCard {
        title: "Failed logins by country",
        icon: "globe-hemisphere-west",
        wide,
        narrow,
        keys: vec![("", "Listed"), ("s0", "Not listed")],
        first_column: "Country",
        columns: vec!["Failed logins", "Logins"],
        rows,
    }
}

/// The country to suggest blocking: the most failed one not listed, from
/// which no account logged in, with at least ten failed logins and a tenth
/// of them all. `logins` is most failed first.
fn suggestion(geo: &app::CountryData, logins: &[sftp_webui::proto::CountryCount], listed: &[String]) -> Option<Suggestion> {
    let total: u64 = logins.iter().map(|c| c.failed).sum();
    let top = logins
        .iter()
        .find(|c| c.ok == 0 && c.failed >= 10 && c.code.as_ref().is_some_and(|code| !listed.contains(code)))?;
    let code = top.code.clone()?;
    let share = top.failed * 100 / total;
    (share >= 10).then(|| Suggestion { country: CountryChoice { name: country_name(geo, &code), code }, share })
}

fn countries_card(
    geo: &app::CountryData,
    rules: sftp_webui::proto::CountryRules,
    logins: anyhow::Result<Vec<sftp_webui::proto::CountryCount>>,
    range: &'static str,
) -> CountriesCard {
    let listed_codes = country_codes(&rules.countries.value);
    let listed = listed_codes.iter().map(|code| CountryChoice { code: code.clone(), name: country_name(geo, code) }).collect();
    let mut others: Vec<CountryChoice> = geo
        .names
        .iter()
        .filter(|(code, _)| !listed_codes.contains(code))
        .map(|(code, name)| CountryChoice { code: code.clone(), name: name.clone() })
        .collect();
    others.sort_by(|a, b| a.name.cmp(&b.name));
    let ports = rules.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(", ");
    let port_words = if rules.ports.len() == 1 { format!("port {ports}") } else { format!("ports {ports}") };
    let applied = count(rules.applied.len() as u64, "country", "countries");
    let pill = match rules.state.as_str() {
        "blocking" => ("ok", format!("Blocking {applied}"), format!("New connections from the listed countries to {port_words} are dropped")),
        "allowing" => ("ok", format!("Allowing {applied}"), format!("Only the listed countries can connect to {port_words}")),
        "refused" => ("warn", "Not enforced".to_string(), "The firewall refused the rules".to_string()),
        "unknown" => ("warn", "Unknown".to_string(), "Whether the rules are enforced cannot be read".to_string()),
        _ => ("", "Off".to_string(), "Country rules are off; choose a rule to turn them on".to_string()),
    };
    let problem = match rules.state.as_str() {
        "refused" => Some(format!("The firewall refused them ({}). Start the container with --cap-add=NET_ADMIN.", rules.refused)),
        "unknown" => Some(rules.refused.clone()),
        _ => None,
    };
    let (suggestion, chart, chart_error) = match logins {
        Ok(rows) => {
            let suggested = if rules.rule.value == "allow" { None } else { suggestion(geo, &rows, &listed_codes) };
            (suggested, Some(countries_chart(geo, &rows, &listed_codes)), None)
        }
        Err(e) => (None, None, Some(format!("{e:#}"))),
    };
    CountriesCard {
        rule: rules.rule.value,
        rule_locked: rules.rule.locked,
        list_locked: rules.countries.locked,
        listed,
        others,
        pill,
        problem,
        skipped: rules.skipped,
        suggestion,
        chart,
        chart_error,
        range,
        no_database: geo.db.is_none(),
    }
}

#[derive(Deserialize)]
pub struct AddressForm {
    address: String,
    #[serde(default)]
    jail: String,
}

pub async fn ban(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<AddressForm>,
) -> Response {
    let request = Request::Ban { actor: app::actor(&ctx, client), address: form.address };
    change(&app, &ctx, request, "Address banned.", "/bans").await
}

pub async fn unban(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<AddressForm>,
) -> Response {
    let request = Request::Unban { actor: app::actor(&ctx, client), jail: form.jail, address: form.address };
    change(&app, &ctx, request, "Address unbanned.", "/bans").await
}

/// Lifts every ban picked in the table; each value is "<jail> <address>".
pub async fn lift(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let picked: Vec<(String, String)> = form
        .into_iter()
        .filter(|(key, _)| key == "ban")
        .filter_map(|(_, value)| value.split_once(' ').map(|(jail, address)| (jail.to_string(), address.to_string())))
        .collect();
    if picked.is_empty() {
        app.flash(&ctx, Flash::error("Choose the bans to lift.", Vec::new()));
        return app::redirect("/bans");
    }
    let mut lifted = 0;
    let mut refused = Vec::new();
    for (jail, address) in picked {
        let request = Request::Unban { actor: app::actor(&ctx, client), jail, address: address.clone() };
        match helper::call(&request).await {
            Ok(reply) if reply.ok => lifted += 1,
            Ok(reply) => refused.push(format!("{address}: {}", reply.error)),
            Err(e) => refused.push(format!("{address}: {e:#}")),
        }
    }
    let done = count(lifted, "ban lifted", "bans lifted");
    if refused.is_empty() {
        app.flash(&ctx, Flash::ok(format!("{done}."), Vec::new()));
    } else {
        app.flash(&ctx, Flash::error(format!("{done}; {} could not be lifted.", refused.len()), refused));
    }
    app::redirect("/bans")
}

/// The rules form: one dropdown per rule, `repeat` as "off" or the longest
/// ban, `maxtime` carrying the saved longest ban, and one `ignoreip` field
/// per network kept or added.
pub async fn ban_rules(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let field = |key: &str| form.iter().find(|(k, _)| k == key).map(|(_, v)| v.trim().to_string());
    let (Some(maxretry), Some(findtime), Some(bantime), Some(repeat), Some(maxtime)) =
        (field("maxretry"), field("findtime"), field("bantime"), field("repeat"), field("maxtime"))
    else {
        app.flash(&ctx, Flash::error("The rules form is missing a rule; reload the page and try again.", Vec::new()));
        return app::redirect("/bans");
    };
    let maxretry: u32 = match maxretry.parse() {
        Ok(n) => n,
        Err(e) => {
            app.flash(&ctx, Flash::error(format!("Failed logins before a ban: {e}"), Vec::new()));
            return app::redirect("/bans");
        }
    };
    let (increment, maxtime) = if repeat == "off" { (false, maxtime) } else { (true, repeat) };
    let ignoreip = form
        .iter()
        .filter(|(k, v)| k == "ignoreip" && !v.trim().is_empty())
        .map(|(_, v)| v.trim().to_string())
        .collect();
    let rules = BanRules { bantime, findtime, maxretry, increment, maxtime, ignoreip };
    let request = Request::Fail2banPut { actor: app::actor(&ctx, client), rules };
    change(&app, &ctx, request, "Ban rules saved and applied.", "/bans").await
}

/// The Countries form: `rule`, one `country` per country kept or added, and
/// `list` when the list may be changed, so that an emptied list is saved
/// empty. A setting the environment locks is not in the form.
pub async fn country_rules(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let mut values = Vec::new();
    if let Some((_, rule)) = form.iter().find(|(k, _)| k == "rule") {
        values.push(SettingValue { key: "SFTP_COUNTRY_RULE".into(), value: rule.trim().to_string() });
    }
    if form.iter().any(|(k, _)| k == "list") {
        let picked: Vec<&str> = form.iter().filter(|(k, _)| k == "country").map(|(_, v)| v.as_str()).collect();
        values.push(SettingValue { key: "SFTP_COUNTRIES".into(), value: country_codes(&picked.join(" ")).join(" ") });
    }
    if values.is_empty() {
        app.flash(&ctx, Flash::error("Both country settings are set in the container's environment.", Vec::new()));
        return app::redirect("/bans");
    }
    let request = Request::SettingsPut { actor: app::actor(&ctx, client), values };
    change(&app, &ctx, request, "Country rules saved and applied.", "/bans").await
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "settings.html")]
struct SettingsPage {
    l: Layout,
    s: Settings,
    /// When the country database in use was built, in words.
    built: String,
}

pub async fn settings_page(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    match helper::data::<Settings>(&Request::SettingsGet).await {
        Ok(s) => {
            let built = if s.locations.built == 0 { "Unknown".to_string() } else { ago(s.locations.built) };
            app::render(StatusCode::OK, &SettingsPage { l: layout(&app, Some(&ctx), "Settings", "settings"), s, built })
        }
        Err(e) => error_page(&app, &ctx, "settings", &format!("{e:#}")),
    }
}

#[derive(Deserialize)]
pub struct MaxmindForm {
    account_id: String,
    license_key: String,
}

/// Saves a MaxMind key; the helper keeps it only once a GeoLite2 download
/// with it works.
pub async fn maxmind_save(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<MaxmindForm>,
) -> Response {
    let request = Request::MaxmindPut {
        actor: app::actor(&ctx, client),
        account_id: form.account_id,
        license_key: sftp_webui::proto::Secret(form.license_key),
    };
    change(&app, &ctx, request, "MaxMind key saved; the country rules now read GeoLite2.", "/settings").await
}

pub async fn maxmind_delete(State(app): AppState, Extension(ctx): Extension<Ctx>, Extension(client): Extension<Client>) -> Response {
    let request = Request::MaxmindDelete { actor: app::actor(&ctx, client) };
    change(&app, &ctx, request, "MaxMind key removed; the country rules read DB-IP Lite again.", "/settings").await
}

pub async fn settings_save(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<Vec<(String, String)>>,
) -> Response {
    let values: Vec<SettingValue> = form
        .into_iter()
        .filter(|(k, _)| k.starts_with("SFTP_"))
        .map(|(key, value)| SettingValue { key, value })
        .collect();
    let request = Request::SettingsPut { actor: app::actor(&ctx, client), values };
    change(&app, &ctx, request, "Settings saved and applied.", "/settings").await
}

// ---------------------------------------------------------------------------
// Activity
// ---------------------------------------------------------------------------

/// A size in bytes for people: "845 KB", "2.4 MB", in steps of 1000.
pub(crate) fn size_label(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return count(bytes, "byte", "bytes");
    }
    let mut value = bytes as f64 / 1000.0;
    let mut unit = 0;
    while value >= 1000.0 && unit + 1 < UNITS.len() {
        value /= 1000.0;
        unit += 1;
    }
    if value < 10.0 { format!("{value:.1} {}", UNITS[unit]) } else { format!("{value:.0} {}", UNITS[unit]) }
}

/// What an event kind is called on the page, and its icon.
fn kind_label(kind: &str) -> (&'static str, &'static str) {
    match kind {
        "login_ok" => ("Signed in", "sign-in"),
        "login_failed" => ("Failed sign-in", "x-circle"),
        "session_opened" => ("Session started", "plugs-connected"),
        "session_closed" => ("Session ended", "sign-out"),
        "browse" => ("Browsed", "folder-open"),
        "download" => ("Downloaded", "download-simple"),
        "upload" => ("Uploaded", "upload-simple"),
        "delete" => ("Deleted", "trash"),
        "rename" => ("Renamed", "pencil-simple"),
        "mkdir" => ("Made a folder", "folder-simple-plus"),
        "rmdir" => ("Removed a folder", "trash"),
        "attributes" => ("Changed attributes", "sliders-horizontal"),
        "link" => ("Made a link", "link-simple"),
        "copy" => ("Copied", "copy-simple"),
        _ => ("Other", "question"),
    }
}

/// One event in the Activity log.
pub struct EventRow {
    pub id: i64,
    pub when: String,
    pub when_iso: String,
    pub time: u64,
    pub account: String,
    pub door: String,
    pub kind: String,
    pub label: &'static str,
    pub icon: &'static str,
    pub failed: bool,
    pub path: String,
    pub other: String,
    pub size: String,
    pub bytes: u64,
    pub address: String,
    /// Who acted in the file browser; empty over SSH.
    pub actor: String,
}

pub(crate) fn event_row(e: sftp_webui::proto::EventView) -> EventRow {
    let (label, icon) = kind_label(&e.kind);
    let shows_size = e.kind == "upload" || e.kind == "download";
    EventRow {
        id: e.id,
        when: ago(e.time),
        when_iso: timefmt::iso(e.time),
        time: e.time,
        failed: e.kind == "login_failed",
        size: if shows_size { size_label(e.bytes) } else { String::new() },
        label,
        icon,
        bytes: e.bytes,
        account: e.account,
        door: e.door,
        kind: e.kind,
        path: e.path,
        other: e.other,
        address: e.address,
        actor: e.actor,
    }
}

#[derive(Deserialize)]
pub struct ActivityQuery {
    #[serde(default)]
    account: String,
    /// people (the default without an account) or log.
    #[serde(default)]
    view: String,
    before: Option<i64>,
    after: Option<i64>,
}

/// An account connected now or active in the last 24 hours.
pub struct PersonCard {
    pub account: String,
    pub connected: bool,
    pub last: String,
    pub last_iso: String,
    pub recent: Vec<EventRow>,
    pub logins: u64,
    pub failed: u64,
    pub uploads: u64,
    pub downloads: u64,
    pub data: String,
}

/// Accounts connected now or active in the last 24 hours, most recent first.
async fn people_cards() -> anyhow::Result<Vec<PersonCard>> {
    let now = timefmt::now();
    let people = helper::data::<Vec<sftp_webui::proto::Person>>(&Request::People { since: now.saturating_sub(86_400) }).await?;
    let status = helper::data::<Status>(&Request::Status).await?;
    let connected: Vec<&str> = status.sessions.iter().map(|s| s.account.as_str()).collect();
    let mut cards: Vec<PersonCard> = people
        .into_iter()
        .map(|p| PersonCard {
            connected: connected.contains(&p.account.as_str()),
            last: ago(p.last),
            last_iso: timefmt::iso(p.last),
            recent: p.recent.into_iter().map(event_row).collect(),
            logins: p.logins,
            failed: p.failed,
            uploads: p.uploads,
            downloads: p.downloads,
            data: size_label(p.bytes_in + p.bytes_out),
            account: p.account,
        })
        .collect();
    for s in &status.sessions {
        if !cards.iter().any(|c| c.account == s.account) {
            cards.push(PersonCard {
                account: s.account.clone(),
                connected: true,
                last: ago(s.since),
                last_iso: timefmt::iso(s.since),
                recent: Vec::new(),
                logins: 0,
                failed: 0,
                uploads: 0,
                downloads: 0,
                data: size_label(0),
            });
        }
    }
    Ok(cards)
}

#[derive(Template)]
#[template(path = "activity.html")]
struct ActivityPage {
    l: Layout,
    rows: Vec<EventRow>,
    account: String,
    first: bool,
    older: Option<i64>,
    view_people: bool,
    people: Vec<PersonCard>,
    people_error: Option<String>,
}

#[derive(Template)]
#[template(path = "activity_people.html")]
struct PeopleFragment {
    people: Vec<PersonCard>,
}

/// The people cards, for the live People view to refresh.
pub async fn activity_people() -> Response {
    match people_cards().await {
        Ok(people) => app::render(StatusCode::OK, &PeopleFragment { people }),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

#[derive(Template)]
#[template(path = "activity_rows.html")]
struct ActivityRows {
    rows: Vec<EventRow>,
}

pub async fn activity_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Query(q): Query<ActivityQuery>) -> Response {
    let mut l = layout(&app, Some(&ctx), "Activity", "activity");
    if q.account.is_empty() && q.view != "log" {
        let (people, people_error) = match people_cards().await {
            Ok(p) => (p, None),
            Err(e) => (Vec::new(), Some(format!("{e:#}"))),
        };
        let page = ActivityPage {
            l,
            rows: Vec::new(),
            account: String::new(),
            first: true,
            older: None,
            view_people: true,
            people,
            people_error,
        };
        return app::render(StatusCode::OK, &page);
    }
    let request = Request::Events { account: q.account.clone(), after: None, before: q.before };
    match helper::data::<sftp_webui::proto::EventPage>(&request).await {
        Ok(page) => {
            if !q.account.is_empty() {
                l.heading = q.account.clone();
            }
            let rows = page.events.into_iter().map(event_row).collect();
            let page = ActivityPage {
                l,
                rows,
                account: q.account,
                first: q.before.is_none(),
                older: page.older,
                view_people: false,
                people: Vec::new(),
                people_error: None,
            };
            app::render(StatusCode::OK, &page)
        }
        Err(e) => error_page(&app, &ctx, "activity", &format!("{e:#}")),
    }
}

/// The events newer than `after`, for the live log to put on top.
pub async fn activity_rows(Query(q): Query<ActivityQuery>) -> Response {
    let Some(after) = q.after else {
        return (StatusCode::BAD_REQUEST, "after is required").into_response();
    };
    let request = Request::Events { account: q.account, after: Some(after), before: None };
    match helper::data::<sftp_webui::proto::EventPage>(&request).await {
        Ok(page) => app::render(StatusCode::OK, &ActivityRows { rows: page.events.into_iter().map(event_row).collect() }),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

// ---------------------------------------------------------------------------
// Logs and audit
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    q: String,
    before: Option<u64>,
}

#[derive(Template)]
#[template(path = "logs.html")]
struct LogsPage {
    l: Layout,
    q: String,
    page: LogPage,
    first: bool,
}

#[derive(Template)]
#[template(path = "logs_rows.html")]
struct LogsRows {
    page: LogPage,
}

pub async fn logs_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Query(q): Query<PageQuery>) -> Response {
    let first = q.before.is_none();
    match helper::data::<LogPage>(&Request::Log { query: q.q.clone(), before: q.before }).await {
        Ok(page) => app::render(StatusCode::OK, &LogsPage { l: layout(&app, Some(&ctx), "Logs", "logs"), q: q.q, page, first }),
        Err(e) => error_page(&app, &ctx, "logs", &format!("{e:#}")),
    }
}

pub async fn logs_rows(Query(q): Query<PageQuery>) -> Response {
    match helper::data::<LogPage>(&Request::Log { query: q.q, before: None }).await {
        Ok(page) => app::render(StatusCode::OK, &LogsRows { page }),
        Err(e) => (StatusCode::BAD_GATEWAY, format!("{e:#}")).into_response(),
    }
}

pub struct AuditRow {
    pub time: String,
    pub time_iso: String,
    pub admin: String,
    pub address: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub ok: bool,
}

#[derive(Template)]
#[template(path = "audit.html")]
struct AuditView {
    l: Layout,
    q: String,
    rows: Vec<AuditRow>,
    older: Option<u64>,
    first: bool,
}

pub async fn audit_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Query(q): Query<PageQuery>) -> Response {
    let first = q.before.is_none();
    match helper::data::<AuditPage>(&Request::AuditLog { query: q.q.clone(), before: q.before }).await {
        Ok(page) => {
            let rows = page
                .entries
                .into_iter()
                .map(|e| AuditRow {
                    time: if e.time > 0 { timefmt::display(e.time) } else { String::new() },
                    time_iso: timefmt::iso(e.time),
                    ok: e.outcome == "ok",
                    admin: e.admin,
                    address: e.address,
                    action: e.action,
                    target: e.target,
                    outcome: e.outcome,
                })
                .collect();
            let view = AuditView { l: layout(&app, Some(&ctx), "Audit log", "audit"), q: q.q, rows, older: page.older, first };
            app::render(StatusCode::OK, &view)
        }
        Err(e) => error_page(&app, &ctx, "audit", &format!("{e:#}")),
    }
}

// ---------------------------------------------------------------------------
// Admins
// ---------------------------------------------------------------------------

pub struct AdminRow {
    pub name: String,
    pub role: &'static str,
    pub role_label: &'static str,
    pub totp: bool,
    pub from_file: bool,
    pub last_login: String,
    pub last_iso: String,
    /// Seconds since 1970 of the last sign-in; 0 for never.
    pub last_sort: u64,
    pub me: bool,
}

pub struct InviteRow {
    pub name: String,
    pub role_label: &'static str,
    /// Time left on the link, in words.
    pub expires: String,
    pub expires_iso: String,
    pub created_by: String,
}

#[derive(Template)]
#[template(path = "admins.html")]
struct AdminsPage {
    l: Layout,
    admins: Vec<AdminRow>,
    invites: Vec<InviteRow>,
}

pub async fn admins_page(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    let (admins, invites) = {
        let store = lock(&app.store);
        let admins = store
            .list()
            .into_iter()
            .map(|a| {
                let (last_login, last_iso, last_sort) = match a.last_login {
                    Some(t) => (ago(t), timefmt::iso(t), t),
                    None => ("Never".into(), String::new(), 0),
                };
                AdminRow {
                    me: a.name == ctx.admin,
                    role: a.role.name(),
                    role_label: a.role.label(),
                    totp: a.totp.is_some(),
                    from_file: a.from_file,
                    last_login,
                    last_iso,
                    last_sort,
                    name: a.name,
                }
            })
            .collect();
        let now = timefmt::now();
        let invites = store
            .invites(now)
            .into_iter()
            .map(|i| InviteRow {
                name: i.name,
                role_label: i.role.label(),
                expires: remaining(i.expires.saturating_sub(now)),
                expires_iso: timefmt::iso(i.expires),
                created_by: i.created_by,
            })
            .collect();
        (admins, invites)
    };
    let page = AdminsPage { l: layout(&app, Some(&ctx), "Admins", "admins"), admins, invites };
    app::render(StatusCode::OK, &page)
}

#[derive(Deserialize)]
pub struct InviteForm {
    name: String,
    role: String,
}

pub async fn admin_invite(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    headers: HeaderMap,
    Form(form): Form<InviteForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let Some(role) = Role::parse(&form.role) else {
        app.flash(&ctx, Flash::error("Choose a role.", Vec::new()));
        return app::redirect("/admins");
    };
    if let Err(e) = spec::validate_name(&name) {
        app.flash(&ctx, Flash::error(e, Vec::new()));
        return app::redirect("/admins");
    }
    let token = match auth::token() {
        Ok(t) => t,
        Err(e) => return error_page(&app, &ctx, "admins", &format!("{e:#}")),
    };
    let invite = Invite {
        name: name.clone(),
        role,
        token_sha256: auth::sha256_hex(token.as_bytes()),
        expires: timefmt::now() + INVITE_LIFETIME,
        created_by: ctx.admin.clone(),
    };
    let added = lock(&app.store).add_invite(invite);
    if let Err(e) = added {
        app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new()));
        return app::redirect("/admins");
    }
    let host = match headers.get(header::HOST) {
        Some(h) => app::header_text(h),
        None => format!("<this server>:{}", app.config.port),
    };
    let link = format!("https://{host}/invite?token={token}");
    audit(app::actor(&ctx, client), "admin invited", &format!("{name} ({})", role.name()), "ok").await;
    app.flash(
        &ctx,
        Flash {
            kind: "invite",
            text: format!("Invite for {name} created. Send this link over a safe channel; it works once, for 24 hours:"),
            detail: vec![link],
        },
    );
    app::redirect("/admins")
}

#[derive(Deserialize)]
pub struct NameForm {
    name: String,
}

pub async fn invite_revoke(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<NameForm>,
) -> Response {
    let removed = lock(&app.store).remove_invite(&form.name);
    match removed {
        Ok(()) => {
            audit(app::actor(&ctx, client), "invite revoked", &form.name, "ok").await;
            app.flash(&ctx, Flash::ok(format!("Invite for {} revoked.", form.name), Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/admins")
}

#[derive(Deserialize)]
pub struct RoleForm {
    role: String,
}

pub async fn admin_role(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
    Form(form): Form<RoleForm>,
) -> Response {
    let Some(role) = Role::parse(&form.role) else {
        app.flash(&ctx, Flash::error("Choose a role.", Vec::new()));
        return app::redirect("/admins");
    };
    let set = lock(&app.store).set_role(&name, role);
    match set {
        Ok(()) => {
            lock(&app.sessions).remove_admin(&name, None);
            audit(app::actor(&ctx, client), "admin role changed", &format!("{name} ({})", role.name()), "ok").await;
            app.flash(&ctx, Flash::ok(format!("{name} is now a {} admin and must sign in again.", role.name()), Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    if name == ctx.admin { app::redirect("/login") } else { app::redirect("/admins") }
}

pub async fn admin_totp_reset(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
) -> Response {
    let reset = lock(&app.store).set_totp(&name, None);
    match reset {
        Ok(()) => {
            audit(app::actor(&ctx, client), "admin TOTP reset", &name, "ok").await;
            app.flash(&ctx, Flash::ok(format!("{name} no longer needs a code to sign in."), Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/admins")
}

pub async fn admin_delete(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Path(name): Path<String>,
) -> Response {
    let removed = lock(&app.store).remove(&name);
    match removed {
        Ok(()) => {
            lock(&app.sessions).remove_admin(&name, None);
            audit(app::actor(&ctx, client), "admin removed", &name, "ok").await;
            if name == ctx.admin {
                return app::redirect("/login");
            }
            app.flash(&ctx, Flash::ok(format!("Admin {name} removed."), Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/admins")
}

// ---------------------------------------------------------------------------
// The signed-in admin's own credentials
// ---------------------------------------------------------------------------

#[derive(Template)]
#[template(path = "me.html")]
struct MePage {
    l: Layout,
    role: &'static str,
    from_file: bool,
    has_totp: bool,
    trusted: bool,
    setup_qr: String,
    setup_secret: String,
    min_password: usize,
}

fn me_view(app: &App, ctx: &Ctx, client: Client) -> Response {
    let Some(admin) = lock(&app.store).get(&ctx.admin) else {
        return app::redirect("/login");
    };
    let setup = match lock(&app.sessions).get(&ctx.cookie, false) {
        Some(s) => s.totp_setup.clone(),
        None => None,
    };
    let (setup_qr, setup_secret) = match setup {
        Some(secret) => match enrollment(&secret, &ctx.admin) {
            Ok(pair) => pair,
            Err(e) => return error_page(app, ctx, "me", &format!("{e:#}")),
        },
        None => (String::new(), String::new()),
    };
    let page = MePage {
        l: layout(app, Some(ctx), "Your sign-in", "me"),
        role: admin.role.name(),
        from_file: admin.from_file,
        has_totp: admin.totp.is_some(),
        trusted: net::any_contains(&app.config.trusted_networks, client.0),
        setup_qr,
        setup_secret,
        min_password: auth::MIN_PASSWORD,
    };
    app::render(StatusCode::OK, &page)
}

/// The QR code (inline SVG) and base32 secret an authenticator app takes.
pub(crate) fn enrollment(secret: &[u8], name: &str) -> anyhow::Result<(String, String)> {
    let totp = auth::totp(secret, name)?;
    let url = totp.to_url().map_err(|e| anyhow::anyhow!("cannot build the TOTP link: {e}"))?;
    let code = qrcode::QrCode::new(url.as_bytes()).map_err(|e| anyhow::anyhow!("cannot draw the QR code: {e}"))?;
    let svg = code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .dark_color(qrcode::render::svg::Color("#000000"))
        .light_color(qrcode::render::svg::Color("#ffffff"))
        .build();
    let svg = match svg.find("<svg") {
        Some(i) => svg[i..].to_string(),
        None => svg,
    };
    let base32 = totp_rs::Secret::from(secret.to_vec()).to_base32();
    Ok((svg, base32))
}

pub async fn me_page(State(app): AppState, Extension(ctx): Extension<Ctx>, Extension(client): Extension<Client>) -> Response {
    me_view(&app, &ctx, client)
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    confirm: String,
}

async fn current_password_ok(app: &App, ctx: &Ctx, password: String) -> bool {
    let hash = lock(&app.store).get(&ctx.admin).map(|a| a.hash);
    match app.hasher.verify(hash, password).await {
        Ok(v) => v,
        Err(e) => {
            crate::log(&format!("password check failed: {e:#}"));
            false
        }
    }
}

pub async fn me_password(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<PasswordForm>,
) -> Response {
    if !current_password_ok(&app, &ctx, form.current).await {
        app.flash(&ctx, Flash::error("Your current password is wrong.", Vec::new()));
        return app::redirect("/me");
    }
    if let Err(e) = new_password(&form.password, &form.confirm) {
        app.flash(&ctx, Flash::error(e, Vec::new()));
        return app::redirect("/me");
    }
    let saved = app.hasher.hash(&form.password).and_then(|hash| lock(&app.store).set_password(&ctx.admin, hash));
    match saved {
        Ok(()) => {
            lock(&app.sessions).remove_admin(&ctx.admin, Some(&ctx.cookie));
            audit(app::actor(&ctx, client), "own password changed", &ctx.admin, "ok").await;
            app.flash(&ctx, Flash::ok("Password changed; your other sessions were ended.", Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/me")
}

pub async fn totp_start(State(app): AppState, Extension(ctx): Extension<Ctx>) -> Response {
    let secret = match auth::random_bytes(20) {
        Ok(s) => s,
        Err(e) => return error_page(&app, &ctx, "me", &format!("{e:#}")),
    };
    if let Some(session) = lock(&app.sessions).get(&ctx.cookie, false) {
        session.totp_setup = Some(secret);
    }
    app::redirect("/me")
}

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

pub async fn totp_confirm(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<CodeForm>,
) -> Response {
    let pending = match lock(&app.sessions).get(&ctx.cookie, false) {
        Some(s) => s.totp_setup.clone(),
        None => None,
    };
    let Some(secret) = pending else {
        app.flash(&ctx, Flash::error("Start the setup again.", Vec::new()));
        return app::redirect("/me");
    };
    let step = auth::totp(&secret, &ctx.admin).map(|t| auth::check_code(&t, &form.code, 0, timefmt::now()));
    match step {
        Ok(Some(step)) => {
            let saved = lock(&app.store).set_totp(&ctx.admin, Some(Totp { secret: URL_SAFE_NO_PAD.encode(&secret), last_step: step }));
            match saved {
                Ok(()) => {
                    if let Some(session) = lock(&app.sessions).get(&ctx.cookie, false) {
                        session.totp_setup = None;
                    }
                    audit(app::actor(&ctx, client), "own TOTP enabled", &ctx.admin, "ok").await;
                    app.flash(&ctx, Flash::ok("Two-factor sign-in is on.", Vec::new()));
                }
                Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
            }
        }
        Ok(None) => app.flash(&ctx, Flash::error("That code is not right; check the time on your phone and try again.", Vec::new())),
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/me")
}

pub async fn totp_disable(
    State(app): AppState,
    Extension(ctx): Extension<Ctx>,
    Extension(client): Extension<Client>,
    Form(form): Form<PasswordForm>,
) -> Response {
    if !current_password_ok(&app, &ctx, form.current).await {
        app.flash(&ctx, Flash::error("Your password is wrong.", Vec::new()));
        return app::redirect("/me");
    }
    let cleared = lock(&app.store).set_totp(&ctx.admin, None);
    match cleared {
        Ok(()) => {
            audit(app::actor(&ctx, client), "own TOTP disabled", &ctx.admin, "ok").await;
            app.flash(&ctx, Flash::ok("Two-factor sign-in is off.", Vec::new()));
        }
        Err(e) => app.flash(&ctx, Flash::error(format!("{e:#}"), Vec::new())),
    }
    app::redirect("/me")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_reads_fail2ban_times() {
        assert_eq!(seconds("600"), Some(600));
        assert_eq!(seconds("600s"), Some(600));
        assert_eq!(seconds("10m"), Some(600));
        assert_eq!(seconds("1h"), Some(3_600));
        assert_eq!(seconds("2d"), Some(172_800));
        assert_eq!(seconds("1w"), Some(604_800));
        assert_eq!(seconds("-1"), Some(-1));
        assert_eq!(seconds("-1s"), Some(-1));
        assert_eq!(seconds(""), None);
        assert_eq!(seconds("h"), None);
        assert_eq!(seconds("1mo"), None);
    }

    #[test]
    fn a_saved_time_outside_the_presets_stays_selected_in_order() {
        let c = duration_choices(&LENGTH_PRESETS, "2h", "");
        let labels: Vec<&str> = c.iter().map(|c| c.label.as_str()).collect();
        assert_eq!(labels, ["10 minutes", "1 hour", "2 hours", "1 day", "1 week", "Forever"]);
        assert!(c[2].selected && c[2].value == "2h");
        assert_eq!(c.iter().filter(|c| c.selected).count(), 1);
    }

    #[test]
    fn a_preset_matches_by_length_not_spelling() {
        let c = duration_choices(&WINDOW_PRESETS, "600", "");
        assert_eq!(c.len(), WINDOW_PRESETS.len());
        assert!(c[1].selected && c[1].value == "10m");
        let c = duration_choices(&LENGTH_PRESETS, "-1", "");
        assert_eq!(c.len(), LENGTH_PRESETS.len());
        assert!(c[4].selected);
    }

    #[test]
    fn failure_and_repeat_choices_keep_the_saved_value() {
        let f = failure_choices(7);
        let values: Vec<&str> = f.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(values, ["3", "5", "7", "10", "20"]);
        assert!(f[2].selected && f[2].label == "7 failures");
        let r = repeat_choices(false, "1w");
        assert!(r[0].selected && r[0].value == "off");
        assert_eq!(r.iter().filter(|c| c.selected).count(), 1);
        let r = repeat_choices(true, "2w");
        assert!(r.iter().any(|c| c.selected && c.value == "2w" && c.label == "Doubling to 2 weeks"));
    }

    #[test]
    fn times_read_in_words() {
        assert_eq!(span(30), "Under a minute");
        assert_eq!(span(60), "1 minute");
        assert_eq!(span(7_200), "2 hours");
        assert_eq!(remaining(48 * 60), "48 minutes");
        assert_eq!(remaining(80 * 60), "1 hour 20 minutes");
        assert_eq!(remaining(3_600), "1 hour");
        assert_eq!(remaining(4 * 86_400), "4 days");
        assert_eq!(remaining(86_400 + 3_600), "1 day 1 hour");
        assert_eq!(duration_label(-1), "Forever");
        assert_eq!(duration_label(90), "90 seconds");
    }

    #[test]
    fn sizes_read_in_steps_of_1000() {
        assert_eq!(size_label(1), "1 byte");
        assert_eq!(size_label(999), "999 bytes");
        assert_eq!(size_label(845_000), "845 KB");
        assert_eq!(size_label(2_400_000), "2.4 MB");
        assert_eq!(size_label(12_300_000), "12 MB");
        assert_eq!(size_label(5_000_000_000), "5.0 GB");
    }
}
