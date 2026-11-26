//! Share links in the file browser: making one for a file, the page of the
//! links a person made, and the public page a link opens, which downloads
//! the file once. The root helper keeps the links; a token travels after
//! the # of a link, which no request carries, and reaches the server only
//! in the body of the public page's own requests.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use askama::Template;
use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use sftp_webui::auth::Refusal;
use sftp_webui::proto::{FilesRequest, Secret, ShareMade, ShareTarget, ShareView};

use crate::app::{self, Client, lock};
use crate::browser::{Browser, LOGIN_COOKIE, Who, ask, capitalized, connect_signed, failure, layout};
use crate::fm;
use crate::pages::Layout;

type Shared = State<Arc<Browser>>;

/// An answer that ends a request early, boxed so a Result stays small.
type Early = Box<Response>;

fn form(body: &[u8]) -> Result<Vec<(String, String)>, Early> {
    match serde_urlencoded::from_bytes::<Vec<(String, String)>>(body) {
        Ok(pairs) => Ok(pairs),
        Err(e) => Err(Box::new((StatusCode::UNPROCESSABLE_ENTITY, format!("The form cannot be read: {e}")).into_response())),
    }
}

fn field(pairs: &[(String, String)], key: &str) -> String {
    match pairs.iter().find(|(k, _)| k == key) {
        Some((_, v)) => v.clone(),
        None => String::new(),
    }
}

/// Asks the helper and returns its data, or the response that reports why
/// it said no.
async fn helper_data<T: serde::de::DeserializeOwned>(request: &FilesRequest) -> Result<T, Early> {
    let reply = match ask(request).await {
        Ok(r) => r,
        Err(e) => return Err(Box::new(failure(&e))),
    };
    if !reply.ok {
        return Err(Box::new((StatusCode::UNPROCESSABLE_ENTITY, capitalized(&reply.error)).into_response()));
    }
    match serde_json::from_value(reply.data) {
        Ok(v) => Ok(v),
        Err(e) => Err(Box::new(failure(&anyhow!("the helper's answer cannot be read: {e}")))),
    }
}

/// What the server allows of share links to the files the page shows, for
/// its share dialog.
pub(crate) async fn policy(who: &Who) -> Result<sftp_webui::proto::SharePolicy> {
    let acting = if who.acting == who.account { None } else { Some(who.acting.clone()) };
    let reply = ask(&FilesRequest::SharePolicy { session: Secret(who_helper(who)), acting }).await?;
    if !reply.ok {
        bail!("{}", reply.error);
    }
    serde_json::from_value(reply.data).context("the helper sent no share policy")
}

#[derive(Serialize)]
struct Made {
    token: String,
    expires: String,
}

/// Makes a link to a file of the account acted as; the token comes back
/// once, for the page to put after the # of the link it shows.
pub async fn create(Extension(who): Extension<Who>, body: Bytes) -> Response {
    let pairs = match form(&body) {
        Ok(p) => p,
        Err(res) => return *res,
    };
    let path = fm::clean(&field(&pairs, "path"));
    let days = match field(&pairs, "days").parse::<u32>() {
        Ok(d) => d,
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, format!("Choose how many days the link lasts: {e}")).into_response(),
    };
    match fm::with_sftp(&who, async |s| s.stat(&path).await).await {
        Ok(attrs) if attrs.dir() || attrs.link() => {
            return (StatusCode::UNPROCESSABLE_ENTITY, "Only a file can be shared.").into_response();
        }
        Ok(_) => {}
        Err(e) => return (StatusCode::UNPROCESSABLE_ENTITY, capitalized(&format!("{e:#}"))).into_response(),
    }
    let acting = if who.acting == who.account { None } else { Some(who.acting.clone()) };
    let request = FilesRequest::ShareCreate {
        session: Secret(who_helper(&who)),
        acting,
        path,
        days,
        password: Secret(field(&pairs, "password")),
    };
    let made: ShareMade = match helper_data(&request).await {
        Ok(m) => m,
        Err(res) => return *res,
    };
    let text = match serde_json::to_string(&Made { token: made.token.0, expires: sftp_webui::timefmt::display(made.expires) }) {
        Ok(t) => t,
        Err(e) => return failure(&anyhow!("cannot write the link: {e}")),
    };
    let mut res = (StatusCode::OK, text).into_response();
    res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    res
}

fn who_helper(who: &Who) -> String {
    who.helper_session()
}

pub struct LinkRow {
    pub id: String,
    pub file: String,
    pub made: String,
    pub ends: String,
    pub state: &'static str,
    pub password: bool,
}

#[derive(Template)]
#[template(path = "files_links.html")]
struct LinksPage {
    l: Layout,
    files_js: String,
    account: String,
    place: fm::Place,
    rows: Vec<LinkRow>,
    error: String,
}

/// The links the person made, with each one's state.
pub async fn links(State(b): Shared, Extension(who): Extension<Who>) -> Response {
    let (place, mut error) = fm::place_of(&who).await;
    let views: Vec<ShareView> = match helper_data(&FilesRequest::ShareList { session: Secret(who_helper(&who)) }).await {
        Ok(v) => v,
        Err(res) => return *res,
    };
    let now = sftp_webui::timefmt::now();
    let rows = views
        .into_iter()
        .map(|v| LinkRow {
            file: if v.account == who.account { v.path } else { format!("{}: {}", v.account, v.path) },
            made: sftp_webui::timefmt::display(v.created),
            ends: sftp_webui::timefmt::display(v.expires),
            state: match (v.used, v.expires > now) {
                (Some(_), _) => "Used",
                (None, true) => "Waiting",
                (None, false) => "Expired",
            },
            password: v.password,
            id: v.id,
        })
        .collect();
    if !error.is_empty() {
        crate::log(&format!("file browser: {error}"));
        error.clear();
    }
    let mut l = layout(&b, "Links you shared", &who.csrf);
    l.admin = who.account.clone();
    l.initials = who.account.chars().take(1).flat_map(char::to_uppercase).collect();
    app::render(StatusCode::OK, &LinksPage { l, files_js: b.assets.files_js.clone(), account: who.account.clone(), place, rows, error })
}

pub async fn revoke(Extension(who): Extension<Who>, body: Bytes) -> Response {
    let pairs = match form(&body) {
        Ok(p) => p,
        Err(res) => return *res,
    };
    let request = FilesRequest::ShareRevoke { session: Secret(who_helper(&who)), id: field(&pairs, "id") };
    match ask(&request).await {
        Ok(reply) if reply.ok => app::redirect("/links"),
        Ok(reply) => (StatusCode::UNPROCESSABLE_ENTITY, capitalized(&reply.error)).into_response(),
        Err(e) => failure(&e),
    }
}

#[derive(Template)]
#[template(path = "share.html")]
struct SharePage {
    l: Layout,
    login_token: String,
}

/// The page a link opens. Its script reads the token after the #, which
/// the browser never sends, and posts it.
pub async fn page(State(b): Shared) -> Response {
    let token = match sftp_webui::auth::token() {
        Ok(t) => t,
        Err(e) => return failure(&e),
    };
    let mut res = app::render(StatusCode::OK, &SharePage { l: layout(&b, "A shared file", ""), login_token: token.clone() });
    match app::set_cookie(LOGIN_COOKIE, &token) {
        Ok(v) => {
            res.headers_mut().append(header::SET_COOKIE, v);
            res
        }
        Err(e) => failure(&e),
    }
}

#[derive(Serialize)]
struct Shown {
    name: String,
    ends: String,
    password: bool,
}

/// What a link leads to, for its page; the link is not used.
pub async fn info(body: Bytes) -> Response {
    let pairs = match form(&body) {
        Ok(p) => p,
        Err(res) => return *res,
    };
    let target: ShareTarget = match helper_data(&FilesRequest::ShareInfo { token: Secret(field(&pairs, "token")) }).await {
        Ok(t) => t,
        Err(res) => return *res,
    };
    let shown = Shown {
        name: fm::name_of(&target.path).to_string(),
        ends: sftp_webui::timefmt::display(target.expires),
        password: target.password,
    };
    match serde_json::to_string(&shown) {
        Ok(text) => {
            let mut res = (StatusCode::OK, text).into_response();
            res.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            res
        }
        Err(e) => failure(&anyhow!("cannot write the link's details: {e}")),
    }
}

/// Downloads the file a link leads to, once. The link is claimed for the
/// download, spent when it completes, and given back when it does not.
pub async fn get(State(b): Shared, Extension(client): Extension<Client>, body: Bytes) -> Response {
    let ip = client.0;
    if let Err(r) = lock(&b.throttle).check(ip, Instant::now()) {
        let wait = match r {
            Refusal::Locked(d) | Refusal::Busy(d) => d.as_secs().div_ceil(60),
        };
        return (StatusCode::TOO_MANY_REQUESTS, format!("Too many wrong passwords. Try again in {wait} minutes.")).into_response();
    }
    let pairs = match form(&body) {
        Ok(p) => p,
        Err(res) => return *res,
    };
    let token = field(&pairs, "token");
    let password = field(&pairs, "password");
    let target: ShareTarget = match helper_data(&FilesRequest::ShareInfo { token: Secret(token.clone()) }).await {
        Ok(t) => t,
        Err(res) => return *res,
    };
    let mut refused = String::new();
    let claimed = connect_signed(&target.account, async |public_key| {
        let request =
            FilesRequest::ShareClaim { token: Secret(token.clone()), password: Secret(password), address: ip.to_string(), public_key };
        let reply = ask(&request).await?;
        if !reply.ok {
            refused = reply.error.clone();
            bail!("{}", reply.error);
        }
        let claim: ShareTarget = serde_json::from_value(reply.data).context("the helper sent no certificate")?;
        Ok(claim.certificate)
    })
    .await;
    let mut conn = match claimed {
        Ok(c) => c,
        Err(e) => {
            if refused == "wrong password" {
                lock(&b.throttle).failure(ip, Instant::now());
                crate::pages::syslog(true, &format!("failed login from {ip} (share link)"));
            }
            if refused.is_empty() {
                done(&token, false).await;
                crate::log(&format!("file browser: a share link's connection failed: {e:#}"));
            }
            return (StatusCode::UNPROCESSABLE_ENTITY, capitalized(&format!("{e:#}"))).into_response();
        }
    };
    let opened = match conn.sftp.stat(&target.path).await {
        Ok(attrs) if attrs.dir() => Err(anyhow!("the shared file is now a folder")),
        Ok(attrs) => match conn.sftp.open_read(&target.path).await {
            Ok(file) => Ok((file, attrs.size)),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    let (file, size) = match opened {
        Ok(found) => found,
        Err(e) => {
            done(&token, false).await;
            return (StatusCode::NOT_FOUND, capitalized(&format!("{e:#}"))).into_response();
        }
    };
    crate::browser::emit(&sftp_webui::events::WebEvent {
        kind: sftp_webui::events::Kind::Download,
        actor: "a share link".into(),
        account: target.account.clone(),
        address: ip.to_string(),
        path: target.path.clone(),
        other: String::new(),
        bytes: size.into_iter().sum(),
    });
    let named = match HeaderValue::from_str(&format!(
        "attachment; filename*=UTF-8''{}",
        fm::query_text(fm::name_of(&target.path)).replace('/', "%2F")
    )) {
        Ok(v) => v,
        Err(e) => {
            done(&token, false).await;
            return failure(&anyhow!("cannot name the download: {e}"));
        }
    };
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tokio::spawn(async move {
        let mut offset = 0u64;
        let complete = loop {
            match conn.sftp.read(&file, offset).await {
                Ok(Some(chunk)) => {
                    offset += chunk.len() as u64;
                    if tx.send(Ok(Bytes::from(chunk))).await.is_err() {
                        break false;
                    }
                }
                Ok(None) => break true,
                Err(e) => {
                    crate::log(&format!("file browser: reading a shared file: {e:#}"));
                    if tx.send(Err(std::io::Error::other(format!("{e:#}")))).await.is_err() {
                        crate::log("file browser: the shared download ended before its error could be sent");
                    }
                    break false;
                }
            }
        };
        if let Err(e) = conn.sftp.close(&file).await {
            crate::log(&format!("file browser: closing a shared file: {e:#}"));
        }
        done(&token, complete).await;
    });
    let mut res = Body::new(fm::Chunks(rx)).into_response();
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    h.insert(header::CONTENT_DISPOSITION, named);
    if let Some(n) = size {
        h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
    }
    res
}

/// Reports a download's end to the helper, which spends the link when it
/// completed and gives it back when not.
async fn done(token: &str, complete: bool) {
    match ask(&FilesRequest::ShareDone { token: Secret(token.to_string()), done: complete }).await {
        Ok(reply) if reply.ok => {}
        Ok(reply) => crate::log(&format!("file browser: a share link's end was not recorded: {}", reply.error)),
        Err(e) => crate::log(&format!("file browser: a share link's end was not recorded: {e:#}")),
    }
}
