//! The WEBUI_* settings, read from the environment the entrypoint passes.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use sftp_webui::net::{self, Network};

pub struct Config {
    pub port: u16,
    pub plain_http: bool,
    pub trusted_proxies: Vec<Network>,
    pub trusted_networks: Vec<Network>,
    pub admin_file: Option<PathBuf>,
    /// The file browser's port while it is on, for the sign-in links the
    /// admin web UI makes.
    pub files_port: Option<u16>,
}

fn var(key: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(v) => Ok(v.trim().to_string()),
        Err(std::env::VarError::NotPresent) => Ok(String::new()),
        Err(e) => Err(e).with_context(|| format!("{key} is not valid text")),
    }
}

fn flag(key: &str) -> Result<bool> {
    let value = var(key)?;
    match value.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "" | "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("{key}={value} must be true or false"),
    }
}

impl Config {
    pub fn from_env() -> Result<Config> {
        let port_text = var("WEBUI_PORT")?;
        let port = if port_text.is_empty() {
            8443
        } else {
            if port_text.len() > 5 || !port_text.bytes().all(|b| b.is_ascii_digit()) {
                bail!("WEBUI_PORT={port_text} is not a port number");
            }
            let port: u32 = port_text.parse().with_context(|| format!("WEBUI_PORT={port_text}"))?;
            if !(1024..=65535).contains(&port) {
                bail!("WEBUI_PORT={port_text} must be from 1024 to 65535, since the web UI runs without root");
            }
            u16::try_from(port).with_context(|| format!("WEBUI_PORT={port_text}"))?
        };
        let plain_http = flag("WEBUI_PLAIN_HTTP")?;
        let trusted_proxies = net::parse_list(&var("WEBUI_TRUSTED_PROXIES")?)
            .map_err(|e| anyhow::anyhow!("WEBUI_TRUSTED_PROXIES: {e}"))?;
        let trusted_networks = net::parse_list(&var("WEBUI_TRUSTED_NETWORKS")?)
            .map_err(|e| anyhow::anyhow!("WEBUI_TRUSTED_NETWORKS: {e}"))?;
        if plain_http && trusted_proxies.is_empty() {
            bail!("WEBUI_PLAIN_HTTP=true needs WEBUI_TRUSTED_PROXIES, the addresses of the proxy that serves HTTPS");
        }
        let admin_file = match var("WEBUI_ADMIN_FILE")? {
            p if p.is_empty() => None,
            p => Some(PathBuf::from(p)),
        };
        let files_text = var("WEBUI_FILES_PORT")?;
        let files_port = if files_text.is_empty() {
            None
        } else {
            Some(files_text.parse::<u16>().with_context(|| format!("WEBUI_FILES_PORT={files_text} is not a port number"))?)
        };
        Ok(Config { port, plain_http, trusted_proxies, trusted_networks, admin_file, files_port })
    }
}
