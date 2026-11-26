//! The admin web UI of the docker-sftp image.
//!
//!   sftp-webui serve           run the server (the entrypoint starts it)
//!   sftp-webui files           run the file browser, on WEBUI_PORT as the
//!                              entrypoint sets it for this process
//!   sftp-webui check           validate the WEBUI_* settings and admin file
//!   sftp-webui hash-password   read a password on stdin, print its hash
//!   sftp-webui --version

mod app;
mod assets;
mod browser;
mod charts;
mod config;
mod fm;
mod helper;
mod pages;
mod server;
mod share;
mod sessions;
mod sftp;
mod store;

use std::io::BufRead;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use sftp_webui::auth;

pub fn log(msg: &str) {
    println!("{} sftp-webui: {msg}", sftp_webui::timefmt::iso(sftp_webui::timefmt::now()));
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("serve") => serve(),
        Some("files") => files(),
        Some("check") => check(),
        Some("hash-password") => hash_password(),
        Some("--version") => {
            println!("sftp-webui {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        _ => {
            eprintln!("usage: sftp-webui serve | files | check | hash-password | --version");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

fn check() -> Result<()> {
    let config = config::Config::from_env()?;
    if let Some(path) = &config.admin_file {
        let admins = store::read_admin_file(path)?;
        if admins.is_empty() {
            bail!("WEBUI_ADMIN_FILE={} holds no admin", path.display());
        }
    }
    Ok(())
}

fn hash_password() -> Result<()> {
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line).context("cannot read the password from standard input")?;
    let password = line.trim_end_matches(['\r', '\n']);
    auth::check_password_rules(password).map_err(|e| anyhow::anyhow!(e))?;
    let hasher = auth::Hasher::new()?;
    println!("{}", hasher.hash(password)?);
    Ok(())
}

fn serve() -> Result<()> {
    let config = config::Config::from_env()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(server::run(config))
}

fn files() -> Result<()> {
    let config = config::Config::from_env()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("cannot start the async runtime")?;
    runtime.block_on(browser::run(config))
}
