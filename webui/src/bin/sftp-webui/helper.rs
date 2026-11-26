//! The client side of the root helper's socket: one request per
//! connection. A change can take as long as `entrypoint apply`, startup
//! scripts included, so no deadline is put on the reply.

use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use sftp_webui::proto::{self, Reply, Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub async fn call(request: &Request) -> Result<Reply> {
    let mut stream = UnixStream::connect(proto::SOCKET).await.context("cannot reach the root helper")?;
    let mut line = serde_json::to_vec(request).context("cannot encode the request")?;
    line.push(b'\n');
    stream.write_all(&line).await.context("cannot send the request")?;
    stream.shutdown().await.context("cannot finish the request")?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.context("cannot read the reply")?;
    serde_json::from_slice(&raw).context("the root helper sent an unreadable reply")
}

/// A read whose reply carries data of type T.
pub async fn data<T: DeserializeOwned>(request: &Request) -> Result<T> {
    let reply = call(request).await?;
    if !reply.ok {
        bail!("{}", reply.error);
    }
    serde_json::from_value(reply.data).context("the root helper sent unexpected data")
}
