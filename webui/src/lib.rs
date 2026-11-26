//! Code shared by the admin web UI (`sftp-webui`) and its root helper
//! (`sftp-helper`): the protocol between them, the validation rules both
//! apply before anything reaches the entrypoint, which validates again, and
//! the password and second-factor checks both make.

pub mod auth;
pub mod events;
pub mod geo;
pub mod net;
pub mod proto;
pub mod spec;
pub mod sshkey;
pub mod tar;
pub mod timefmt;
pub mod zip;
