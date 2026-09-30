//! Server description endpoint.

use axum::extract::State;
use axum::Json;
use serde::Serialize;
use std::sync::Arc;

use crate::codec::B64;
use crate::state::AppState;

/// What a client learns before it has any credentials.
///
/// Deliberately tiny. Everything here is either public by nature (protocol version,
/// default KDF parameters) or an operational flag. Later this is also where the
/// SHA-256 of the served web bundle belongs, so a desktop client can check what the
/// server is handing to a browser.
#[derive(Debug, Serialize)]
pub struct MetaResponse {
    /// Stored-data format version this server speaks.
    pub protocol_version: u8,
    /// KDF parameters to use for a newly created account.
    pub kdf_default: KdfDefault,
    /// Whether new accounts may be created.
    pub registration_open: bool,
    /// Server time, so a client can detect a badly skewed clock.
    pub server_time: i64,
    /// The desktop application this server offers, if it has one.
    ///
    /// `None` is a normal answer: a server built without running the desktop build script has
    /// nothing to hand out, and the portal then shows no download at all rather than a link
    /// that 404s.
    pub desktop: Option<DesktopBuildDto>,
}

/// A desktop build, described well enough that a person can verify what they downloaded.
#[derive(Debug, Serialize)]
pub struct DesktopBuildDto {
    pub file: String,
    /// Fetch path, relative to this origin.
    pub url: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
}

#[derive(Debug, Serialize)]
pub struct KdfDefault {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
    /// Present for symmetry with `prelogin`; always empty here because the salt is
    /// per-account and chosen by the client at registration.
    pub salt: B64,
}

pub async fn meta(State(state): State<Arc<AppState>>) -> Json<MetaResponse> {
    let params = cloudpass_core::params::KdfParams::RECOMMENDED;
    Json(MetaResponse {
        protocol_version: cloudpass_core::PROTOCOL_VERSION,
        kdf_default: KdfDefault {
            m_kib: params.m_kib,
            t: params.t,
            p: params.p,
            salt: B64::default(),
        },
        registration_open: state.registration_open,
        server_time: crate::codec::now_unix(),
        desktop: state.desktop_build.as_ref().map(|build| DesktopBuildDto {
            file: build.file_name.clone(),
            url: build.url.clone(),
            size: build.size,
            sha256: build.sha256.clone(),
        }),
    })
}
