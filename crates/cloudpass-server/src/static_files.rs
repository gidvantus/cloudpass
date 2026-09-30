//! Serving the web portal.
//!
//! # Why this is hand-written
//!
//! A general-purpose static file server brings a directory-listing bug and a traversal
//! bug with it, and neither is worth the dependency for six file types. What is here
//! does exactly three things: map a path to one file inside one directory, refuse
//! anything that resolves outside it, and attach the headers the portal needs.
//!
//! # The headers are part of the security argument
//!
//! The portal is the client whose JavaScript the server itself hands out, so a single
//! injected script would defeat the whole design. That is what the content security
//! policy is for: no inline script, no third-party origin, no `eval`. WebAssembly
//! compilation needs `'wasm-unsafe-eval'` — without it the module does not load — and
//! that permission is scoped to this origin's own files by `'self'`.
//!
//! # What it does not do
//!
//! It does not serve `pkg/` specially, cache, compress, or support range requests. The
//! files are small, they are served over the same origin as the API, and `no-store`
//! means a rebuilt portal is picked up by a reload rather than by a cache-busting
//! argument nobody remembers to add.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::state::AppState;

/// The content security policy the portal is served under.
///
/// `default-src 'none'` and then only what the page genuinely needs. Two entries are worth
/// their own explanation:
///
/// * `'wasm-unsafe-eval'` is what allows the browser to *compile* the module; without it
///   `WebAssembly.instantiate` is blocked and the portal never starts.
/// * `font-src 'self'` exists because the typeface is served from this origin rather than
///   from a font CDN. A page that cannot load a third-party font is a page that cannot be
///   fingerprinted by one, and the rule this project set for itself — no external origins at
///   all — is only enforceable if the font it wants is here.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'self' 'wasm-unsafe-eval'; \
     style-src 'self'; \
     font-src 'self'; \
     img-src 'self' data:; \
     connect-src 'self'; \
     base-uri 'none'; \
     form-action 'none'; \
     frame-ancestors 'none'";

/// Where the portal's files live, unless `CLOUDPASS_WEB_ROOT` says otherwise.
#[must_use]
pub fn default_root() -> PathBuf {
    std::env::var("CLOUDPASS_WEB_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("apps/web/ui"))
}

/// Resolves the configured root once, at startup.
///
/// Canonicalised here rather than per request so that the containment check below is a
/// comparison of two real paths. `None` means there is no portal to serve, which is a
/// supported state: the API is the product, and the portal is one client of it.
#[must_use]
pub fn resolve_root(configured: &Path) -> Option<PathBuf> {
    std::fs::canonicalize(configured).ok()
}

/// The fallback handler: everything that is not an API route.
pub async fn serve(State(state): State<Arc<AppState>>, uri: Uri) -> Response {
    let Some(root) = state.web_root.as_ref() else {
        return not_found(Some(
            "the web portal is not built: run scripts/build-web.ps1, or point \
             CLOUDPASS_WEB_ROOT at the directory that holds index.html",
        ));
    };

    let requested = uri.path().trim_start_matches('/');
    let requested = if requested.is_empty() {
        "index.html"
    } else {
        requested
    };

    // Reject anything that could climb out before touching the filesystem. The
    // canonical containment check below is the real guard; this is the cheap one, and it
    // also rejects empty segments, which would otherwise make `a//b` resolve oddly.
    if requested
        .split(['/', '\\'])
        .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return not_found(None);
    }

    let candidate = root.join(requested);
    let Ok(real) = tokio::fs::canonicalize(&candidate).await else {
        return not_found(None);
    };
    if !real.starts_with(root) {
        return not_found(None);
    }

    let Ok(bytes) = tokio::fs::read(&real).await else {
        return not_found(None);
    };

    let (content_type, cache) = match real.extension().and_then(|e| e.to_str()) {
        Some("html") => ("text/html; charset=utf-8", "no-store"),
        Some("js") => ("text/javascript; charset=utf-8", "no-store"),
        Some("css") => ("text/css; charset=utf-8", "no-store"),
        Some("wasm") => ("application/wasm", "no-store"),
        Some("json") => ("application/json", "no-store"),
        Some("svg") => ("image/svg+xml", "no-store"),
        Some("png") => ("image/png", "no-store"),
        Some("ico") => ("image/x-icon", "no-store"),
        // A font served as `octet-stream` is a font the browser refuses to use, so the type
        // silently falls back to whatever the system has and the design stops being the
        // design. That failure is invisible in a terminal and obvious in the page, which is
        // exactly the kind that survives to production.
        Some("woff2") => ("font/woff2", "no-store"),
        Some("txt") => ("text/plain; charset=utf-8", "no-store"),
        // A Windows program. `application/octet-stream` is deliberate rather than a
        // PE-specific type: it is what makes every browser save the file instead of trying to
        // be clever with it.
        Some("exe") | Some("msi") => ("application/octet-stream", "no-store"),
        _ => ("application/octet-stream", "no-store"),
    };

    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, cache)
        .header(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer");

    // Installers are downloads, not pages. Without this a browser that has been taught to
    // associate something with `.exe` would navigate to it, and a `Content-Disposition` also
    // means the saved file keeps the name the server advertised — which is the name whose
    // SHA-256 the portal publishes.
    if let Some(name) = attachment_name(&real) {
        builder = builder.header(
            header::CONTENT_DISPOSITION,
            format!("attachment; filename=\"{name}\""),
        );
    }

    match builder.body(Body::from(bytes)) {
        Ok(response) => response,
        Err(_) => {
            // Only reachable if a header value were invalid. Reported as a missing file rather
            // than as a 500, so that nothing about the server's internals reaches the page.
            not_found(None)
        }
    }
}

/// The name to offer as a download, for the file types that are downloads.
///
/// Quoted in the header, so a file name containing a quote would break out of it. Names come
/// from our own build scripts, and one that did contain a quote would be rejected here rather
/// than trusted — a small check in front of a small risk, which is the cheapest kind.
fn attachment_name(path: &Path) -> Option<&str> {
    let extension = path.extension()?.to_str()?;
    if !extension.eq_ignore_ascii_case("exe") && !extension.eq_ignore_ascii_case("msi") {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    if name.contains(['"', '\\', '\r', '\n']) {
        return None;
    }
    Some(name)
}

fn not_found(message: Option<&str>) -> Response {
    let body = message.unwrap_or("not found");
    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body.to_owned(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::body::to_bytes;
    use cloudpass_core::opaque::server::ServerSetupState;

    /// A portal directory with the file types the portal actually ships.
    fn portal_dir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cloudpass-portal-{}",
            cloudpass_core::ids::random_uuid()
        ));
        std::fs::create_dir_all(&dir).expect("create portal dir");
        std::fs::write(dir.join("index.html"), b"<html>portal</html>").expect("write");
        std::fs::write(dir.join("app.js"), b"export const x = 1;").expect("write");
        std::fs::write(dir.join("app.css"), b":root{}").expect("write");
        std::fs::write(dir.join("montserrat.woff2"), b"wOF2 not really").expect("write");

        // An installer, so the download path is covered by the same handler.
        let download = dir.join("download");
        std::fs::create_dir_all(&download).expect("create download dir");
        std::fs::write(
            download.join("CloudPass_0.1.0_x64-setup.exe"),
            b"MZ not really",
        )
        .expect("write");
        dir
    }

    async fn state_with(web_root: Option<PathBuf>) -> Arc<AppState> {
        let pool = crate::db::connect("sqlite::memory:")
            .await
            .expect("connect");
        Arc::new(AppState {
            pool,
            setup: ServerSetupState::generate(),
            prelogin_secret: [0u8; 32],
            registration_open: true,
            web_root,
            desktop_build: None,
        })
    }

    async fn body_of(response: Response) -> String {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8_lossy(&bytes).into_owned()
    }

    #[tokio::test]
    async fn the_root_serves_the_portal_under_a_strict_policy() {
        let dir = portal_dir();
        let state = state_with(resolve_root(&dir)).await;

        let response = serve(State(Arc::clone(&state)), Uri::from_static("/")).await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers().clone();
        assert_eq!(
            headers.get(header::CONTENT_TYPE).expect("content type"),
            "text/html; charset=utf-8"
        );

        // The module cannot be compiled without this, and nothing else may run.
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .expect("csp")
            .to_str()
            .expect("ascii");
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("'wasm-unsafe-eval'"));
        assert!(csp.contains("script-src 'self'"));
        // The typeface is served from here, so the policy has to allow it from here. A
        // `default-src 'none'` without this entry blocks the font, and a blocked font is a
        // page that silently renders in something else.
        assert!(csp.contains("font-src 'self'"));
        assert!(!csp.contains("unsafe-inline"));

        assert!(body_of(response).await.contains("portal"));

        let script = serve(State(Arc::clone(&state)), Uri::from_static("/app.js")).await;
        assert_eq!(
            script.headers().get(header::CONTENT_TYPE).expect("type"),
            "text/javascript; charset=utf-8"
        );

        let style = serve(State(Arc::clone(&state)), Uri::from_static("/app.css")).await;
        assert_eq!(
            style.headers().get(header::CONTENT_TYPE).expect("type"),
            "text/css; charset=utf-8"
        );

        // `application/octet-stream` here would be a font the browser declines to use.
        let font = serve(
            State(Arc::clone(&state)),
            Uri::from_static("/montserrat.woff2"),
        )
        .await;
        assert_eq!(
            font.headers().get(header::CONTENT_TYPE).expect("type"),
            "font/woff2"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn leaving_the_portal_directory_is_refused() {
        let dir = portal_dir();
        let state = state_with(resolve_root(&dir)).await;

        for path in [
            // A client that sends the dots itself, without a browser normalising them
            // away first. This is the request that matters: the browser will never make
            // it, and an attacker will.
            "/../Cargo.toml",
            "/../../Cargo.toml",
            "/./index.html",
            "/pkg/../../Cargo.toml",
            "/missing.html",
        ] {
            let uri: Uri = path.parse().expect("a valid uri");
            let response = serve(State(Arc::clone(&state)), uri).await;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} should not have been served"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An installer has to arrive as a download, under the name the portal advertised.
    ///
    /// Both halves matter. A browser that navigates to an `.exe` instead of saving it, or one
    /// that saves it as something other than the advertised name, breaks the only check a
    /// person can actually make on a binary: comparing its hash with the published one.
    #[tokio::test]
    async fn an_installer_is_served_as_a_download_under_its_own_name() {
        let dir = portal_dir();
        let state = state_with(resolve_root(&dir)).await;

        let response = serve(
            State(Arc::clone(&state)),
            Uri::from_static("/download/CloudPass_0.1.0_x64-setup.exe"),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get(header::CONTENT_DISPOSITION)
                .expect("content disposition")
                .to_str()
                .expect("ascii"),
            "attachment; filename=\"CloudPass_0.1.0_x64-setup.exe\""
        );
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).expect("type"),
            "application/octet-stream"
        );
        assert_eq!(body_of(response).await, "MZ not really");

        // A page is not a download, and must not be labelled as one.
        let page = serve(State(Arc::clone(&state)), Uri::from_static("/app.js")).await;
        assert!(page.headers().get(header::CONTENT_DISPOSITION).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_server_without_a_portal_still_answers() {
        let state = state_with(None).await;
        let response = serve(State(state), Uri::from_static("/")).await;
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(body_of(response).await.contains("not built"));
    }

    #[test]
    fn a_missing_directory_resolves_to_nothing_rather_than_failing() {
        assert!(resolve_root(Path::new("definitely/not/here")).is_none());
    }
}
