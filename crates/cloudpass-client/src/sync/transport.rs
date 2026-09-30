//! The transport seam: bytes out, bytes back.

use crate::error::Result;

/// HTTP method, restricted to the three this API uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
}

impl Method {
    /// The wire form of the method.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
        }
    }
}

/// A request, in the smallest shape that is still enough to describe this API.
///
/// Deliberately not a general-purpose HTTP client: there are no headers to set, no
/// redirects to follow and no cookies. The bearer token is the one thing that varies.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: Method,
    /// Path only, such as `/api/v1/sync/pull?cursor=0`. The base URL belongs to the
    /// transport, so the logic never has to know where the server lives.
    pub path: String,
    pub token: Option<String>,
    /// JSON body. Empty for `GET`.
    pub body: Vec<u8>,
}

impl HttpRequest {
    #[must_use]
    pub fn get(path: impl Into<String>, token: Option<String>) -> Self {
        Self {
            method: Method::Get,
            path: path.into(),
            token,
            body: Vec::new(),
        }
    }

    #[must_use]
    pub fn post(path: impl Into<String>, token: Option<String>, body: Vec<u8>) -> Self {
        Self {
            method: Method::Post,
            path: path.into(),
            token,
            body,
        }
    }
}

/// A response, reduced to a status and a body.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Whether the server reported success.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Sends requests. Implemented by the desktop's HTTP client, by the browser's `fetch`,
/// and — in tests — by an in-process router or a scripted fake.
///
/// `async fn` in a trait is allowed but discouraged because callers cannot state the
/// auto-trait bounds they need. That is acceptable here: the trait is used through a
/// generic parameter in a single-threaded client, never as `dyn Transport`, so there is
/// no place for a missing `Send` bound to matter.
#[allow(async_fn_in_trait)]
pub trait Transport {
    /// Performs one request. An error here means the bytes never made a round trip;
    /// a non-2xx status is a successful call with an unsuccessful answer.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse>;
}
