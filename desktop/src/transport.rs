//! The HTTP transport.
//!
//! Thin on purpose: it turns the client library's request type into a `reqwest` call and
//! the answer back into bytes. Every decision about *what* to send lives in
//! `cloudpass-client`, where it is testable without a socket.
//!
//! # TLS
//!
//! `rustls` rather than the platform TLS stack. A password manager's transport should
//! not vary with the machine it was built on, and a bundled stack is one fewer thing
//! that can be quietly misconfigured by the environment.

use std::time::Duration;

use cloudpass_client::sync::{HttpRequest, HttpResponse, Method, Transport};
use cloudpass_client::ClientError;

/// Sends requests to one server.
pub struct HttpTransport {
    client: reqwest::Client,
    base_url: String,
}

impl HttpTransport {
    /// Builds a transport for a server URL such as `http://127.0.0.1:8080`.
    pub fn new(base_url: &str) -> Result<Self, ClientError> {
        Self::build(base_url, None)
    }

    /// Builds a transport that gives up on an answer after `timeout`.
    ///
    /// For requests nobody is waiting in front of — the update check, which runs in the
    /// background — where a server that has stopped answering must not leave a task
    /// holding the application's state lock, and therefore the vault, until it does.
    pub fn with_timeout(base_url: &str, timeout: Duration) -> Result<Self, ClientError> {
        Self::build(base_url, Some(timeout))
    }

    fn build(base_url: &str, timeout: Option<Duration>) -> Result<Self, ClientError> {
        let mut builder = reqwest::Client::builder()
            // A password manager talking to its own server has no use for a proxy, and
            // honouring one silently would send vault metadata somewhere it does not
            // belong.
            .no_proxy();
        if let Some(timeout) = timeout {
            builder = builder.timeout(timeout);
        }

        let client = builder
            .build()
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_owned(),
        })
    }
}

impl Transport for HttpTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let url = format!("{}{}", self.base_url, request.path);

        let mut builder = match request.method {
            Method::Get => self.client.get(&url),
            Method::Post => self.client.post(&url),
            Method::Put => self.client.put(&url),
        };

        if let Some(token) = &request.token {
            builder = builder.bearer_auth(token);
        }
        if request.method != Method::Get {
            builder = builder
                .header("content-type", "application/json")
                .body(request.body);
        }

        let response = builder
            .send()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|error| ClientError::Transport(error.to_string()))?
            .to_vec();

        Ok(HttpResponse { status, body })
    }
}
