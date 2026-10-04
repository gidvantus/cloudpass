//! The HTTP transport, against a real socket.
//!
//! Everything else in the client is tested against a scripted transport, which is the
//! point of the trait. That leaves exactly one piece untested: the glue that turns a
//! request into a `reqwest` call and an answer back into bytes. These tests cover it —
//! URL construction, the bearer header, the JSON content type, and how a non-2xx status
//! is reported — by speaking HTTP to a real listener rather than mocking `reqwest`.
//!
//! The handler is deliberately hand-rolled instead of pulling in a web framework: the
//! thing under test is a client, and the responder only has to be honest about what it
//! received.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use cloudpass_client::sync::{HttpRequest, Transport};
use cloudpass_client::ClientError;
use cloudpass_desktop_lib::transport::HttpTransport;

/// A listener that answers exactly one request and hands back what it read.
fn serve_once(status: &'static str, body: &'static str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let address = listener.local_addr().expect("local address");

    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept one connection");
        let request = read_request(&mut stream);

        let response = format!(
            "HTTP/1.1 {status}\r\n\
             content-type: application/json\r\n\
             content-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
        request
    });

    (format!("http://{address}"), handle)
}

/// Reads a complete HTTP/1.1 request, headers and body.
fn read_request(stream: &mut TcpStream) -> String {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];

    loop {
        let read = stream.read(&mut buffer).unwrap_or(0);
        if read == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..read]);

        if let Some(headers_end) = find_headers_end(&data) {
            let head = String::from_utf8_lossy(&data[..headers_end]).to_lowercase();
            let length: usize = head
                .lines()
                .find_map(|line| line.strip_prefix("content-length:"))
                .and_then(|value| value.trim().parse().ok())
                .unwrap_or(0);
            if data.len() >= headers_end + 4 + length {
                break;
            }
        }
    }

    String::from_utf8_lossy(&data).into_owned()
}

fn find_headers_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n")
}

#[tokio::test]
async fn a_get_carries_the_path_and_the_bearer_token_and_no_body() {
    let (base, handle) = serve_once("200 OK", r#"{"ok":true}"#);
    let transport = HttpTransport::new(&base).expect("transport");

    let response = transport
        .send(HttpRequest::get(
            "/api/v1/sync/pull?cursor=7",
            Some("token-abc".to_owned()),
        ))
        .await
        .expect("send");

    assert!(response.is_success());
    assert_eq!(response.status, 200);
    assert_eq!(response.body, br#"{"ok":true}"#);

    let request = handle.join().expect("handler");
    let head = request.lines().next().unwrap_or_default().to_owned();
    assert!(
        head.starts_with("GET /api/v1/sync/pull?cursor=7 "),
        "{head}"
    );
    assert!(
        request
            .to_lowercase()
            .contains("authorization: bearer token-abc"),
        "{request}"
    );
    // A GET with a body would be a mistake the server might act on.
    assert!(
        !request.to_lowercase().contains("content-length: "),
        "{request}"
    );
}

#[tokio::test]
async fn a_post_carries_json_and_the_token() {
    let (base, handle) = serve_once("200 OK", "{}");
    let transport = HttpTransport::new(&base).expect("transport");

    let body = br#"{"changes":[]}"#.to_vec();
    transport
        .send(HttpRequest::post(
            "/api/v1/sync/push",
            Some("token-xyz".to_owned()),
            body.clone(),
        ))
        .await
        .expect("send");

    let request = handle.join().expect("handler");
    let lower = request.to_lowercase();
    assert!(
        lower.contains("content-type: application/json"),
        "{request}"
    );
    assert!(
        lower.contains("authorization: bearer token-xyz"),
        "{request}"
    );
    // The body must arrive byte for byte: it is a signature-carrying commitment, and a
    // re-encoded JSON body would invalidate it.
    assert!(request.contains(r#"{"changes":[]}"#), "{request}");
}

#[tokio::test]
async fn a_refusal_is_returned_rather_than_turned_into_an_error() {
    let (base, handle) = serve_once("401 Unauthorized", r#"{"error":"invalid_credentials"}"#);
    let transport = HttpTransport::new(&base).expect("transport");

    let response = transport
        .send(HttpRequest::post(
            "/api/v1/accounts/login/start",
            None,
            b"{}".to_vec(),
        ))
        .await
        .expect("the call itself succeeded");

    // A non-2xx status is a successful round trip with an unsuccessful answer; the
    // caller decides what it means.
    assert!(!response.is_success());
    assert_eq!(response.status, 401);
    assert_eq!(response.body, br#"{"error":"invalid_credentials"}"#);

    let request = handle.join().expect("handler");
    assert!(
        !request.to_lowercase().contains("authorization"),
        "an anonymous call must not invent a token: {request}"
    );
}

#[tokio::test]
async fn an_unreachable_server_is_a_transport_error() {
    // Bind and drop, so the port is almost certainly closed.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local address");
    drop(listener);

    let transport = HttpTransport::new(&format!("http://{address}")).expect("transport");
    let error = transport
        .send(HttpRequest::get("/api/v1/meta", None))
        .await
        .expect_err("a refused connection must not look like success");

    assert!(
        matches!(error, ClientError::Transport(_)),
        "unexpected: {error}"
    );
}

#[tokio::test]
async fn a_trailing_slash_on_the_base_url_does_not_double_up() {
    let (base, handle) = serve_once("200 OK", "{}");
    let transport = HttpTransport::new(&format!("{base}/")).expect("transport");

    transport
        .send(HttpRequest::get("/api/v1/meta", None))
        .await
        .expect("send");

    let request = handle.join().expect("handler");
    let line = request.lines().next().unwrap_or_default().to_owned();
    // The transport joins base and path directly, so a stray slash would produce
    // `//api/v1/meta` — a different route to some servers, and a confusing 404 to debug.
    assert!(line.starts_with("GET /api/v1/meta "), "{line}");
}
