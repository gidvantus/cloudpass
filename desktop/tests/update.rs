//! The update check, against a real socket.
//!
//! The rules about which version to announce are unit-tested where they live. What is
//! covered here is the join between them and the wire: a real listener answers
//! `/api/v1/meta`, the real transport reads it, and the answer decides whether the
//! application would have said anything.
//!
//! It is the shape a server *actually* produces that matters. A desktop client has to
//! survive one that has never heard of the `version` field, one whose installer name
//! carries no version, and one that answers with something that is not the API at all —
//! and in every one of those cases the correct behaviour is the same silence as "you are
//! up to date", not an error about an errand the user did not ask for.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::Duration;

use cloudpass_client::sync::{HttpRequest, Transport};
use cloudpass_desktop_lib::transport::HttpTransport;
use cloudpass_desktop_lib::update;
use semver::Version;

/// The version this test pretends the application was installed as.
const CURRENT: &str = "0.1.0";

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
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
    }

    String::from_utf8_lossy(&data).into_owned()
}

/// The errand the application runs on a timer: ask for `/api/v1/meta`, then decide.
///
/// Written the way the background task is written, so the test fails if any of the three
/// steps — the request, the reading of the answer, the comparison — stops agreeing with
/// the others.
async fn announced(base: &str) -> Option<String> {
    let transport =
        HttpTransport::with_timeout(base, Duration::from_secs(5)).expect("build the transport");

    let response = transport
        .send(HttpRequest::get("/api/v1/meta", None))
        .await
        .expect("the listener answers");

    update::should_notify(
        &Version::parse(CURRENT).expect("a version this test wrote"),
        update::offered_version(&response.body).as_deref(),
        None,
    )
    .map(|version| version.to_string())
}

#[tokio::test]
async fn a_newer_version_published_by_the_server_is_announced() {
    let (base, handle) = serve_once(
        "200 OK",
        r#"{
            "protocol_version": 1,
            "registration_open": true,
            "server_time": 1767225600,
            "kdf_default": {"m_kib": 65536, "t": 3, "p": 1, "salt": ""},
            "desktop": {
                "file": "CloudPass_0.2.0_x64-setup.exe",
                "url": "/download/CloudPass_0.2.0_x64-setup.exe",
                "size": 41943040,
                "sha256": "0f3d2c1b0a99887766554433221100ffeeddccbbaa99887766554433221100ff",
                "version": "0.2.0"
            }
        }"#,
    );

    assert_eq!(announced(&base).await.as_deref(), Some("0.2.0"));

    let request = handle.join().expect("the handler finished");
    let line = request.lines().next().unwrap_or_default().to_owned();
    assert!(line.starts_with("GET /api/v1/meta "), "{line}");
    // The check is anonymous: it asks the same question the portal asks, and a token
    // would be a credential sent somewhere that never needed one.
    assert!(
        !request.to_lowercase().contains("authorization"),
        "{request}"
    );
}

/// The version installed is the version installed; announcing it would send a person to
/// download the program they are already running.
#[tokio::test]
async fn the_version_already_installed_is_not_announced() {
    let (base, handle) = serve_once(
        "200 OK",
        r#"{"desktop": {"file": "CloudPass_0.1.0_x64-setup.exe", "url": "/download/x.exe",
            "size": 1, "sha256": "ab", "version": "0.1.0"}}"#,
    );

    assert_eq!(announced(&base).await, None);
    handle.join().expect("the handler finished");
}

/// A server built before the field existed answers without it, and that must not break a
/// client that was hoping for a comparison.
#[tokio::test]
async fn a_server_that_does_not_publish_a_version_is_silent() {
    let (base, handle) = serve_once(
        "200 OK",
        r#"{
            "protocol_version": 1,
            "desktop": {
                "file": "CloudPass_9.9.9_x64-setup.exe",
                "url": "/download/CloudPass_9.9.9_x64-setup.exe",
                "size": 1,
                "sha256": "ab"
            }
        }"#,
    );

    assert_eq!(announced(&base).await, None);
    handle.join().expect("the handler finished");
}

/// An installer renamed by hand, or produced by a build with no version to stamp: still
/// downloadable, and still nothing to compare against.
#[tokio::test]
async fn an_installer_without_a_version_in_its_name_is_silent() {
    let (base, handle) = serve_once(
        "200 OK",
        r#"{"desktop": {"file": "CloudPass_x64-setup.exe", "url": "/download/CloudPass_x64-setup.exe",
            "size": 1, "sha256": "ab", "version": null}}"#,
    );

    assert_eq!(announced(&base).await, None);
    handle.join().expect("the handler finished");
}

#[tokio::test]
async fn a_server_with_nothing_to_offer_is_silent() {
    let (base, handle) = serve_once("200 OK", r#"{"protocol_version": 1, "desktop": null}"#);

    assert_eq!(announced(&base).await, None);
    handle.join().expect("the handler finished");
}

/// A proxy, a captive portal or a much older server that answers with a page rather than
/// with JSON is not a reason to interrupt somebody about an update.
#[tokio::test]
async fn an_answer_that_is_not_the_api_is_silent() {
    let (base, handle) = serve_once("200 OK", "<html>sign in to the wifi</html>");

    assert_eq!(announced(&base).await, None);
    handle.join().expect("the handler finished");
}

/// The failure the background task meets most often on a machine with no server: the
/// connection is refused. It has to be an error here and silence up the stack, which is
/// what the caller does with it.
#[tokio::test]
async fn a_server_that_is_not_there_is_an_error_the_caller_turns_into_silence() {
    // Bind and drop, so the port is almost certainly closed.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("local address");
    drop(listener);

    let transport =
        HttpTransport::with_timeout(&format!("http://{address}"), Duration::from_secs(5))
            .expect("build the transport");

    let error = transport
        .send(HttpRequest::get("/api/v1/meta", None))
        .await
        .expect_err("a refused connection must not look like an answer");

    assert!(
        matches!(error, cloudpass_client::ClientError::Transport(_)),
        "unexpected: {error}"
    );
}
