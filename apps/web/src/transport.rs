//! The browser's two externals: `fetch` and the clipboard.
//!
//! # Why the globals are reached through `Reflect`
//!
//! `web_sys::window()` resolves to `Some` only in an actual browser: it is a typed
//! `instanceof` check against the `Window` interface. That makes the transport unusable
//! anywhere else, including the Node-based smoke test that drives this exact artifact.
//! `js_sys::global()` is simply `globalThis` on every JavaScript host, and the two things
//! this module needs — `fetch` and `navigator.clipboard` — are ordinary properties of it.
//!
//! The upshot is that a missing feature is a typed error rather than a `TypeError` thrown
//! out of a wasm frame, which is the difference between "the clipboard needs https" and a
//! page that appears to hang.

use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

use cloudpass_client::sync::{HttpRequest, HttpResponse, Transport};
use cloudpass_client::ClientError;

/// Renders a JavaScript exception as something a human can read.
///
/// `JsValue` has no useful `Display`, and its `Debug` is a pointer. The message property
/// is where the actual complaint lives, so it is worth the two lines.
pub fn describe(value: &JsValue) -> String {
    if let Some(error) = value.dyn_ref::<js_sys::Error>() {
        return String::from(error.message());
    }
    if let Some(text) = value.as_string() {
        return text;
    }
    format!("{value:?}")
}

pub fn transport_error(value: &JsValue) -> ClientError {
    ClientError::Transport(describe(value))
}

fn property(target: &JsValue, name: &str) -> Result<JsValue, ClientError> {
    js_sys::Reflect::get(target, &JsValue::from_str(name)).map_err(|e| transport_error(&e))
}

/// Looks a global function up, and says which one is missing when it is not there.
fn global_function(name: &str) -> Result<js_sys::Function, ClientError> {
    let value = property(&js_sys::global(), name)?;
    value
        .dyn_into::<js_sys::Function>()
        .map_err(|_| ClientError::Transport(format!("this environment has no {name}")))
}

fn as_promise(value: JsValue) -> Result<js_sys::Promise, ClientError> {
    value
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| ClientError::Transport("вызов не вернул обещание".to_owned()))
}

/// Sends requests with the browser's own `fetch`.
///
/// Same origin as the page: the server that serves this file is the server it talks to,
/// so there is no CORS preflight and no third-party origin in the trust path.
pub struct FetchTransport {
    base_url: String,
}

impl FetchTransport {
    #[must_use]
    pub fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
        }
    }
}

impl Transport for FetchTransport {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, ClientError> {
        let url = format!("{}{}", self.base_url, request.path);

        let init = web_sys::RequestInit::new();
        init.set_method(request.method.as_str());

        let headers = web_sys::Headers::new().map_err(|e| transport_error(&e))?;
        if !request.body.is_empty() {
            headers
                .set("content-type", "application/json")
                .map_err(|e| transport_error(&e))?;
            // A `Uint8Array`, not a string: the bodies are base64 inside JSON already, and
            // re-encoding them as text would mean guessing at an encoding.
            let bytes = js_sys::Uint8Array::from(request.body.as_slice());
            init.set_body(&bytes);
        }
        if let Some(token) = &request.token {
            headers
                .set("authorization", &format!("Bearer {token}"))
                .map_err(|e| transport_error(&e))?;
        }
        init.set_headers(&headers);

        let built = web_sys::Request::new_with_str_and_init(&url, &init)
            .map_err(|e| transport_error(&e))?;

        let fetch = global_function("fetch")?;
        let promise = fetch
            .call1(&JsValue::UNDEFINED, &built)
            .map_err(|e| transport_error(&e))?;

        let value = JsFuture::from(as_promise(promise)?)
            .await
            .map_err(|e| transport_error(&e))?;
        let response: web_sys::Response = value
            .dyn_into()
            .map_err(|_| ClientError::Transport("fetch вернул не ответ".to_owned()))?;

        let status = response.status();
        let buffer = JsFuture::from(response.array_buffer().map_err(|e| transport_error(&e))?)
            .await
            .map_err(|e| transport_error(&e))?;

        let array = js_sys::Uint8Array::new(&buffer);
        let mut body = vec![0u8; array.length() as usize];
        array.copy_to(&mut body);

        Ok(HttpResponse {
            status: status as u16,
            body,
        })
    }
}

/// Writes to the clipboard, from here, so the secret never enters the page.
///
/// The Clipboard API only exists in a secure context — `https`, or `localhost`. Everywhere
/// else `navigator.clipboard` is simply absent, which is reported as itself rather than as
/// a mysterious failure: a "copied" button that copied nothing is worse than one that
/// says why it could not.
pub async fn write_clipboard(text: &str) -> Result<(), ClientError> {
    let navigator = property(&js_sys::global(), "navigator")?;
    let clipboard = property(&navigator, "clipboard")?;
    if clipboard.is_undefined() || clipboard.is_null() {
        return Err(ClientError::Transport(
            "браузер не даёт доступ к буферу обмена: для этого нужен https или localhost"
                .to_owned(),
        ));
    }

    let write_text = property(&clipboard, "writeText")?;
    let write_text = write_text.dyn_into::<js_sys::Function>().map_err(|_| {
        ClientError::Transport("в этом браузере нет записи в буфер обмена".to_owned())
    })?;

    let promise = write_text
        .call1(&clipboard, &JsValue::from_str(text))
        .map_err(|e| transport_error(&e))?;

    JsFuture::from(as_promise(promise)?).await.map_err(|e| {
        ClientError::Transport(format!(
            "браузер отказал в доступе к буферу обмена ({})",
            describe(&e)
        ))
    })?;

    Ok(())
}
