//! HTTP semantics → mux policy.
//!
//! This is the only place that knows both what an HTTP exchange looks like
//! and what the mux can be told. The mux itself has no notion of MIME
//! types, headers or secrets: it takes a scheduling [`Class`] at `open`
//! (and `set_class`) and a [`Compress`] stance on every `send`; this module
//! produces both.
//!
//! Heads (request and response) are always sent with [`Compress::Never`]:
//! they carry cookies, authorization tokens and CSRF secrets, which is
//! exactly what compression side channels (CRIME/BREACH) extract.

use weaver_mux::{Class, Compress};

use crate::http::{HttpHead, HttpResponseHead};

/// Declared body size above which a visitor stream is opened as bulk
/// outright, instead of waiting for the mux's own `bulk_threshold` to
/// demote it.
pub const BULK_THRESHOLD: u64 = 256 * 1024;

/// Scheduling class for a control stream. Control traffic is tiny, so the
/// mux's bulk demotion never triggers on it.
pub const CONTROL_CLASS: Class = Class::Interactive;

/// Compression stance for every message on a control stream.
pub const CONTROL_COMPRESS: Compress = Compress::Never;

/// Compression stance for request and response heads.
pub const HEAD_COMPRESS: Compress = Compress::Never;

/// Scheduling class for the stream carrying this request.
pub fn request_class(req: &HttpHead) -> Class {
    if is_realtime_request(req) {
        return Class::Realtime;
    }
    if content_length(req.header("content-length")).is_some_and(|len| len > BULK_THRESHOLD) {
        return Class::Bulk;
    }
    Class::Interactive
}

/// Scheduling class once the response head is known: a response that
/// turns out to be an event stream or a large body reclassifies the
/// stream. Returns `None` when the request-derived class stands.
pub fn response_class(req: &HttpHead, resp: &HttpResponseHead) -> Option<Class> {
    if is_realtime_request(req) {
        return None;
    }
    if is_event_stream(resp.header("content-type")) {
        return Some(Class::Realtime);
    }
    if content_length(resp.header("content-length")).is_some_and(|len| len > BULK_THRESHOLD) {
        return Some(Class::Bulk);
    }
    None
}

/// Compression stance for request body chunks.
pub fn request_body_compress(req: &HttpHead) -> Compress {
    if is_realtime_request(req)
        || req.header("content-encoding").is_some()
        || mime_is_precompressed(req.header("content-type"))
        || carries_secret(req)
    {
        Compress::Never
    } else {
        Compress::Auto
    }
}

/// Compression stance for response body chunks. `req` is the request the
/// response answers: an authenticated exchange whose body reflects
/// attacker-influenced input is the BREACH shape and is never compressed.
pub fn response_body_compress(req: &HttpHead, resp: &HttpResponseHead) -> Compress {
    if is_realtime_request(req)
        || is_event_stream(resp.header("content-type"))
        || resp.header("content-encoding").is_some()
        || mime_is_precompressed(resp.header("content-type"))
        || (carries_secret(req) && mime_is_reflectable(resp.header("content-type")))
    {
        Compress::Never
    } else {
        Compress::Auto
    }
}

fn is_realtime_request(req: &HttpHead) -> bool {
    req.header("upgrade").is_some() || is_event_stream(req.header("accept"))
}

fn is_event_stream(content_type: Option<&[u8]>) -> bool {
    mime_essence(content_type).is_some_and(|e| e == "text/event-stream")
}

/// Request-side auth material the response body might echo.
fn carries_secret(req: &HttpHead) -> bool {
    req.header("authorization").is_some() || req.header("cookie").is_some()
}

/// Bodies whose content is typically templated from request data.
fn mime_is_reflectable(content_type: Option<&[u8]>) -> bool {
    matches!(
        mime_essence(content_type).as_deref(),
        Some("text/html") | Some("application/json") | Some("application/xhtml+xml")
    )
}

/// Types whose bytes are already compressed (or encrypted) and would only
/// grow under zstd. `image/svg+xml` is text and stays compressible.
fn mime_is_precompressed(content_type: Option<&[u8]>) -> bool {
    let Some(essence) = mime_essence(content_type) else {
        return false;
    };
    if essence == "image/svg+xml" {
        return false;
    }
    if essence.starts_with("image/")
        || essence.starts_with("video/")
        || essence.starts_with("audio/")
        || essence.starts_with("font/woff")
    {
        return true;
    }
    matches!(
        essence.as_str(),
        "application/zip"
            | "application/gzip"
            | "application/zstd"
            | "application/x-xz"
            | "application/pdf"
            | "application/wasm"
            | "application/octet-stream"
    )
}

/// `type/subtype` of a MIME header value: lowercase, parameters stripped.
fn mime_essence(content_type: Option<&[u8]>) -> Option<String> {
    let ct = std::str::from_utf8(content_type?).ok()?;
    Some(
        ct.split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase(),
    )
}

fn content_length(value: Option<&[u8]>) -> Option<u64> {
    std::str::from_utf8(value?).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(headers: &[(&str, &str)]) -> HttpHead {
        HttpHead {
            method: "GET".into(),
            scheme: "https".into(),
            authority: "web.example".into(),
            path: "/".into(),
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect(),
        }
    }

    fn resp(headers: &[(&str, &str)]) -> HttpResponseHead {
        HttpResponseHead {
            status: 200,
            headers: headers
                .iter()
                .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                .collect(),
        }
    }

    #[test]
    fn request_classification() {
        assert_eq!(request_class(&req(&[])), Class::Interactive);
        assert_eq!(
            request_class(&req(&[("upgrade", "websocket")])),
            Class::Realtime
        );
        assert_eq!(
            request_class(&req(&[("accept", "text/event-stream")])),
            Class::Realtime
        );
        assert_eq!(
            request_class(&req(&[("content-length", "300000")])),
            Class::Bulk
        );
        assert_eq!(
            request_class(&req(&[("content-length", "262144")])),
            Class::Interactive
        );
        // Realtime wins over size.
        assert_eq!(
            request_class(&req(&[("upgrade", "x"), ("content-length", "300000")])),
            Class::Realtime
        );
    }

    #[test]
    fn response_reclassification() {
        let r = req(&[]);
        assert_eq!(response_class(&r, &resp(&[])), None);
        assert_eq!(
            response_class(
                &r,
                &resp(&[("content-type", "text/event-stream; charset=utf-8")])
            ),
            Some(Class::Realtime)
        );
        assert_eq!(
            response_class(&r, &resp(&[("content-length", "10000000")])),
            Some(Class::Bulk)
        );
        // An already-realtime request is not touched.
        assert_eq!(
            response_class(
                &req(&[("upgrade", "websocket")]),
                &resp(&[("content-length", "10000000")])
            ),
            None
        );
    }

    #[test]
    fn body_compression_rules() {
        let plain = req(&[]);
        assert_eq!(
            response_body_compress(&plain, &resp(&[("content-type", "text/html")])),
            Compress::Auto
        );
        for ct in [
            "image/png",
            "video/mp4",
            "audio/ogg",
            "font/woff2",
            "application/zip",
            "application/pdf; version=1.7",
            "application/octet-stream",
        ] {
            assert_eq!(
                response_body_compress(&plain, &resp(&[("content-type", ct)])),
                Compress::Never,
                "{ct}"
            );
        }
        assert_eq!(
            response_body_compress(&plain, &resp(&[("content-type", "image/svg+xml")])),
            Compress::Auto
        );
        assert_eq!(
            response_body_compress(
                &plain,
                &resp(&[("content-type", "text/html"), ("content-encoding", "gzip")])
            ),
            Compress::Never
        );
        assert_eq!(
            response_body_compress(&plain, &resp(&[("content-type", "text/event-stream")])),
            Compress::Never
        );
        assert_eq!(
            response_body_compress(&req(&[("upgrade", "websocket")]), &resp(&[])),
            Compress::Never
        );
    }

    #[test]
    fn breach_rule() {
        let authed = req(&[("cookie", "session=abc")]);
        assert_eq!(
            response_body_compress(&authed, &resp(&[("content-type", "text/html")])),
            Compress::Never,
            "authenticated HTML is never compressed"
        );
        assert_eq!(
            response_body_compress(&authed, &resp(&[("content-type", "application/json")])),
            Compress::Never
        );
        assert_eq!(
            response_body_compress(&authed, &resp(&[("content-type", "text/css")])),
            Compress::Auto,
            "static assets do not reflect request data"
        );
        assert_eq!(
            request_body_compress(&req(&[("authorization", "Bearer x")])),
            Compress::Never
        );
        assert_eq!(request_body_compress(&plain_post()), Compress::Auto);
    }

    fn plain_post() -> HttpHead {
        let mut r = req(&[("content-type", "application/json")]);
        r.method = "POST".into();
        r
    }
}
