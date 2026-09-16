//! HTTP request and response structures for proxied traffic.

use serde::{Deserialize, Serialize};

/// Head of a proxied HTTP request sent in mux stream OPEN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpHead {
    /// HTTP request method in uppercase (e.g. "GET", "POST").
    pub method: String,
    /// Request URI scheme ("http" or "https").
    pub scheme: String,
    /// Request authority / host header value.
    pub authority: String,
    /// Request target path and optional query string (e.g. "/hello?x=1").
    pub path: String,
    /// HTTP headers in order. Values are raw byte vectors per RFC 9110 §5.5.
    pub headers: Vec<(String, Vec<u8>)>,
    /// Scheduling and compression hints passed through to the multiplexer.
    pub hints: weaver_mux::Hints,
}

/// Head of a proxied HTTP response sent across the stream before the response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseHead {
    /// HTTP status code (e.g. 200, 302, 404, 502).
    pub status: u16,
    /// Response headers in order. Values are raw byte vectors.
    pub headers: Vec<(String, Vec<u8>)>,
}
