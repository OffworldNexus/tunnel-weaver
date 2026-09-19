//! HTTP request and response heads for proxied traffic.
//!
//! Both are plain schema: how they travel (as the first message on a mux
//! stream) and how they are scheduled and compressed is decided in
//! [`crate::policy`].

use serde::{Deserialize, Serialize};

/// Head of a proxied HTTP request: the first message on a visitor stream.
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
    /// HTTP headers in order, names lowercased. Values are raw byte
    /// vectors per RFC 9110 §5.5.
    pub headers: Vec<(String, Vec<u8>)>,
}

/// Head of a proxied HTTP response: the first message the client sends
/// back on a visitor stream, before the body chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponseHead {
    /// HTTP status code (e.g. 200, 302, 404, 502).
    pub status: u16,
    /// Response headers in order, names lowercased. Values are raw byte
    /// vectors.
    pub headers: Vec<(String, Vec<u8>)>,
}

impl HttpHead {
    /// First value of header `name` (already lowercase), if present.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_of(&self.headers, name)
    }
}

impl HttpResponseHead {
    /// First value of header `name` (already lowercase), if present.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_of(&self.headers, name)
    }
}

fn header_of<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}
