//! The shared request context that passes collaborate over.
//!
//! One [`RequestContext`] travels through the pipeline and every pass reads
//! it. It is also where the caller-supplied `now_ms` and the request's
//! [`Fingerprint`] live, keeping the engine sans-IO.

use http::Method;

use crate::key::Fingerprint;
use crate::policy::ViewId;
use crate::surface::Surface;

/// Everything the pipeline knows about one request.
#[derive(Debug, Clone)]
pub struct RequestContext<'a> {
    /// Which surface the request arrived on.
    pub surface: Surface,
    /// The HTTP method.
    pub method: Method,
    /// The query-stripped path (what exemption checks use).
    pub path: &'a str,
    /// The full path and query (what the scanner rules decode).
    pub raw_path: &'a str,
    /// Who is asking.
    pub fingerprint: Fingerprint,
    /// The protected thing being requested.
    pub view: ViewId,
    /// The caller-supplied wall clock, in Unix milliseconds.
    pub now_ms: i64,
}
