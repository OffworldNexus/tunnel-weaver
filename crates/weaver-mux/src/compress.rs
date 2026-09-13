//! Per-stream zstd compression and the policy deciding when to skip it.
//!
//! Compression is decided once per stream by the sender, on its first DATA
//! frame, and signalled by a flag bit on every DATA payload. The receiver
//! honours the flag and nothing else. All checks run cheapest-first; any
//! hit leaves the stream uncompressed for its whole life.

use std::io;

use crate::sched::{Class, mime_essence};
use crate::wire::Hints;

/// Frames smaller than this are not worth a zstd header.
pub const MIN_COMPRESS_LEN: usize = 1024;
/// How much of the first frame the entropy probe looks at.
pub const ENTROPY_SAMPLE: usize = 4096;
/// Bits/byte at or above which the data is considered incompressible.
pub const ENTROPY_CUTOFF: f64 = 7.5;

/// Should DATA on this stream be compressed? Evaluated exactly once, on
/// the first chunk the application writes.
pub fn should_compress(class: Class, hints: &Hints, first_chunk: &[u8]) -> bool {
    // (2) Realtime streams: latency beats bytes, and CRIME/BREACH-style
    // side channels bite hardest on interactive traffic.
    if class == Class::Realtime {
        return false;
    }
    // (3) Already encoded, or a MIME type that is compressed by
    // construction.
    if hints.content_encoding.is_some() {
        return false;
    }
    if let Some(ct) = hints.content_type.as_deref()
        && mime_is_precompressed(&mime_essence(ct))
    {
        return false;
    }
    // (4) Too small to pay for the container.
    if first_chunk.len() < MIN_COMPRESS_LEN {
        return false;
    }
    // (5) Looks random already.
    entropy_bits_per_byte(&first_chunk[..first_chunk.len().min(ENTROPY_SAMPLE)]) < ENTROPY_CUTOFF
}

/// Types whose bytes are already compressed (or encrypted) and would only
/// grow under zstd. `image/svg+xml` is text and stays compressible.
fn mime_is_precompressed(essence: &str) -> bool {
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
        essence,
        "application/zip"
            | "application/gzip"
            | "application/zstd"
            | "application/x-xz"
            | "application/pdf"
            | "application/wasm"
            | "application/octet-stream"
    )
}

/// Shannon entropy over a 256-bucket byte histogram, in bits per byte.
pub fn entropy_bits_per_byte(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut hist = [0u32; 256];
    for &b in sample {
        hist[usize::from(b)] += 1;
    }
    let n = sample.len() as f64;
    hist.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

/// Reusable zstd contexts, one pair per connection.
pub struct ZstdCtx {
    compressor: zstd::bulk::Compressor<'static>,
    decompressor: zstd::bulk::Decompressor<'static>,
}

impl std::fmt::Debug for ZstdCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZstdCtx")
    }
}

impl ZstdCtx {
    /// Create contexts at the given level. zstd context creation only
    /// fails on allocation failure, which we treat as fatal.
    pub fn new(level: i32) -> Self {
        Self {
            compressor: zstd::bulk::Compressor::new(level).expect("zstd compressor"),
            decompressor: zstd::bulk::Decompressor::new().expect("zstd decompressor"),
        }
    }

    /// Compress `data` into a fresh buffer.
    pub fn compress(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        self.compressor.compress(data)
    }

    /// Decompress with an output cap; exceeding it is treated as an error
    /// so a hostile peer cannot inflate a tiny frame into gigabytes.
    pub fn decompress(&mut self, data: &[u8], cap: usize) -> io::Result<Vec<u8>> {
        self.decompressor.decompress(data, cap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hints(ct: Option<&str>, enc: Option<&str>) -> Hints {
        Hints {
            content_type: ct.map(str::to_owned),
            content_length: None,
            upgrade: false,
            content_encoding: enc.map(str::to_owned),
        }
    }

    fn json(n: usize) -> Vec<u8> {
        let mut v = Vec::new();
        while v.len() < n {
            v.extend_from_slice(br#"{"id":123,"name":"weaver","tags":["a","b"]},"#);
        }
        v.truncate(n);
        v
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x1234_5678_9abc_def0u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn entropy_probe() {
        assert!(entropy_bits_per_byte(&noise(4096)) >= ENTROPY_CUTOFF);
        assert!(entropy_bits_per_byte(&json(4096)) < ENTROPY_CUTOFF);
        assert_eq!(entropy_bits_per_byte(&[7; 100]), 0.0);
    }

    #[test]
    fn policy() {
        let h = hints(Some("application/json"), None);
        assert!(should_compress(Class::Small, &h, &json(2048)));
        assert!(!should_compress(Class::Realtime, &h, &json(2048)));
        assert!(!should_compress(
            Class::Small,
            &hints(Some("application/json"), Some("gzip")),
            &json(2048)
        ));
        assert!(!should_compress(
            Class::Small,
            &hints(Some("image/png"), None),
            &json(2048)
        ));
        assert!(should_compress(
            Class::Small,
            &hints(Some("image/svg+xml"), None),
            &json(2048)
        ));
        assert!(!should_compress(
            Class::Small,
            &hints(Some("font/woff2"), None),
            &json(2048)
        ));
        assert!(!should_compress(
            Class::Bulk,
            &hints(Some("Application/PDF; x=y"), None),
            &json(2048)
        ));
        assert!(
            !should_compress(Class::Small, &h, &json(1023)),
            "1 KiB floor"
        );
        assert!(should_compress(Class::Small, &h, &json(1024)));
        assert!(!should_compress(Class::Small, &h, &noise(4096)), "entropy");
        assert!(should_compress(
            Class::Bulk,
            &hints(None, None),
            &json(8192)
        ));
    }

    #[test]
    fn round_trip_and_cap() {
        let mut z = ZstdCtx::new(3);
        let data = json(10_000);
        let c = z.compress(&data).unwrap();
        assert!(c.len() < data.len());
        assert_eq!(z.decompress(&c, 10_000).unwrap(), data);
        assert!(z.decompress(&c, 9_999).is_err(), "cap enforced");
        assert!(z.decompress(b"not zstd", 100).is_err());
    }
}
