//! zstd mechanics and the content-agnostic part of the compression policy.
//!
//! The mux does not know what a message *is*; the layer above says
//! [`Compress::Never`] or [`Compress::Auto`] per message. Under `Auto` the
//! mux still declines when compression cannot pay off: the class is
//! `Realtime` (latency beats bytes, and compression side channels bite
//! hardest on interactive traffic), the fragment is too small for a zstd
//! header, or the bytes already look random. A fragment whose compressed
//! form is not smaller goes out raw regardless.

use std::io;

use crate::sched::Class;

/// Per-message compression stance passed to [`crate::Connection::send`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Compress {
    /// The mux may compress if it judges it worthwhile (size floor,
    /// entropy probe, raw fallback when compression does not shrink the
    /// fragment). Never applied on `Realtime` streams.
    #[default]
    Auto,
    /// Never compress this message: secrets, already-encoded bodies,
    /// anything an attacker could probe via a compression side channel.
    Never,
}

/// Fragments smaller than this are not worth a zstd header.
pub const MIN_COMPRESS_LEN: usize = 1024;
/// How much of a fragment the entropy probe looks at.
pub const ENTROPY_SAMPLE: usize = 4096;
/// Bits/byte at or above which the data is considered incompressible.
pub const ENTROPY_CUTOFF: f64 = 7.5;

/// Should this fragment be compressed? `Never` is final; `Auto` is subject
/// to the checks above, cheapest first.
pub fn should_compress(stance: Compress, class: Class, fragment: &[u8]) -> bool {
    if stance == Compress::Never || class == Class::Realtime {
        return false;
    }
    if fragment.len() < MIN_COMPRESS_LEN {
        return false;
    }
    entropy_bits_per_byte(&fragment[..fragment.len().min(ENTROPY_SAMPLE)]) < ENTROPY_CUTOFF
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
        assert!(should_compress(
            Compress::Auto,
            Class::Interactive,
            &json(2048)
        ));
        assert!(should_compress(Compress::Auto, Class::Bulk, &json(8192)));
        assert!(!should_compress(Compress::Never, Class::Bulk, &json(8192)));
        assert!(!should_compress(
            Compress::Auto,
            Class::Realtime,
            &json(8192)
        ));
        assert!(
            !should_compress(Compress::Auto, Class::Interactive, &json(1023)),
            "1 KiB floor"
        );
        assert!(should_compress(
            Compress::Auto,
            Class::Interactive,
            &json(1024)
        ));
        assert!(
            !should_compress(Compress::Auto, Class::Interactive, &noise(4096)),
            "entropy"
        );
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
