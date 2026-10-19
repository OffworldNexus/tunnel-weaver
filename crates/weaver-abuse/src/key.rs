//! Request identity: the *fingerprint* of who is asking.
//!
//! A budget is never keyed on a single value. A caller is described by several
//! keys at once so a policy can charge them independently: a **peer-host** key
//! (one address) and a **peer-network** key (the surrounding subnet) run side
//! by side, so one abusive host exhausts its own budget first while a
//! spread-out set of hosts in the same subnet trips the laxer network backstop.
//!
//! Building a fingerprint is pure: the caller passes the already-resolved peer
//! address (never a forwarding header).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One dimension a budget can be keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// A single client address (IPv4 `/32`, IPv6 `/64`).
    PeerHost,
    /// The surrounding network (IPv4 `/24`, IPv6 `/56`), a laxer backstop.
    PeerNetwork,
}

impl KeyKind {
    /// A short, stable token for logs and persisted rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerHost => "peer-host",
            Self::PeerNetwork => "peer-network",
        }
    }

    /// A stable numeric discriminator for persisted rows.
    pub fn code(self) -> i32 {
        match self {
            Self::PeerHost => 0,
            Self::PeerNetwork => 1,
        }
    }
}

/// An opaque, stable budget key.
///
/// `id` is a 64-bit hash of the normalized value for determinism — not secrecy.
/// The engine never carries the raw address, so persisted and logged state is
/// uniform and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    /// The dimension this key belongs to.
    pub kind: KeyKind,
    /// The normalized value within that dimension.
    pub id: u64,
}

/// A set of keys describing who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    keys: Vec<Key>,
}

impl Fingerprint {
    /// The key for a given dimension, if present.
    pub fn get(&self, kind: KeyKind) -> Option<Key> {
        self.keys.iter().copied().find(|key| key.kind == kind)
    }
}

/// Build a fingerprint: the peer yields a host key (IPv4 `/32`, IPv6 `/64`)
/// and a network key (IPv4 `/24`, IPv6 `/56`).
pub fn fingerprint(peer: IpAddr) -> Fingerprint {
    let keys = vec![
        Key {
            kind: KeyKind::PeerHost,
            id: hash_masked(peer, 32, 64),
        },
        Key {
            kind: KeyKind::PeerNetwork,
            id: hash_masked(peer, 24, 56),
        },
    ];
    Fingerprint { keys }
}

/// FNV-1a of the address with all but its first `v4_prefix`/`v6_prefix` bits
/// cleared (both non-zero).
fn hash_masked(peer: IpAddr, v4_prefix: u32, v6_prefix: u32) -> u64 {
    match peer {
        IpAddr::V4(v4) => {
            let masked = u32::from(v4) & (u32::MAX << (32 - v4_prefix));
            fnv1a(&Ipv4Addr::from(masked).octets())
        }
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << (128 - v6_prefix));
            fnv1a(&Ipv6Addr::from(masked).octets())
        }
    }
}

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = FNV_OFFSET;
    for &byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_layers_split_host_from_network() {
        let a = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let b = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        // Different hosts, same /24.
        assert_ne!(a.get(KeyKind::PeerHost), b.get(KeyKind::PeerHost));
        assert_eq!(a.get(KeyKind::PeerNetwork), b.get(KeyKind::PeerNetwork));

        let c = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)));
        assert_ne!(a.get(KeyKind::PeerNetwork), c.get(KeyKind::PeerNetwork));
    }

    #[test]
    fn ipv6_layers_split_64_from_56() {
        let a = fingerprint("2001:db8:0:1::1".parse().unwrap());
        let same_64 = fingerprint("2001:db8:0:1::2".parse().unwrap());
        // One /64 is a single host: the host mask zeroes the interface bits.
        assert_eq!(a.get(KeyKind::PeerHost), same_64.get(KeyKind::PeerHost));
        assert_eq!(
            a.get(KeyKind::PeerNetwork),
            same_64.get(KeyKind::PeerNetwork)
        );

        // A different /64 inside the same /56: host keys differ, network matches.
        let other_64 = fingerprint("2001:db8:0:2::1".parse().unwrap());
        assert_ne!(a.get(KeyKind::PeerHost), other_64.get(KeyKind::PeerHost));
        assert_eq!(
            a.get(KeyKind::PeerNetwork),
            other_64.get(KeyKind::PeerNetwork)
        );

        // A different /56: the network key differs too.
        let other_56 = fingerprint("2001:db8:0:100::1".parse().unwrap());
        assert_ne!(
            a.get(KeyKind::PeerNetwork),
            other_56.get(KeyKind::PeerNetwork)
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let peer = "192.0.2.5".parse().unwrap();
        assert_eq!(fingerprint(peer,), fingerprint(peer,));
    }
}
