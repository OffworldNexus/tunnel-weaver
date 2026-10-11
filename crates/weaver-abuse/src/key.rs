//! Request identity: the *fingerprint* of who is asking.
//!
//! A budget is never keyed on a single value. A caller is described by several
//! keys at once so a policy can charge them independently: a **peer-host** key
//! (one address) and a **peer-network** key (the surrounding subnet) run side
//! by side, so one abusive host exhausts its own budget first while a
//! spread-out set of hosts in the same subnet trips the laxer network backstop.
//!
//! Building a fingerprint is pure: the caller passes the already-resolved peer
//! address (never a forwarding header) and, when authenticated, the account id.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// One dimension a budget can be keyed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyKind {
    /// A single client address (IPv4 `/32`, IPv6 `/64`).
    PeerHost,
    /// The surrounding network (IPv4 `/24`, IPv6 `/56`), a laxer backstop.
    PeerNetwork,
    /// An authenticated account.
    Account,
    /// A server-issued flow context. Reserved for proof-of-work (WVR-136).
    Flow,
}

impl KeyKind {
    /// A short, stable token for logs and persisted rows.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PeerHost => "peer-host",
            Self::PeerNetwork => "peer-network",
            Self::Account => "account",
            Self::Flow => "flow",
        }
    }

    /// A stable numeric discriminator for persisted rows.
    pub fn code(self) -> i32 {
        match self {
            Self::PeerHost => 0,
            Self::PeerNetwork => 1,
            Self::Account => 2,
            Self::Flow => 3,
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

/// The prefix lengths used to derive the two peer layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerMasks {
    /// IPv4 host prefix (the restrictive layer).
    pub v4_host: u8,
    /// IPv4 network prefix (the lax backstop).
    pub v4_network: u8,
    /// IPv6 host prefix (the restrictive layer).
    pub v6_host: u8,
    /// IPv6 network prefix (the lax backstop).
    pub v6_network: u8,
}

impl Default for PeerMasks {
    /// IPv4 `/32` + `/24`, IPv6 `/64` + `/56`.
    fn default() -> Self {
        Self {
            v4_host: 32,
            v4_network: 24,
            v6_host: 64,
            v6_network: 56,
        }
    }
}

/// A set of keys describing who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    keys: Vec<Key>,
}

impl Fingerprint {
    /// The keys in canonical order: peer-host, peer-network, then account.
    pub fn keys(&self) -> &[Key] {
        &self.keys
    }

    /// The key for a given dimension, if present.
    pub fn get(&self, kind: KeyKind) -> Option<Key> {
        self.keys.iter().copied().find(|key| key.kind == kind)
    }
}

/// Build a fingerprint with the default peer masks.
pub fn fingerprint(peer: IpAddr, account: Option<u64>) -> Fingerprint {
    fingerprint_with(PeerMasks::default(), peer, account)
}

/// Build a fingerprint with explicit peer masks.
///
/// The peer always yields a host key and a network key; `account` adds a third
/// key when the caller is authenticated.
pub fn fingerprint_with(masks: PeerMasks, peer: IpAddr, account: Option<u64>) -> Fingerprint {
    let mut keys = Vec::with_capacity(3);
    keys.push(Key {
        kind: KeyKind::PeerHost,
        id: hash_masked(peer, masks.v4_host, masks.v6_host),
    });
    keys.push(Key {
        kind: KeyKind::PeerNetwork,
        id: hash_masked(peer, masks.v4_network, masks.v6_network),
    });
    if let Some(account) = account {
        keys.push(Key {
            kind: KeyKind::Account,
            id: account,
        });
    }
    Fingerprint { keys }
}

fn hash_masked(peer: IpAddr, v4_prefix: u8, v6_prefix: u8) -> u64 {
    match peer {
        IpAddr::V4(v4) => fnv1a(&Ipv4Addr::from(mask_v4(u32::from(v4), v4_prefix)).octets()),
        IpAddr::V6(v6) => fnv1a(&Ipv6Addr::from(mask_v6(u128::from(v6), v6_prefix)).octets()),
    }
}

fn mask_v4(addr: u32, prefix: u8) -> u32 {
    let prefix = prefix.min(32);
    if prefix == 0 {
        0
    } else {
        addr & (u32::MAX << (32 - prefix))
    }
}

fn mask_v6(addr: u128, prefix: u8) -> u128 {
    let prefix = prefix.min(128);
    if prefix == 0 {
        0
    } else {
        addr & (u128::MAX << (128 - prefix))
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
        let a = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None);
        let b = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), None);
        // Different hosts, same /24.
        assert_ne!(a.get(KeyKind::PeerHost), b.get(KeyKind::PeerHost));
        assert_eq!(a.get(KeyKind::PeerNetwork), b.get(KeyKind::PeerNetwork));

        let c = fingerprint(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)), None);
        assert_ne!(a.get(KeyKind::PeerNetwork), c.get(KeyKind::PeerNetwork));
    }

    #[test]
    fn ipv6_layers_split_64_from_56() {
        let a = fingerprint("2001:db8:0:1::1".parse().unwrap(), None);
        let same_64 = fingerprint("2001:db8:0:1::2".parse().unwrap(), None);
        // One /64 is a single host: the host mask zeroes the interface bits.
        assert_eq!(a.get(KeyKind::PeerHost), same_64.get(KeyKind::PeerHost));
        assert_eq!(
            a.get(KeyKind::PeerNetwork),
            same_64.get(KeyKind::PeerNetwork)
        );

        // A different /64 inside the same /56: host keys differ, network matches.
        let other_64 = fingerprint("2001:db8:0:2::1".parse().unwrap(), None);
        assert_ne!(a.get(KeyKind::PeerHost), other_64.get(KeyKind::PeerHost));
        assert_eq!(
            a.get(KeyKind::PeerNetwork),
            other_64.get(KeyKind::PeerNetwork)
        );

        // A different /56: the network key differs too.
        let other_56 = fingerprint("2001:db8:0:100::1".parse().unwrap(), None);
        assert_ne!(
            a.get(KeyKind::PeerNetwork),
            other_56.get(KeyKind::PeerNetwork)
        );
    }

    #[test]
    fn account_key_added_only_when_present() {
        let peer = "10.0.0.1".parse().unwrap();
        let authed = fingerprint(peer, Some(7));
        assert_eq!(authed.keys().len(), 3);
        assert_eq!(
            authed.get(KeyKind::Account),
            Some(Key {
                kind: KeyKind::Account,
                id: 7,
            })
        );
        assert_eq!(fingerprint(peer, None).get(KeyKind::Account), None);
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let peer = "192.0.2.5".parse().unwrap();
        assert_eq!(fingerprint(peer, Some(9)), fingerprint(peer, Some(9)));
    }
}
