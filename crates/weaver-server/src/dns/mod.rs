//! Authoritative DNS responder for the relay's root zone.
//!
//! Answers A/AAAA/NS/CAA/SOA and DNS-01 TXT queries for `<root>` and any single
//! label directly beneath it. It is generative — no zone files, no second
//! binary — reading relay addresses from config and TXT values from the live
//! challenge registry in the `Store`. The zone's NS and SOA MNAME point at the
//! relay's own admin domain, which lives outside the delegated tunnel zone.
//!
//! Design points (OFF-190):
//! - **No recursion, ever.** `RA=0`; out-of-zone names get `REFUSED` because we
//!   are not authoritative for the parent (NXDOMAIN would be a lie).
//! - **Every in-zone name resolves identically** to the relay's addresses. That
//!   is the anti-enumeration mechanism: there are no distinct records to walk.
//! - **TXT is answered only for live challenge names**, `NODATA` otherwise, so
//!   the multi-value ACME rrset is the only thing an attacker can probe.
//! - Everything else (AXFR/IXFR, UPDATE, NOTIFY, CH/version.bind, ANY) is
//!   refused or minimised per RFC 8482.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use hickory_proto::op::{Edns, Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CAA, HINFO, NS, SOA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::net::{TcpListener, UdpSocket};
use tokio_util::sync::CancellationToken;
use tracing::{debug, trace, warn};

use crate::config::Config;
use crate::store::Store;

/// TTL for static records (A/AAAA/NS/CAA/SOA), in seconds.
pub const STATIC_TTL: u32 = 3600;

/// TTL for ACME challenge TXT records, in seconds. Short so a resolver that
/// asked before publication does not cache the old answer through validation.
pub const CHALLENGE_TTL: u32 = 30;

/// TTL for CAA records, in seconds.
///
/// Deliberately shorter than the other static records: CAs cache the CAA tree
/// for its TTL, so a mistaken or stale CAA (e.g. one that forbids wildcards)
/// blocks issuance for that whole window. 60s keeps mistakes cheap to correct.
pub const CAA_TTL: u32 = 60;

/// Negative-cache TTL, mirrored into the SOA MINIMUM. Kept short because a
/// resolver that cached NODATA for `_acme-challenge.<root>` would break DCV.
pub const NEGATIVE_TTL: u32 = 30;

/// The prefix of the DNS-01 challenge name, `_acme-challenge.<root>`.
// The responder matches the full `_acme-challenge.<root>` name via the store,
// so the prefix is documentation only for now.
const _ACME_PREFIX: &str = "_acme-challenge";

/// Generative authoritative responder bound to one root zone.
pub struct DnsResponder {
    root_domain: String,
    root_name: Name,
    /// The name server target for the zone's NS and SOA MNAME records: the
    /// relay's own stable (admin) hostname, which lives outside the delegation.
    admin_name: Name,
    relay_ips: Vec<IpAddr>,
    soa: SOA,
    /// CA issuer domains for the `issue`/`issuewild` CAA records. Empty means
    /// we cannot name the CA, so no CAA is served (permissive).
    caa_issuers: Vec<String>,
    store: Arc<Store>,
}

impl std::fmt::Debug for DnsResponder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResponder")
            .field("root_domain", &self.root_domain)
            .field("admin_name", &self.admin_name)
            .field("relay_ips", &self.relay_ips)
            .finish()
    }
}

impl DnsResponder {
    /// Builds a responder for the configured root zone.
    pub fn new(config: &Config, store: Arc<Store>) -> Self {
        let root_domain = config.root_domain.to_ascii_lowercase();
        let root_name = Name::from_str(&format!("{root_domain}.")).expect("root domain is a Name");
        // The zone is delegated to the relay, whose own stable hostname is the
        // admin domain; NS and SOA advertise that name, never the apex (an
        // apex self-reference is not resolvable once delegated).
        let admin_domain = config.admin_domain.to_ascii_lowercase();
        let admin_name =
            Name::from_str(&format!("{admin_domain}.")).expect("admin domain is a Name");
        let soa = SOA::new(
            admin_name.clone(),
            admin_name.clone(),
            1,
            7200,
            3600,
            1_209_600,
            NEGATIVE_TTL,
        );
        Self {
            root_domain,
            root_name,
            admin_name,
            relay_ips: config.relay_ips.clone(),
            soa,
            caa_issuers: crate::cert::providers::caa_identifiers(
                &config.acme_provider,
                &config.acme_fallback_providers,
            ),
            store,
        }
    }

    /// True if `name` (lowercased, no trailing dot) is the apex or one label
    /// beneath it. The wildcard matches exactly one label, so deeper names are
    /// out of zone.
    fn in_zone(&self, name: &str) -> bool {
        if name == self.root_domain {
            return true;
        }
        match name.strip_suffix(&format!(".{}", self.root_domain)) {
            Some(label) => !label.is_empty() && !label.contains('.'),
            None => false,
        }
    }

    fn a_records(&self, owner: &Name) -> Vec<Record> {
        self.relay_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V4(v4) => Some(Record::from_rdata(
                    owner.clone(),
                    STATIC_TTL,
                    RData::A(A(*v4)),
                )),
                IpAddr::V6(_) => None,
            })
            .collect()
    }

    fn aaaa_records(&self, owner: &Name) -> Vec<Record> {
        self.relay_ips
            .iter()
            .filter_map(|ip| match ip {
                IpAddr::V6(v6) => Some(Record::from_rdata(
                    owner.clone(),
                    STATIC_TTL,
                    RData::AAAA(AAAA(*v6)),
                )),
                IpAddr::V4(_) => None,
            })
            .collect()
    }

    fn soa_record(&self) -> Record {
        Record::from_rdata(
            self.root_name.clone(),
            NEGATIVE_TTL,
            RData::SOA(self.soa.clone()),
        )
    }

    /// Builds the reply for a decoded query, or `None` to drop it silently.
    pub async fn answer(&self, req: &Message) -> Option<Message> {
        let mut resp = Message::new(0, MessageType::Response, req.op_code);
        resp.metadata = Metadata::response_from_request(&req.metadata);
        resp.metadata.authoritative = true;
        resp.metadata.recursion_available = false;
        // RFC 1035 §4.1.1: the response must echo the question section. Without
        // it resolvers treat the reply as malformed and fall back to SERVFAIL.
        resp.queries = req.queries.clone();

        // EDNS: minimal but present. Echo an OPT with our small buffer; fail
        // BADVERS for an unknown version (RFC 6891). Options are ignored.
        if let Some(req_edns) = &req.edns {
            let mut out = Edns::new();
            out.set_version(0);
            out.set_max_payload(512);
            out.flags_mut().dnssec_ok = false;
            if req_edns.version() != 0 {
                resp.metadata.response_code = ResponseCode::BADVERS;
                resp.set_edns(out);
                return Some(resp);
            }
            resp.set_edns(out);
        }

        // Query shape: only standard queries. UPDATE/NOTIFY are refused (we are
        // read-only and have no secondaries); anything else is NOTIMP.
        match req.op_code {
            OpCode::Query => {}
            OpCode::Update | OpCode::Notify => {
                resp.metadata.response_code = ResponseCode::Refused;
                return Some(resp);
            }
            _ => {
                resp.metadata.response_code = ResponseCode::NotImp;
                return Some(resp);
            }
        }

        if req.queries.len() != 1 {
            resp.metadata.response_code = ResponseCode::FormErr;
            return Some(resp);
        }

        let query = &req.queries[0];
        let qname = normalize(query.name().to_utf8());
        let qtype = query.query_type();
        let qclass = query.query_class();

        // Fingerprinting / unsupported classes are refused.
        if qclass != hickory_proto::rr::DNSClass::IN {
            resp.metadata.response_code = ResponseCode::Refused;
            return Some(resp);
        }

        // Enumeration and zone transfer are refused.
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            resp.metadata.response_code = ResponseCode::Refused;
            return Some(resp);
        }

        // Out of zone: we are authoritative only for `<root>` and one label.
        if !self.in_zone(&qname) {
            resp.metadata.response_code = ResponseCode::Refused;
            return Some(resp);
        }

        // ANY is minimised per RFC 8482 with a single HINFO.
        if qtype == RecordType::ANY {
            resp.add_answer(Record::from_rdata(
                query.name().clone(),
                STATIC_TTL,
                RData::HINFO(HINFO::new("RFC8482".to_string(), String::new())),
            ));
            return Some(resp);
        }

        let owner = query.name().clone();

        match qtype {
            RecordType::A => {
                let records = self.a_records(&owner);
                if records.is_empty() {
                    resp.add_authority(self.soa_record());
                } else {
                    resp.add_answers(records);
                }
            }
            RecordType::AAAA => {
                let records = self.aaaa_records(&owner);
                if records.is_empty() {
                    resp.add_authority(self.soa_record());
                } else {
                    resp.add_answers(records);
                }
            }
            RecordType::TXT => {
                let values = self.store.get_challenges(&qname).await.unwrap_or_default();
                if values.is_empty() {
                    // Only live challenge names have TXT. NODATA (not NXDOMAIN)
                    // keeps the wildcard's non-enumerability intact.
                    resp.add_authority(self.soa_record());
                } else {
                    for value in values {
                        resp.add_answer(Record::from_rdata(
                            owner.clone(),
                            CHALLENGE_TTL,
                            RData::TXT(TXT::new(vec![value])),
                        ));
                    }
                }
            }
            RecordType::SOA if qname == self.root_domain => {
                resp.add_answer(self.soa_record());
            }
            RecordType::NS if qname == self.root_domain => {
                resp.add_answer(Record::from_rdata(
                    self.root_name.clone(),
                    STATIC_TTL,
                    RData::NS(NS(self.admin_name.clone())),
                ));
            }
            RecordType::CAA if qname == self.root_domain => {
                // Authorise the configured CA(s) for both ordinary and wildcard
                // issuance. An empty `issuewild` would *forbid* wildcards, so if
                // the CA is unknown we serve no CAA at all (NODATA).
                if self.caa_issuers.is_empty() {
                    resp.add_authority(self.soa_record());
                } else {
                    for issuer in &self.caa_issuers {
                        // Parse *without* a trailing dot: hickory's `CAA`
                        // encoder appends the name via `to_ascii()`, and a
                        // trailing dot ("letsencrypt.org.") does not match the
                        // CA's issuer identifier, so issuance is refused.
                        let Ok(name) = Name::from_str(issuer) else {
                            continue;
                        };
                        resp.add_answer(Record::from_rdata(
                            self.root_name.clone(),
                            CAA_TTL,
                            RData::CAA(CAA::new_issue(false, Some(name.clone()), Vec::new())),
                        ));
                        resp.add_answer(Record::from_rdata(
                            self.root_name.clone(),
                            CAA_TTL,
                            RData::CAA(CAA::new_issuewild(false, Some(name), Vec::new())),
                        ));
                    }
                }
            }
            _ => {
                // NODATA: NOERROR, no answers, SOA for negative caching.
                resp.add_authority(self.soa_record());
            }
        }

        Some(resp)
    }
}

/// Lowercases and strips the trailing dot from a presentation-format name.
fn normalize(name: String) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// Serves DNS over UDP until the shutdown token fires.
pub async fn run_udp(socket: UdpSocket, responder: Arc<DnsResponder>, shutdown: CancellationToken) {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 4096];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            recv = socket.recv_from(&mut buf) => {
                let (len, peer) = match recv {
                    Ok(v) => v,
                    Err(err) => {
                        trace!(error = %err, "DNS UDP receive error");
                        continue;
                    }
                };
                let responder = Arc::clone(&responder);
                let socket_ready = Arc::clone(&socket);
                let request = buf[..len].to_vec();
                tokio::spawn(async move {
                    let Ok(query) = Message::from_vec(&request) else {
                        trace!(%peer, "Dropping malformed DNS UDP query");
                        return;
                    };
                    if let Some(resp) = responder.answer(&query).await {
                        match resp.to_vec() {
                            Ok(bytes) => {
                                if let Err(err) = socket_ready.send_to(&bytes, peer).await {
                                    trace!(%peer, error = %err, "DNS UDP send error");
                                }
                            }
                            Err(err) => warn!(error = %err, "Failed to encode DNS UDP response"),
                        }
                    }
                });
            }
        }
    }
    debug!("DNS UDP responder stopped");
}

/// Serves DNS over TCP (RFC 7766) until the shutdown token fires.
pub async fn run_tcp(
    listener: TcpListener,
    responder: Arc<DnsResponder>,
    shutdown: CancellationToken,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accept = listener.accept() => {
                let (mut stream, peer) = match accept {
                    Ok(v) => v,
                    Err(err) => {
                        trace!(error = %err, "DNS TCP accept error");
                        continue;
                    }
                };
                let responder = Arc::clone(&responder);
                let conn_shutdown = shutdown.clone();
                tokio::spawn(async move {
                    loop {
                        // DNS over TCP prefixes each message with a 2-byte length.
                        let mut len_buf = [0u8; 2];
                        tokio::select! {
                            _ = conn_shutdown.cancelled() => return,
                            read = stream.read_exact(&mut len_buf) => {
                                if read.is_err() {
                                    return;
                                }
                            }
                        }
                        let len = u16::from_be_bytes(len_buf) as usize;
                        let mut msg = vec![0u8; len];
                        if stream.read_exact(&mut msg).await.is_err() {
                            return;
                        }
                        let Ok(query) = Message::from_vec(&msg) else {
                            trace!(%peer, "Dropping malformed DNS TCP query");
                            return;
                        };
                        let Some(resp) = responder.answer(&query).await else {
                            return;
                        };
                        let Ok(bytes) = resp.to_vec() else {
                            warn!(error = "encode", "Failed to encode DNS TCP response");
                            return;
                        };
                        let prefix = (bytes.len() as u16).to_be_bytes();
                        if stream.write_all(&prefix).await.is_err()
                            || stream.write_all(&bytes).await.is_err()
                        {
                            return;
                        }
                    }
                });
            }
        }
    }
    debug!("DNS TCP responder stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::store::Store;
    use hickory_proto::op::Query;

    async fn responder(relay_ips: Vec<IpAddr>) -> Arc<DnsResponder> {
        // Keep the temp directory alive for the whole test: `TempDir` drops on
        // scope exit and would unlink the SQLite file under the open connection.
        let dir = tempfile::tempdir().unwrap().keep();
        let store = Store::open(dir.join("test.db")).await.unwrap();
        let config = Config {
            root_domain: "example.com".into(),
            admin_domain: "relay-admin.test".into(),
            admin_email: "ops@example.com".into(),
            acme_provider: "letsencrypt".into(),
            listen_http: "0.0.0.0:80".parse().unwrap(),
            listen_https: "0.0.0.0:443".parse().unwrap(),
            control_socket: "/tmp/weaver-test.sock".into(),
            acme_directory: None,
            acme_eab_kid: None,
            acme_eab_hmac: None,
            acme_root_ca_pem: None,
            acme_fallback_providers: Vec::new(),
            usage_flush_interval_secs: 60,
            relay_ips,
            setup_complete: false,
        };
        Arc::new(DnsResponder::new(&config, Arc::new(store)))
    }

    fn query(qname: &str, qtype: RecordType, class: hickory_proto::rr::DNSClass) -> Message {
        let mut msg = Message::new(0x1, MessageType::Query, OpCode::Query);
        let mut q = Query::query(Name::from_str(&format!("{qname}.")).unwrap(), qtype);
        q.set_query_class(class);
        msg.add_query(q);
        msg
    }

    #[tokio::test]
    async fn wildcard_a_resolves_every_in_zone_name() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        for name in ["example.com", "poc-laptop-web.example.com"] {
            let resp = r
                .answer(&query(name, RecordType::A, hickory_proto::rr::DNSClass::IN))
                .await
                .unwrap();
            assert_eq!(resp.response_code, ResponseCode::NoError);
            assert_eq!(resp.answers.len(), 1, "name {name}");
            assert!(resp.metadata.authoritative);
            // RFC 1035: the response must echo the question section, or
            // resolvers treat it as malformed and return SERVFAIL.
            assert_eq!(resp.queries.len(), 1, "question echoed for {name}");
        }
    }

    #[tokio::test]
    async fn multi_label_is_out_of_zone() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        let resp = r
            .answer(&query(
                "a.b.example.com",
                RecordType::A,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.response_code, ResponseCode::Refused);
    }

    #[tokio::test]
    async fn out_of_zone_is_refused_not_nxdomain() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        let resp = r
            .answer(&query(
                "other.net",
                RecordType::A,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.response_code, ResponseCode::Refused);
        assert!(!resp.metadata.recursion_available);
    }

    #[tokio::test]
    async fn challenge_txt_is_multi_value_and_absent_is_nodata() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        r.store
            .publish_challenge("_acme-challenge.example.com", "value-a", 0)
            .await
            .unwrap();
        r.store
            .publish_challenge("_acme-challenge.example.com", "value-b", 0)
            .await
            .unwrap();

        let resp = r
            .answer(&query(
                "_acme-challenge.example.com",
                RecordType::TXT,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert_eq!(resp.answers.len(), 2);

        let resp = r
            .answer(&query(
                "poc-laptop-web.example.com",
                RecordType::TXT,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.response_code, ResponseCode::NoError);
        assert!(resp.answers.is_empty());
        assert_eq!(resp.authorities.len(), 1, "NODATA carries SOA");
    }

    #[tokio::test]
    async fn axfr_and_any_are_handled() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        let resp = r
            .answer(&query(
                "example.com",
                RecordType::AXFR,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.response_code, ResponseCode::Refused);

        let resp = r
            .answer(&query(
                "example.com",
                RecordType::ANY,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 1);
        assert_eq!(resp.answers[0].record_type(), RecordType::HINFO);
    }

    #[tokio::test]
    async fn bad_edns_version_is_badvers() {
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        let mut msg = query(
            "example.com",
            RecordType::A,
            hickory_proto::rr::DNSClass::IN,
        );
        let mut edns = Edns::new();
        edns.set_version(1);
        msg.set_edns(edns);
        let resp = r.answer(&msg).await.unwrap();
        assert_eq!(resp.response_code, ResponseCode::BADVERS);
    }

    #[tokio::test]
    async fn caa_authorises_configured_ca() {
        // The responder is built with `acme_provider = letsencrypt`, so it must
        // publish `issue`/`issuewild` for letsencrypt.org. An empty value would
        // forbid wildcard issuance and break the ACME order.
        let r = responder(vec!["203.0.113.7".parse().unwrap()]).await;
        let resp = r
            .answer(&query(
                "example.com",
                RecordType::CAA,
                hickory_proto::rr::DNSClass::IN,
            ))
            .await
            .unwrap();
        assert_eq!(resp.answers.len(), 2);
        let records: Vec<(&str, String)> = resp
            .answers
            .iter()
            .filter_map(|record| match &record.data {
                RData::CAA(caa) => Some((
                    caa.tag.as_str(),
                    String::from_utf8_lossy(&caa.value).into_owned(),
                )),
                _ => None,
            })
            .collect();
        // The CAA value must be the bare issuer domain with no trailing dot:
        // Let's Encrypt rejects `letsencrypt.org.`.
        assert!(
            records
                .iter()
                .any(|(tag, value)| *tag == "issue" && value == "letsencrypt.org"),
            "CAA issue must name the CA without a trailing dot: {records:?}"
        );
        assert!(
            records
                .iter()
                .any(|(tag, value)| *tag == "issuewild" && value == "letsencrypt.org"),
            "CAA issuewild must name the CA without a trailing dot: {records:?}"
        );
    }
}
