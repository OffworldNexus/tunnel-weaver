//! The client's local decisions, with an in-memory key agent and no relay.

use std::sync::{Arc, Mutex};

use weave::{
    Client, Error, KeyAgent, KeyError, OpenedKey, PairRequest, Provision, Reporter, SecurityLevel,
    ServiceSpec, StartOptions, Store, Target,
};
use weaver_mux::KeyId;
use weaver_mux::auth::Signer as _;
use weaver_mux::testing::P256TestSigner;

/// Every `open` the agent was asked: the remembered key and the provision.
type Calls = Arc<Mutex<Vec<(Option<KeyId>, Provision)>>>;

/// Hands out the key derived from `seed`; `created` says whether it is new.
struct FakeAgent {
    seed: u64,
    created: bool,
    /// Refuse to create below the floor without consent.
    below_floor: bool,
    calls: Calls,
}

impl FakeAgent {
    fn new(seed: u64) -> Self {
        Self {
            seed,
            created: false,
            below_floor: false,
            calls: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl KeyAgent for FakeAgent {
    async fn open(
        &self,
        remembered: Option<KeyId>,
        provision: Provision,
        _reporter: Arc<dyn Reporter>,
    ) -> Result<OpenedKey, KeyError> {
        self.calls.lock().unwrap().push((remembered, provision));
        if self.below_floor && !provision.allow_below_floor {
            return Err(KeyError::BelowFloor {
                required: provision.floor,
                available: SecurityLevel::File,
            });
        }
        Ok(OpenedKey {
            signer: Box::new(P256TestSigner::from_seed(self.seed)),
            level: SecurityLevel::Sealed,
            created: self.created,
        })
    }
}

/// Records what the client reported, and answers the below-floor question.
#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
    allow_below_floor: bool,
}

impl Recorder {
    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn record(&self, event: String) {
        self.events.lock().unwrap().push(event);
    }
}

impl Reporter for Recorder {
    fn pairing_not_effective(&self, host: &str, _reason: &str) {
        self.record(format!("not effective: {host}"));
    }

    fn allow_below_floor(&self, required: SecurityLevel, available: SecurityLevel) -> bool {
        self.record(format!("below floor: {required} > {available}"));
        self.allow_below_floor
    }

    fn connecting(&self, host: &str) {
        self.record(format!("connecting: {host}"));
    }
}

fn key_of(seed: u64) -> String {
    P256TestSigner::from_seed(seed).key_id().to_string()
}

async fn store(dir: &tempfile::TempDir, relays: &[(&str, i32, &str)]) -> Store {
    let store = Store::open(dir.path().join("weave.db")).await.unwrap();
    for (host, machine, key) in relays {
        store.record_pairing(host, *machine, key).await.unwrap();
    }
    store
}

async fn hosts(dir: &tempfile::TempDir) -> Vec<(String, bool)> {
    let store = Store::open(dir.path().join("weave.db")).await.unwrap();
    store
        .relays()
        .await
        .unwrap()
        .into_iter()
        .map(|r| (r.admin_host, r.is_default))
        .collect()
}

#[tokio::test]
async fn unpairing_a_key_the_relay_never_had_forgets_it_without_dialling() {
    let dir = tempfile::tempdir().unwrap();
    // Paired under another key: the pairing cannot be in effect.
    let store = store(
        &dir,
        &[("a.example", 1, &key_of(9)), ("b.example", 2, &key_of(9))],
    )
    .await;
    let recorder = Arc::new(Recorder::default());
    let client = Client::new(store, Box::new(FakeAgent::new(1)), recorder.clone());

    let unpaired = client.unpair("").await.unwrap();
    assert_eq!(unpaired.host, "a.example");
    assert!(!unpaired.revoked);
    assert_eq!(unpaired.new_default, "b.example");
    assert_eq!(unpaired.remaining, 1);
    assert_eq!(recorder.events(), ["not effective: a.example"]);
    assert_eq!(hosts(&dir).await, [("b.example".to_string(), true)]);

    // A relay that is not paired is an error, not a no-op.
    assert!(matches!(
        client.unpair("c.example").await,
        Err(Error::NotPaired(host)) if host == "c.example"
    ));
}

#[tokio::test]
async fn unpairing_an_unreachable_relay_keeps_the_pairing() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &[("127.0.0.1:1", 1, &key_of(1))]).await;
    store.set_device_key(&key_of(1)).await.unwrap();
    let client = Client::new(
        store,
        Box::new(FakeAgent::new(1)),
        Arc::new(Recorder::default()),
    );

    let result = client.unpair("").await;
    assert!(
        matches!(result, Err(Error::Unreachable { .. })),
        "{result:?}"
    );
    assert_eq!(hosts(&dir).await, [("127.0.0.1:1".to_string(), true)]);
}

#[tokio::test]
async fn start_with_a_new_key_says_the_old_one_is_gone_and_remembers_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &[("a.example", 1, &key_of(1))]).await;
    store.set_device_key(&key_of(1)).await.unwrap();
    let agent = FakeAgent {
        created: true,
        ..FakeAgent::new(2)
    };
    let calls = agent.calls.clone();
    let recorder = Arc::new(Recorder::default());
    let client = Client::new(store, Box::new(agent), recorder.clone());

    let opts = StartOptions {
        server: String::new(),
        services: vec![ServiceSpec::new("web", Target::parse("8080").unwrap())],
    };
    let result = client
        .start(&opts, tokio_util::sync::CancellationToken::new())
        .await;
    assert!(
        matches!(result, Err(Error::KeyGone { ref host }) if host == "a.example"),
        "{result:?}"
    );
    // The remembered key was asked for, the relay never dialled.
    assert_eq!(calls.lock().unwrap()[0].0, key_of(1).parse().ok());
    assert!(recorder.events().is_empty(), "{:?}", recorder.events());

    let store = Store::open(dir.path().join("weave.db")).await.unwrap();
    assert_eq!(store.device_key().await.unwrap(), key_of(2));
}

#[tokio::test]
async fn pairing_again_with_the_same_key_is_refused_before_dialling() {
    let dir = tempfile::tempdir().unwrap();
    let store = store(&dir, &[("a.example", 7, &key_of(1))]).await;
    store.set_device_key(&key_of(1)).await.unwrap();
    let recorder = Arc::new(Recorder::default());
    let client = Client::new(store, Box::new(FakeAgent::new(1)), recorder.clone());

    let request = PairRequest {
        admin_host: "A.Example".into(),
        machine: None,
        floor: SecurityLevel::Sealed,
        allow_below_floor: false,
    };
    let result = client.pair(&request).await;
    assert!(
        matches!(result, Err(Error::AlreadyPaired { machine_id: 7, .. })),
        "{result:?}"
    );
    assert!(recorder.events().is_empty(), "{:?}", recorder.events());
}

#[tokio::test]
async fn pairing_below_the_floor_needs_consent() {
    let request = PairRequest {
        admin_host: "127.0.0.1:1".into(),
        machine: None,
        floor: SecurityLevel::Sealed,
        allow_below_floor: false,
    };

    for consent in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let agent = FakeAgent {
            below_floor: true,
            ..FakeAgent::new(1)
        };
        let calls = agent.calls.clone();
        let recorder = Arc::new(Recorder {
            allow_below_floor: consent,
            ..Recorder::default()
        });
        let client = Client::new(store(&dir, &[]).await, Box::new(agent), recorder.clone());

        let result = client.pair(&request).await;
        let mut expected = vec!["below floor: sealed > file".to_string()];
        if consent {
            // Created at the weaker level, then on to the (unreachable) relay.
            assert!(
                matches!(result, Err(Error::Unreachable { .. })),
                "{result:?}"
            );
            assert!(calls.lock().unwrap()[1].1.allow_below_floor);
            expected.push("connecting: 127.0.0.1:1".into());
        } else {
            assert!(
                matches!(result, Err(Error::Key(KeyError::BelowFloor { .. }))),
                "{result:?}"
            );
            assert_eq!(calls.lock().unwrap().len(), 1);
        }
        assert_eq!(recorder.events(), expected);
    }
}
