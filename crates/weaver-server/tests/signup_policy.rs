//! The relay's signup policy (WVR-98): evaluation, numbering, and the two
//! account-creation paths that enforce it.
//!
//! The browser suite walks the password journey; these tests pin the parts a
//! browser cannot reach cheaply — exact-domain matching, rule ordering and
//! numbering, and the SSO first-sign-in rules.

use tempfile::TempDir;
use weaver_server::store::account::NewExternalIdentity;
use weaver_server::store::signup::{Decision, RuleKind, RuleValue, SignupDecision, SignupRefusal};
use weaver_server::{Store, StoreError};

async fn open_store() -> (TempDir, Store) {
    let temp = TempDir::new().expect("tempdir");
    let store = Store::open(temp.path().join("signup.db"))
        .await
        .expect("open store");
    (temp, store)
}

fn rule(kind: RuleKind, value: &str) -> RuleValue {
    RuleValue::typed(kind, value).expect("valid rule value")
}

fn identity<'a>(
    subject: &'a str,
    email: &'a str,
    verified: bool,
    now: i64,
) -> NewExternalIdentity<'a> {
    NewExternalIdentity {
        provider: "microsoft",
        tenant_id: "32fb7b25-9b31-4552-a225-7cb8da0afb61",
        subject,
        name: "Ada",
        email,
        lookup_key: email,
        email_verified_at: verified.then_some(now),
        sealed_refresh: "",
        now,
    }
}

#[tokio::test]
async fn an_unconfigured_relay_allows_everyone() {
    let (_temp, store) = open_store().await;

    assert_eq!(
        store.signup_decision("anyone@example.com").await.unwrap(),
        SignupDecision::Allowed
    );
    // An open relay admits even an unverified SSO claim; only a configured
    // policy judges the vouch.
    assert_eq!(
        store
            .signup_admit("anyone@example.com", false)
            .await
            .unwrap(),
        SignupDecision::Allowed
    );
    assert!(store.signup_rules().await.unwrap().is_empty());
    assert_eq!(store.signup_default().await.unwrap(), Decision::Allow);
}

#[tokio::test]
async fn rules_match_in_number_order_and_domains_match_exactly() {
    let (_temp, store) = open_store().await;
    store.signup_default_set(Decision::Deny).await.unwrap();
    // Deliberately inserted out of order: evaluation follows the number, not
    // the insertion order.
    store
        .signup_rule_add(
            Some(200),
            Decision::Allow,
            rule(RuleKind::Domain, "acme.com"),
        )
        .await
        .unwrap();
    store
        .signup_rule_add(
            Some(100),
            Decision::Deny,
            rule(RuleKind::Email, "X@ACME.com"),
        )
        .await
        .unwrap();

    assert_eq!(
        store.signup_decision("x@acme.com").await.unwrap(),
        SignupDecision::Denied {
            refusal: SignupRefusal::Rule(100)
        }
    );
    assert_eq!(
        store.signup_decision("Bob@ACME.com").await.unwrap(),
        SignupDecision::Allowed
    );
    // A domain rule is exact: a subdomain is a different domain.
    assert_eq!(
        store.signup_decision("bob@eng.acme.com").await.unwrap(),
        SignupDecision::Denied {
            refusal: SignupRefusal::Default
        }
    );
    assert_eq!(
        store.signup_decision("bob@other.com").await.unwrap(),
        SignupDecision::Denied {
            refusal: SignupRefusal::Default
        }
    );
}

#[tokio::test]
async fn rules_are_numbered_100_at_a_time_and_numbers_are_never_reused() {
    let (_temp, store) = open_store().await;

    let first = store
        .signup_rule_add(None, Decision::Allow, rule(RuleKind::Domain, "acme.com"))
        .await
        .unwrap();
    assert_eq!(first.number, 100);

    let second = store
        .signup_rule_add(None, Decision::Deny, rule(RuleKind::Email, "x@acme.com"))
        .await
        .unwrap();
    assert_eq!(second.number, 200);

    // An explicit number that is taken is a conflict, not an overwrite.
    assert!(matches!(
        store
            .signup_rule_add(
                Some(100),
                Decision::Allow,
                rule(RuleKind::Domain, "other.com")
            )
            .await,
        Err(StoreError::Conflict(_))
    ));
}

#[tokio::test]
async fn deleting_a_rule_reports_whether_it_existed() {
    let (_temp, store) = open_store().await;
    store
        .signup_rule_add(
            Some(100),
            Decision::Allow,
            rule(RuleKind::Domain, "acme.com"),
        )
        .await
        .unwrap();

    assert!(store.signup_rule_delete(100).await.unwrap());
    assert!(!store.signup_rule_delete(100).await.unwrap());
    assert!(store.signup_rules().await.unwrap().is_empty());
}

#[tokio::test]
async fn replace_states_the_whole_policy_in_evaluation_order() {
    let (_temp, store) = open_store().await;
    store
        .signup_rule_add(
            Some(7),
            Decision::Deny,
            rule(RuleKind::Domain, "stale.example"),
        )
        .await
        .unwrap();

    store
        .signup_policy_replace(
            Decision::Deny,
            &[
                (Decision::Allow, rule(RuleKind::Email, "Ada@Example.com")),
                (Decision::Allow, rule(RuleKind::Domain, "acme.com")),
            ],
        )
        .await
        .unwrap();

    let listed = store
        .signup_rules()
        .await
        .unwrap()
        .into_iter()
        .map(|rule| (rule.number, rule.value.as_str().to_string()))
        .collect::<Vec<_>>();
    assert_eq!(
        listed,
        vec![
            (100, "ada@example.com".to_string()),
            (200, "acme.com".to_string())
        ]
    );
    assert_eq!(
        store
            .signup_decision("stranger@stale.example")
            .await
            .unwrap(),
        SignupDecision::Denied {
            refusal: SignupRefusal::Default
        }
    );

    // Replacing with no rules and an allow default reopens the relay.
    store
        .signup_policy_replace(Decision::Allow, &[])
        .await
        .unwrap();
    assert_eq!(
        store
            .signup_decision("stranger@stale.example")
            .await
            .unwrap(),
        SignupDecision::Allowed
    );
}

#[tokio::test]
async fn an_unverified_sso_address_cannot_create_an_account_under_a_policy() {
    let (_temp, store) = open_store().await;
    let now = 1_000;

    // Open relay: today's behaviour, an unverified claim still signs up and
    // settles the address later with an emailed code.
    let created = store
        .external_identity_resolve_or_create(identity("oid-a", "ada@example.com", false, now))
        .await
        .expect("creates on an open relay");
    assert!(created.created);

    store.signup_default_set(Decision::Deny).await.unwrap();
    assert!(matches!(
        store
            .external_identity_resolve_or_create(identity("oid-b", "bob@example.com", false, now))
            .await,
        Err(StoreError::SignupRefused {
            refusal: SignupRefusal::UnverifiedAddress
        })
    ));

    // The already-linked identity keeps signing in: the policy governs
    // creation, not sign-in.
    let again = store
        .external_identity_resolve_or_create(identity("oid-a", "ada@example.com", false, now))
        .await
        .expect("signs in");
    assert!(!again.created);
    assert_eq!(again.account.id, created.account.id);
}

#[tokio::test]
async fn a_verified_sso_address_obeys_the_policy() {
    let (_temp, store) = open_store().await;
    let now = 1_000;

    store.signup_default_set(Decision::Deny).await.unwrap();
    store
        .signup_rule_add(
            Some(100),
            Decision::Allow,
            rule(RuleKind::Domain, "acme.com"),
        )
        .await
        .unwrap();

    let created = store
        .external_identity_resolve_or_create(identity("oid-a", "ada@acme.com", true, now))
        .await
        .expect("allowed by the domain rule");
    assert!(created.created);

    assert!(matches!(
        store
            .external_identity_resolve_or_create(identity("oid-b", "bob@other.com", true, now))
            .await,
        Err(StoreError::SignupRefused {
            refusal: SignupRefusal::Default
        })
    ));
}
