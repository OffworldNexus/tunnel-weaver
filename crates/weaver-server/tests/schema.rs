//! The schema a fresh store is created with: its references, its indexes and
//! the constraints the identity model rests on — one person per account, one
//! key per machine, and a key log that outlives what it describes.

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tempfile::TempDir;
use weaver_mux::KeyId;
use weaver_server::Store;

async fn fresh() -> (TempDir, Store) {
    let dir = TempDir::new().unwrap();
    let store = Store::open(dir.path().join("weaver.db")).await.unwrap();
    (dir, store)
}

/// Every row of `sql`, each column rendered as text (`NULL` for null).
async fn rows(store: &Store, sql: &str) -> Vec<Vec<String>> {
    store
        .db()
        .query_all_raw(Statement::from_string(DbBackend::Sqlite, sql))
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            (0..)
                .map_while(|i| {
                    row.try_get_by_index::<Option<String>>(i)
                        .map(|v| v.unwrap_or_else(|| "NULL".into()))
                        .or_else(|_| {
                            row.try_get_by_index::<Option<i64>>(i)
                                .map(|v| v.map_or("NULL".into(), |n| n.to_string()))
                        })
                        .ok()
                })
                .collect()
        })
        .collect()
}

async fn exec(store: &Store, sql: &str) -> Result<(), sea_orm::DbErr> {
    store.db().execute_unprepared(sql).await.map(|_| ())
}

#[tokio::test]
async fn references_point_where_the_model_says() {
    let (_dir, store) = fresh().await;
    for (table, parents) in [
        ("person", vec!["account"]),
        ("machine", vec!["person"]),
        ("service", vec!["machine"]),
        ("domains", vec!["service"]),
        ("usage_daily", vec!["service"]),
        ("usage_live", vec!["service"]),
        ("altcha_client", vec!["service"]),
        ("email_identity", vec!["account"]),
        ("password_credential", vec!["account"]),
        ("browser_session", vec!["account"]),
        ("password_reset_token", vec!["account"]),
        ("verification_token", vec!["pending_registration"]),
        (
            "email_verification",
            vec!["account", "email_identity", "verification_token"],
        ),
        ("machine_key_log", vec![]),
    ] {
        let mut found: Vec<String> = rows(
            &store,
            &format!("SELECT \"table\" FROM pragma_foreign_key_list('{table}')"),
        )
        .await
        .into_iter()
        .map(|row| row[0].clone())
        .collect();
        found.sort();
        assert_eq!(found, parents, "{table} references");
    }
    assert!(
        rows(
            &store,
            "SELECT name FROM sqlite_master WHERE name = 'machine_key'"
        )
        .await
        .is_empty()
    );
    for index in [
        "idx_machine_person_id_name",
        "idx_service_machine_id_name",
        "idx_machine_key_log_retired_at",
        "idx_altcha_proof_public_key_nonce",
    ] {
        assert_eq!(
            rows(
                &store,
                &format!(
                    "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = '{index}'"
                ),
            )
            .await,
            vec![vec!["1".to_string()]],
            "{index}"
        );
    }
}

#[tokio::test]
async fn people_and_machines_are_constrained_by_the_schema_itself() {
    let (_dir, store) = fresh().await;
    exec(
        &store,
        "INSERT INTO account (id, name, state, created_at, activated_at) \
         VALUES (1, 'A', 'active', 0, 0)",
    )
    .await
    .unwrap();
    exec(
        &store,
        "INSERT INTO person (id, name, created_at, account_id) VALUES (1, 'alice', 0, 1)",
    )
    .await
    .unwrap();
    exec(
        &store,
        "INSERT INTO machine (person_id, name, created_at, key_id) VALUES (1, 'laptop', 0, 'p256:k')",
    )
    .await
    .unwrap();

    for sql in [
        // A second person for the account, a person without one, a dangling one.
        "INSERT INTO person (name, created_at, account_id) VALUES ('alice2', 0, 1)",
        "INSERT INTO person (name, created_at, account_id) VALUES ('nobody', 0, NULL)",
        "INSERT INTO person (name, created_at, account_id) VALUES ('nowhere', 0, 77)",
        // A key held twice, a machine without a key, a duplicate name.
        "INSERT INTO machine (person_id, name, created_at, key_id) VALUES (1, 'other', 0, 'p256:k')",
        "INSERT INTO machine (person_id, name, created_at) VALUES (1, 'keyless', 0)",
        "INSERT INTO machine (person_id, name, created_at, key_id) VALUES (1, 'laptop', 0, 'p256:j')",
    ] {
        assert!(exec(&store, sql).await.is_err(), "{sql} must be refused");
    }
    assert!(rows(&store, "PRAGMA foreign_key_check").await.is_empty());
}

#[tokio::test]
async fn the_key_log_outlives_a_revoked_machine_and_its_account() {
    let (_dir, store) = fresh().await;
    let alice = store.create_test_person("alice").await.unwrap();
    let key = KeyId::P256([2; 33]);
    let laptop = store
        .create_machine(alice.id, "laptop", &key)
        .await
        .unwrap();
    store.revoke_machine(&key).await.unwrap().unwrap();
    exec(
        &store,
        &format!("DELETE FROM account WHERE id = {}", alice.account_id),
    )
    .await
    .unwrap();

    assert!(rows(&store, "SELECT id FROM person").await.is_empty());
    assert_eq!(
        rows(
            &store,
            "SELECT machine_id, person_id, retired_reason FROM machine_key_log"
        )
        .await,
        vec![vec![
            laptop.id.to_string(),
            alice.id.to_string(),
            "revoked".into()
        ]]
    );
    assert!(rows(&store, "PRAGMA foreign_key_check").await.is_empty());
}
