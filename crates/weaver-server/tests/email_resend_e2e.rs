//! Ignored real-provider e2e.
//!
//! Runs only when `RESEND_API_KEY` and `WEAVER_E2E_EMAIL` are present, and
//! skips otherwise so it is safe in any suite. `WEAVER_E2E_FROM` may override
//! the sender (defaults to Resend's shared onboarding address).

use weaver_server::config::EmailConfig;
use weaver_server::email::{Joke, Mailbox, mailer_from_config};

#[tokio::test]
#[ignore = "e2e: requires RESEND_API_KEY and WEAVER_E2E_EMAIL"]
async fn resend_sends_a_real_joke() {
    let Ok(api_key) = std::env::var("RESEND_API_KEY") else {
        eprintln!("skipping: RESEND_API_KEY is not set");
        return;
    };
    let Ok(to) = std::env::var("WEAVER_E2E_EMAIL") else {
        eprintln!("skipping: WEAVER_E2E_EMAIL is not set");
        return;
    };
    let from =
        std::env::var("WEAVER_E2E_FROM").unwrap_or_else(|_| "onboarding@resend.dev".to_string());

    let cfg = EmailConfig {
        provider: "resend".into(),
        from,
        api_key: Some(api_key),
        ..Default::default()
    };
    let mailer = mailer_from_config(Some(&cfg), "https://relay.example.org").expect("build mailer");
    let to = Mailbox::parse(&to, None).expect("valid recipient");
    let joke = Joke {
        line: "If at first you do not succeed, call it version 1.0.".into(),
    };

    let email = mailer.compose(to, &joke).expect("compose");
    let receipt = mailer.send(&email).await.expect("resend send");
    eprintln!("resend accepted id={:?}", receipt.message_id);
}
