//! What every way of signing in shares: opening the browser session, offering
//! the emailed code, and emailing a code with the copy its purpose needs.
//!
//! The password, passkey and identity-provider sign-ins differ only in how the
//! first factor is checked and which proof it records; the rest lives here once.

use axum::response::Response;
use http::StatusCode;

use crate::account::auth::{AuthManager, SessionContext};
use crate::account::router::{err, with_cookie};
use crate::account::second_factor::{Challenge, Flow, Purpose};
use crate::account::{AccountRuntime, session};
use crate::email::{Mailbox, SignInCode, Verification};

/// Why an emailed code did not reach the person.
#[derive(Debug)]
pub enum DeliverError {
    /// The code could not be stored.
    Store,
    /// The code was stored but the email was not sent.
    Mail(String),
}

impl std::fmt::Display for DeliverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeliverError::Store => f.write_str("the code could not be stored"),
            DeliverError::Mail(error) => write!(f, "the email was not sent: {error}"),
        }
    }
}

/// Issues a flow's code and emails it with the copy of its purpose.
pub async fn deliver_code(
    rt: &AccountRuntime,
    flow: Flow,
    purpose: Purpose,
    name: &str,
    email: &str,
    now: i64,
) -> Result<(), DeliverError> {
    let code = Challenge::new(&rt.store, flow)
        .issue(purpose, now)
        .await
        .map_err(|_| DeliverError::Store)?;
    send_code(rt, purpose, name, email, &code)
        .await
        .map_err(DeliverError::Mail)
}

/// Emails a code. `code` is the plaintext; it is never logged here.
async fn send_code(
    rt: &AccountRuntime,
    purpose: Purpose,
    name: &str,
    email: &str,
    code: &str,
) -> Result<(), String> {
    let Some(mailer) = &rt.mailer else {
        return Err("email is not configured".into());
    };
    let to = Mailbox::parse(email, Some(name.to_string())).map_err(|e| e.to_string())?;
    let code = code.to_string();
    let composed = match purpose {
        Purpose::SignIn => mailer.compose(to, &SignInCode { code }),
        Purpose::VerifyAddress => mailer.compose(to, &Verification { code }),
    }
    .map_err(|e| e.to_string())?;
    mailer.send(&composed).await.map_err(|e| e.to_string())?;
    Ok(())
}

/// A browser session a sign-in has just opened, before its cookies are set.
///
/// Every failure after [`OpenedSession::open`] must go through
/// [`OpenedSession::abort`], so a half-made sign-in never leaves a live session.
pub struct OpenedSession<'a> {
    rt: &'a AccountRuntime,
    raw: String,
    now: i64,
    pub context: SessionContext,
}

impl<'a> OpenedSession<'a> {
    /// Opens a session for `account_id`, recording the external identity
    /// provider that opened it (empty for a password or passkey sign-in); `None`
    /// when the store is unavailable.
    pub async fn open(
        rt: &'a AccountRuntime,
        account_id: i32,
        now: i64,
        provider: &str,
    ) -> Option<Self> {
        let raw = rt.sessions.create(account_id, provider, now).await.ok()?;
        let Some(session) = rt
            .store
            .session_live(&session::token_hash(&raw), now)
            .await
            .ok()
            .flatten()
        else {
            let _ = rt.sessions.invalidate(&raw, now).await;
            return None;
        };
        Some(Self {
            rt,
            raw,
            now,
            context: SessionContext {
                session_id: session.id,
                account_id,
            },
        })
    }

    /// Closes the session again.
    pub async fn close(self) {
        let _ = self.rt.sessions.invalidate(&self.raw, self.now).await;
    }

    /// Closes the session again and answers `503`.
    pub async fn abort(self) -> Response {
        self.abort_with("temporarily unavailable").await
    }

    /// Closes the session again and answers `503` with `message`.
    pub async fn abort_with(self, message: &str) -> Response {
        self.close().await;
        err(StatusCode::SERVICE_UNAVAILABLE, message)
    }

    /// Records the sign-in on the account (the inactivity clock).
    pub async fn record_login(&self) -> Result<(), crate::store::StoreError> {
        self.rt
            .store
            .account_record_login(self.context.account_id, self.now)
            .await
    }

    /// Offers the emailed code. A sign-in code is skipped when the account has a
    /// confirmed authenticator app — the app is what the verify step asks for —
    /// but an address-verification code is always sent: nothing else settles
    /// the address.
    pub async fn offer_emailed_code(
        &self,
        manager: &AuthManager,
        purpose: Purpose,
        name: &str,
        email: &str,
    ) -> Result<(), DeliverError> {
        if purpose == Purpose::SignIn
            && self
                .rt
                .store
                .totp_confirmed_count_for(self.context.account_id)
                .await
                .is_ok_and(|count| count > 0)
        {
            return Ok(());
        }
        let flow = Flow::Session(self.context.session_id);
        deliver_code(self.rt, flow, purpose, name, email, self.now).await?;
        manager
            .email_otp_issued(self.context)
            .await
            .map_err(|_| DeliverError::Store)
    }

    /// Hands the session to the browser: `response` with the session and CSRF
    /// cookies set.
    pub fn finish(self, response: Response) -> Response {
        let csrf = session::new_token();
        let response = with_cookie(response, self.rt.sessions.session_cookie(&self.raw));
        with_cookie(response, self.rt.sessions.csrf_cookie(&csrf))
    }
}
