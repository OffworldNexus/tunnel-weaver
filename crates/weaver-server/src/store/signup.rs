//! The relay's account-creation policy (WVR-98): who may sign up.
//!
//! Apache-ipfw semantics, one policy for the whole relay: numbered rules are
//! evaluated in ascending order, the first match wins, and the default decides
//! when nothing matches. A rule targets one exact address or one exact domain
//! (`acme.com` never matches `eng.acme.com`). Values are validated and
//! normalised here, once, so the CLI, the setup wizard and matching agree.
//!
//! The policy is deliberately **not** part of the cached config: every attempt
//! reads it from the store, which is what makes `weaver-server signup …` apply
//! to the next signup with no daemon restart.

use std::fmt;

use sea_orm::sea_query::OnConflict;
use sea_orm::{ConnectionTrait, EntityTrait, QueryOrder, Set, TransactionTrait};

use super::entity::signup_policy::SINGLETON_ID;
use super::entity::{signup_policy, signup_rule};
use super::{Store, StoreError};

/// The gap left between automatically numbered rules, so an operator can insert
/// one in between later.
const RULE_GAP: i32 = 100;

/// A rule's (or the default's) decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

impl Decision {
    /// The word the decision is stored and shown as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }

    /// Parses the stored/typed word; `None` for anything else.
    pub fn parse(word: &str) -> Option<Self> {
        match word {
            "allow" => Some(Self::Allow),
            "deny" => Some(Self::Deny),
            _ => None,
        }
    }
}

/// Why a creation was refused, for the operator's log. Never shown to the
/// person, who sees one fixed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupRefusal {
    /// A rule with this number matched.
    Rule(i32),
    /// No rule matched, and the default denies.
    Default,
    /// The identity provider did not vouch for the address, and the relay has a
    /// policy at all: an unproven claim cannot create an account.
    UnverifiedAddress,
}

impl fmt::Display for SignupRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule(number) => write!(f, "rule {number}"),
            Self::Default => f.write_str("default"),
            Self::UnverifiedAddress => f.write_str("unverified address"),
        }
    }
}

/// What the policy answers for one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignupDecision {
    /// The address may create an account.
    Allowed,
    /// The address may not create an account.
    Denied { refusal: SignupRefusal },
}

/// Which part of an address a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    /// The whole address, exactly.
    Email,
    /// The part after `@`, exactly — no subdomain matching.
    Domain,
}

impl RuleKind {
    /// Parses the stored/typed kind; `None` for anything else.
    pub fn parse(kind: &str) -> Option<Self> {
        match kind {
            "email" => Some(Self::Email),
            "domain" => Some(Self::Domain),
            _ => None,
        }
    }

    /// The word the kind is stored and shown as.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Domain => "domain",
        }
    }
}

/// One rule's target, already validated and normalised.
///
/// The fields are private and construction goes through [`RuleValue::typed`] or
/// [`RuleValue::infer`], so a caller cannot write a value that no address could
/// carry or that matching would never compare against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleValue {
    kind: RuleKind,
    value: String,
}

impl RuleValue {
    /// Parses a value for a kind the operator named explicitly (the CLI's
    /// `signup add … email|domain VALUE`).
    pub fn typed(kind: RuleKind, input: &str) -> Result<Self, String> {
        let value = crate::email::normalize_address(input);
        let valid = match kind {
            RuleKind::Email => crate::email::is_valid_address(&value),
            RuleKind::Domain => crate::email::is_valid_domain(&value),
        };
        if !valid {
            return Err(format!(
                "'{input}' is not a valid {}",
                match kind {
                    RuleKind::Email => "email address",
                    RuleKind::Domain => "domain",
                }
            ));
        }
        Ok(Self { kind, value })
    }

    /// Parses a value whose kind the operator did not name: anything carrying an
    /// `@` is an address, everything else a domain (the setup wizard's single
    /// field, and `--signup-allow`).
    pub fn infer(input: &str) -> Result<Self, String> {
        let kind = if input.contains('@') {
            RuleKind::Email
        } else {
            RuleKind::Domain
        };
        Self::typed(kind, input)
    }

    /// Which part of an address this rule matches.
    pub fn kind(&self) -> RuleKind {
        self.kind
    }

    /// The normalised value, as stored, displayed and forwarded across the
    /// `sudo` re-exec.
    pub fn as_str(&self) -> &str {
        &self.value
    }
}

/// One stored rule, as listed for the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub number: i32,
    pub decision: Decision,
    pub value: RuleValue,
}

/// The domain half of a lookup key, and of the address a person typed.
pub(crate) fn domain_of(address: &str) -> &str {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain)
        .unwrap_or("")
}

impl Store {
    /// The policy's default decision when no rule matches: allow when no policy
    /// was ever configured. An unreadable stored word counts as deny, so a
    /// corrupted row cannot quietly reopen the relay.
    pub async fn signup_default(&self) -> Result<Decision, StoreError> {
        self.signup_default_in_txn(&self.db).await
    }

    async fn signup_default_in_txn(
        &self,
        conn: &impl ConnectionTrait,
    ) -> Result<Decision, StoreError> {
        let stored = signup_policy::Entity::find_by_id(SINGLETON_ID)
            .one(conn)
            .await?
            .map(|row| row.default_decision);
        Ok(match stored.as_deref() {
            // Never configured: today's relay, open to anyone.
            None => Decision::Allow,
            Some(word) => Decision::parse(word).unwrap_or(Decision::Deny),
        })
    }

    /// The policy's decision for an address's lookup key.
    pub async fn signup_decision(&self, lookup_key: &str) -> Result<SignupDecision, StoreError> {
        self.signup_decision_in_txn(&self.db, lookup_key).await
    }

    /// The decision for an SSO assertion that would create an account.
    ///
    /// An address the provider does not vouch for cannot create one under any
    /// configured policy: the operator asked to control who gets in, and an
    /// unverified claim proves nothing about who owns the address.
    pub async fn signup_admit(
        &self,
        lookup_key: &str,
        address_verified: bool,
    ) -> Result<SignupDecision, StoreError> {
        self.signup_admit_in_txn(&self.db, lookup_key, address_verified)
            .await
    }

    /// The transaction variant of [`Store::signup_admit`], so an account
    /// creation and the policy read that authorises it are one atomic step.
    pub(crate) async fn signup_admit_in_txn(
        &self,
        conn: &impl ConnectionTrait,
        lookup_key: &str,
        address_verified: bool,
    ) -> Result<SignupDecision, StoreError> {
        if !address_verified && self.signup_policy_restrictive_in_txn(conn).await? {
            return Ok(SignupDecision::Denied {
                refusal: SignupRefusal::UnverifiedAddress,
            });
        }
        self.signup_decision_in_txn(conn, lookup_key).await
    }

    /// The transaction variant of [`Store::signup_decision`].
    pub(crate) async fn signup_decision_in_txn(
        &self,
        conn: &impl ConnectionTrait,
        lookup_key: &str,
    ) -> Result<SignupDecision, StoreError> {
        let key = crate::email::normalize_address(lookup_key);
        let domain = domain_of(&key);
        let rules = signup_rule::Entity::find()
            .order_by_asc(signup_rule::Column::Number)
            .all(conn)
            .await?;
        for rule in rules {
            let matched = match RuleKind::parse(&rule.kind) {
                Some(RuleKind::Email) => rule.value == key,
                Some(RuleKind::Domain) => rule.value == domain,
                // A row this program never writes; treat it as matching nothing
                // rather than failing every signup on a corrupted policy.
                None => false,
            };
            if matched {
                return Ok(match Decision::parse(&rule.decision) {
                    Some(Decision::Allow) => SignupDecision::Allowed,
                    // An unreadable decision denies: fail closed like the
                    // default.
                    _ => SignupDecision::Denied {
                        refusal: SignupRefusal::Rule(rule.number),
                    },
                });
            }
        }
        Ok(match self.signup_default_in_txn(conn).await? {
            Decision::Allow => SignupDecision::Allowed,
            Decision::Deny => SignupDecision::Denied {
                refusal: SignupRefusal::Default,
            },
        })
    }

    /// Whether the policy would refuse anyone at all: a deny default or any
    /// rule. "Default allow with no rules" is exactly an open relay, whether
    /// that is stored or simply never configured.
    async fn signup_policy_restrictive_in_txn(
        &self,
        conn: &impl ConnectionTrait,
    ) -> Result<bool, StoreError> {
        Ok(self.signup_default_in_txn(conn).await? == Decision::Deny
            || signup_rule::Entity::find().one(conn).await?.is_some())
    }

    /// Every rule in evaluation order.
    pub async fn signup_rules(&self) -> Result<Vec<Rule>, StoreError> {
        let rows = signup_rule::Entity::find()
            .order_by_asc(signup_rule::Column::Number)
            .all(&self.db)
            .await?;
        Ok(rows.into_iter().filter_map(rule_from_row).collect())
    }

    /// Sets the default decision, creating the singleton row when absent.
    pub async fn signup_default_set(&self, decision: Decision) -> Result<(), StoreError> {
        signup_policy::Entity::insert(signup_policy::ActiveModel {
            id: Set(SINGLETON_ID),
            default_decision: Set(decision.as_str().to_string()),
        })
        .on_conflict(
            OnConflict::column(signup_policy::Column::Id)
                .update_column(signup_policy::Column::DefaultDecision)
                .to_owned(),
        )
        .exec(&self.db)
        .await?;
        Ok(())
    }

    /// Adds one rule. `number: None` places it 100 after the highest rule (100
    /// on an empty policy); a number already in use is a [`StoreError::Conflict`].
    ///
    /// The primary key is what makes a duplicate impossible; the explicit check
    /// is what turns it into a message the operator can act on.
    pub async fn signup_rule_add(
        &self,
        number: Option<i32>,
        decision: Decision,
        value: RuleValue,
    ) -> Result<Rule, StoreError> {
        let txn = self.db.begin().await?;
        let number = match number {
            Some(number) => number,
            None => signup_rule::Entity::find()
                .order_by_desc(signup_rule::Column::Number)
                .one(&txn)
                .await?
                .map(|rule| rule.number + RULE_GAP)
                .unwrap_or(RULE_GAP),
        };
        if signup_rule::Entity::find_by_id(number)
            .one(&txn)
            .await?
            .is_some()
        {
            txn.rollback().await?;
            return Err(StoreError::Conflict(format!(
                "a rule numbered {number} already exists"
            )));
        }
        let inserted = signup_rule::Entity::insert(signup_rule::ActiveModel {
            number: Set(number),
            decision: Set(decision.as_str().to_string()),
            kind: Set(value.kind().as_str().to_string()),
            value: Set(value.as_str().to_string()),
        })
        .exec_with_returning(&txn)
        .await?;
        txn.commit().await?;
        rule_from_row(inserted)
            .ok_or_else(|| StoreError::Conflict("the inserted rule could not be read back".into()))
    }

    /// Deletes one rule; `false` when no rule carries that number.
    pub async fn signup_rule_delete(&self, number: i32) -> Result<bool, StoreError> {
        Ok(signup_rule::Entity::delete_by_id(number)
            .exec(&self.db)
            .await?
            .rows_affected
            > 0)
    }

    /// Replaces the whole policy in one transaction: `default`, plus one rule
    /// per entry, numbered 100, 200, … in the order given.
    ///
    /// Setup and the e2e harness both describe a policy in one shot; everything
    /// else edits it rule by rule.
    pub async fn signup_policy_replace(
        &self,
        default: Decision,
        rules: &[(Decision, RuleValue)],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin().await?;
        signup_rule::Entity::delete_many().exec(&txn).await?;
        for (index, (decision, value)) in rules.iter().enumerate() {
            signup_rule::Entity::insert(signup_rule::ActiveModel {
                number: Set(RULE_GAP * (index as i32 + 1)),
                decision: Set(decision.as_str().to_string()),
                kind: Set(value.kind().as_str().to_string()),
                value: Set(value.as_str().to_string()),
            })
            .exec_without_returning(&txn)
            .await?;
        }
        signup_policy::Entity::insert(signup_policy::ActiveModel {
            id: Set(SINGLETON_ID),
            default_decision: Set(default.as_str().to_string()),
        })
        .on_conflict(
            OnConflict::column(signup_policy::Column::Id)
                .update_column(signup_policy::Column::DefaultDecision)
                .to_owned(),
        )
        .exec(&txn)
        .await?;
        txn.commit().await?;
        Ok(())
    }
}

/// Turns a stored row into the value type the CLI prints, or `None` for a row
/// this program never writes.
fn rule_from_row(row: signup_rule::Model) -> Option<Rule> {
    let decision = Decision::parse(&row.decision)?;
    let value = RuleValue::typed(RuleKind::parse(&row.kind)?, &row.value).ok()?;
    Some(Rule {
        number: row.number,
        decision,
        value,
    })
}
