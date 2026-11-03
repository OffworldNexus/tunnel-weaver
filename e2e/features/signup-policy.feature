@account
Feature: Who may create an account

  The relay can be closed to new sign-ups while leaving the accounts it already
  has untouched. The operator states one default decision and a list of addresses
  and domains that may open an account; a person gets in only where that policy
  says so. The suite starts each scenario with sign-ups open, so a scenario that
  needs the gate closed states the whole policy itself.

  Background:
    Given a unique email address for "Ada Lovelace"

  # WVR-98: the refusal is the gate, not a validation error — the same address
  # named by a rule on the next step goes the whole way. The email assertion
  # proves the refusal lands before a code is ever queued: a closed relay must
  # not mail the address it just turned away.
  Scenario: Sign-ups stay closed until the policy allows an address
    Given sign-ups are closed to everyone
    When I try to create an account for "Ada Lovelace"
    Then I see the sign-up refusal
    And no verification email is sent
    Given sign-ups are open only to my address
    When I create an account for "Ada Lovelace"
    Then I see the "Enter your code" heading
    When I enter the code from the verification email
    Then I see the "Set your password" heading
    When I set the password to "correct-horse-battery-staple"
    Then I see "Your account is active. Sign in to continue."

  # WVR-98: the other two ways a policy opens the relay, and the proof that
  # removing the rules closes it again. Each address is fresh, so the gate — not
  # an existing account — is what every refusal here reports.
  Scenario: The policy opens a domain or everyone, and clearing it closes them again
    Given a unique email address at "example.net" for "Grace Hopper"
    Given sign-ups are open only to the domain "example.net"
    When I create an account for "Grace Hopper"
    Then I see the "Enter your code" heading
    When I enter the code from the verification email
    Then I see the "Set your password" heading
    When I set the password to "correct-horse-battery-staple"
    Then I see "Your account is active. Sign in to continue."
    Given a unique email address for "Katherine Johnson"
    Given sign-ups are open to everyone
    When I create an account for "Katherine Johnson"
    Then I see the "Enter your code" heading
    When I enter the code from the verification email
    Then I see the "Set your password" heading
    When I set the password to "correct-horse-battery-staple"
    Then I see "Your account is active. Sign in to continue."
    # The domain rule that just worked is gone: a new address at example.net is
    # refused by the deny default, so the replacement really dropped the rules.
    Given a unique email address at "example.net" for "Mary Jackson"
    Given sign-ups are closed to everyone
    When I try to create an account for "Mary Jackson"
    Then I see the sign-up refusal

  # WVR-98: the gate is on account creation only. The account predates the
  # close, and both factors of its sign-in still work while the relay refuses
  # new sign-ups.
  Scenario: An account created before the policy closed still signs in
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    Given sign-ups are closed to everyone
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
