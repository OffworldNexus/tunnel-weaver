@account
Feature: Account lifecycle

  A person creates an account, confirms their email, sets a password and signs
  in. The relay never reveals whether an address is already registered until the
  person has proven ownership of it.

  Background:
    Given a unique email address for "Ada Lovelace"

  Scenario: The full happy path from landing to a second sign-in
    Given I open the landing page
    When I follow the "Create account" call to action
    And I create an account for "Ada Lovelace"
    Then I see the "Check your email" heading
    When I open the verification link from the latest email
    Then I see the "Set your password" heading
    And the verified email is shown as the account address
    When I set the password to "correct-horse-battery-staple"
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I sign out
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"

  Scenario: Signing in with the wrong password is refused generically
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the wrong password "definitely-not-it"
    Then I see the sign-in error "invalid email or password"

  Scenario: Creating an account with an existing email does not disclose it before confirmation
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I open the sign-up page
    And I create an account for "Ada Lovelace"
    Then I see the "Check your email" heading
    When I open the verification link from the latest email
    Then I see the "You already have an account" heading

  # WVR-41: the password-reset round trip. Both scenarios sit here because they
  # start from the same per-scenario unique address the Background seeds: the
  # first gives it an account, the second deliberately does not, and both walk
  # the same `/forgot-password` request path.
  Scenario: Requesting a reset link by email and signing in with the new password
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I follow the "Forgot password?" link from the sign-in page
    Then I see the "Reset your password" heading
    When I request a reset link for my email
    Then I see the "Reset request accepted" heading
    And I see the acknowledgement that instructions will be emailed
    When I take the reset link from the latest email
    Then the reset link carries its token in the fragment, never the query string
    When I open the reset link
    Then I see the "Choose a new password" heading
    And the verified email is shown as the account address
    When I set the new password to "correct-horse-battery-staple-2"
    Then I see the "Sign in" heading
    And I see the reset success notice
    When I sign in with the password "correct-horse-battery-staple-2"
    Then I see the signed-in identity for "Ada Lovelace"
    When I open the same reset link again
    Then I see the "Link expired or used" heading

  # WVR-41: the enumeration-safe half. The Background's address has no account
  # here, so this proves the relay's acceptance screen and its copy are identical
  # to the happy path's — and that no mail is sent.
  Scenario: Requesting a reset for an address without an account discloses nothing
    Given I open the reset request page
    When I request a reset link for my email
    Then I see the "Reset request accepted" heading
    And I see the acknowledgement that instructions will be emailed
    And no reset email is sent
