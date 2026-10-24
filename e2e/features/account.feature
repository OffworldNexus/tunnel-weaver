@account
Feature: Account lifecycle

  A person creates an account, confirms their email, sets a password and signs
  in. The relay never reveals whether an address is already registered until the
  person has proven ownership of it.

  Background:
    Given a unique email address for "Ada Lovelace"

  Scenario: The full journey from landing through a password change to a fresh sign-in
    Given I open the "landing" page
    When I follow the "Create account" link
    And I create an account for "Ada Lovelace"
    Then I see the "Check your email" heading
    When I open the verification link from the latest email
    Then I see the "Set your password" heading
    And the verified email is shown as the account address
    When I set the password to "correct-horse-battery-staple"
    Then I see "Your account is active. Sign in to continue."
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I sign out
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    And the Password panel shows "Password is set"
    When I follow the "Change password" link
    Then I see the "Change your password" heading
    When I change my password from "correct-horse-battery-staple" to "correct-horse-battery-staple-2"
    Then I see "Your password has been changed. Sign in with your new password."
    And I am signed out everywhere, this device included
    When I sign in with the password "correct-horse-battery-staple-2"
    Then I see the signed-in identity for "Ada Lovelace"
    And the password change notification email is sent

  Scenario: Signing in with the wrong password is refused generically
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the wrong password "definitely-not-it"
    Then I see the error "invalid email or password"

  Scenario: Creating an account with an existing email does not disclose it before confirmation
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I open the "sign-up" page
    And I create an account for "Ada Lovelace"
    Then I see the "Check your email" heading
    When I open the verification link from the latest email
    Then I see the "You already have an account" heading

  Scenario: Requesting a reset link by email and signing in with the new password
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I follow the "Forgot password?" link
    And I request a reset link for my email
    Then I see the "Reset request accepted" heading
    And I see "If an account exists, we'll email instructions to reset your password."
    When I take the reset link from the latest email
    Then the reset link carries its token in the fragment, never the query string
    When I open the reset link
    Then I see the "Choose a new password" heading
    And the verified email is shown as the account address
    When I set the new password to "correct-horse-battery-staple-2"
    Then I see the "Sign in" heading
    And I see "Your password has been reset. Sign in with your new password."
    When I sign in with the password "correct-horse-battery-staple-2"
    Then I see the signed-in identity for "Ada Lovelace"
    # WVR-168: a signed-in visitor is sent off the auth pages, so the spent link
    # is only observable once signed out again.
    When I sign out
    When I open the reset link again
    Then I see the "Link expired or used" heading

  # The address has no account here: the acknowledgement must read exactly as
  # it does for one that has, and no mail may be sent.
  Scenario: Requesting a reset for an address without an account discloses nothing
    Given I open the "reset request" page
    When I request a reset link for my email
    Then I see the "Reset request accepted" heading
    And I see "If an account exists, we'll email instructions to reset your password."
    And no reset email is sent

  # A refused change keeps the session, unlike a successful one.
  Scenario: Changing the password with a wrong current password is refused on its field
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    And I follow the "Change password" link
    And I change my password from "definitely-not-my-password" to "correct-horse-battery-staple-2"
    Then the current password field reports "that is not your current password"
    When I open the "account" page
    Then I see the signed-in identity for "Ada Lovelace"

  # WVR-29: deletion really destroys its account, so this scenario registers one
  # of its own instead of borrowing the one the read-only journeys leave behind.
  # It walks the whole destructive journey: the Danger zone gate, the signed-out
  # landing with its notice, and the proof that nothing of the account survives.
  Scenario: Deleting my account from the Danger zone leaves nothing behind
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    When I open the delete confirmation
    Then the delete confirmation is locked
    When I type my email into the confirmation
    Then the delete confirmation is unlocked
    When I confirm the deletion
    Then the deletion lands me signed out on the sign-in page
    And I see "Your account and all its data have been deleted."
    And the old session no longer authenticates
    And the browser holds no account cookie
    When I sign in with the wrong password "correct-horse-battery-staple"
    Then I see the error "invalid email or password"
