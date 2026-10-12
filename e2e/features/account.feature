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
