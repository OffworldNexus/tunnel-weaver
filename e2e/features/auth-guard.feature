@auth-guard
Feature: A signed-in person is kept out of the account-entry pages

  WVR-168: whoever already holds a session must never be shown a sign-in,
  sign-up or recovery page — every one of them sends them on to their console,
  and never spends a one-shot link on the way. A pending machine pairing is
  honoured: that visitor goes on to its confirmation instead.

  A signed-out visitor still gets the page they asked for.

  Background:
    Given a unique email address for "Ada Lovelace"

  Scenario: A signed-in visitor is sent to the console from every account-entry page
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I open the "sign-in" page
    Then I land on my console
    When I open the "sign-up" page
    Then I land on my console
    When I open the "forgot-password" page
    Then I land on my console
    When I open the "check-email" page
    Then I land on my console
    When I open the "verify" page
    Then I land on my console
    When I open the "set-password" page
    Then I land on my console
    When I open the "reset" page
    Then I land on my console
    When I open the "existing-account" page
    Then I land on my console

  Scenario: A signed-out visitor still sees each account-entry page
    When I open the "sign-in" page
    Then I see the "Sign in" heading
    When I open the "sign-up" page
    Then I see the "Create your account" heading
    When I open the "forgot-password" page
    Then I see the "Reset your password" heading

  Scenario: A signed-in visitor with a pending pairing goes on to its confirmation
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    And a pending pairing is seeded for the machine "laptop"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given a sign-in detour is pending
    When I open the "sign-in" page
    Then I see the "Approve a machine" heading
