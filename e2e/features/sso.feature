@sso
Feature: Signing in with an external identity provider

  A person signs up or signs in with an identity they already hold elsewhere.
  The relay runs the flow itself, resolves the identity to an account (creating
  one on the spot when it is new), and never trusts an address the provider does
  not vouch for.

  Background:
    Given a unique email address for "Ada Lovelace"

  Scenario: An unknown provider identity signs itself up and settles its address
    Given I open the "sign-in" page
    And the fake provider does not vouch for the address
    When I sign in with the fake provider
    Then I see the "Enter your code" heading
    When I enter the address-verification code
    Then I see the signed-in identity for "Ada Lovelace"

  Scenario: A provider that vouches for the address still asks for a second factor
    Given I open the "sign-in" page
    And the fake provider vouches for the address
    When I sign in with the fake provider
    Then I see the "Enter your code" heading
    When I enter the code from my email
    Then I see the signed-in identity for "Ada Lovelace"

  Scenario: An unverified address never takes over an existing account
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I open the "sign-in" page
    And a stranger claims my address through the fake provider
    And I sign in with the fake provider
    Then I see the error "That account has no usable email address, or the address belongs to another account."
