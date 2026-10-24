@landing
Feature: Landing page

  The public front door presents the product and offers the two account entry
  points: sign in and create account.

  Background:
    Given I open the "landing" page

  Scenario: The landing page presents the product and its calls to action
    Then I see the "Your services, on the open web." heading
    And I see a link to "Create account"
    And I see a link to "Sign in"

  Scenario: Following the create-account call to action reaches the sign-up form
    When I follow the "Create account" link
    Then I see the "Create your account" heading

  Scenario: Following the sign-in call to action reaches the sign-in form
    When I follow the "Sign in" link
    Then I see the "Sign in" heading

  # WVR-168: the front door recognises a signed-in visitor and offers the
  # console instead of asking them to sign in again.
  Scenario: A signed-in visitor is offered their console instead of the sign-in calls to action
    Given a unique email address for "Ada Lovelace"
    And an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I open the "landing" page
    Then I see a link to "Open your console"
    And I do not see a link to "Sign in"
    And I do not see a link to "Create account"
    And I see "Your machines, tunnels and traffic are waiting in the console."
