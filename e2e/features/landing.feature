@landing
Feature: Landing page

  The public front door presents the product and offers the two account entry
  points: sign in and create account.

  Background:
    Given I open the landing page

  Scenario: The landing page presents the product and its calls to action
    Then I see the welcome heading "Your services, on the open web."
    And I see a link to "Create account"
    And I see a link to "Sign in"

  Scenario: Following the create-account call to action reaches the sign-up form
    When I follow the "Create account" call to action
    Then I see the "Create your account" heading

  Scenario: Following the sign-in call to action reaches the sign-in form
    When I follow the "Sign in" call to action
    Then I see the "Sign in" heading
