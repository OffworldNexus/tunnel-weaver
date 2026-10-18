@pairing
Feature: Pairing a machine to the relay

  A machine asks to be enrolled over its own channel; the person approves or
  rejects it in the browser. The handle naming the pending request is a
  capability: it rides in the URL fragment, is spent by the first verdict, and
  never reaches a query string, a request line or a `Referer`.

  A machine belongs to one person and holds one key. A new machine gets a name
  the person may edit; a machine that lost its key moves onto a new one with its
  name fixed.

  The terminal half (`weave pair`, `weave start`, Ctrl-C, the key floor) is
  CLI-only and lives in the Rust tests. Here the harness seeds a pending pairing,
  the scenario opens the link the CLI would have printed, and the harness reports
  what the terminal would have received.

  Background:
    Given a unique email address for "Ada Lovelace"

  # The fragment rule is asserted inside this journey rather than as a test of
  # its own: the page that strips the handle is the page this scenario is on.
  Scenario: Approving a seeded pairing and the handle never leaving the fragment
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given a pending pairing is seeded for the machine "laptop"
    When I open the pairing link from the fragment
    Then I see the "Approve a machine" heading
    And the confirmation proposes the machine "laptop" and a person slug
    And the pairing key fingerprint is shown
    And the address bar carries no pairing handle
    And no request carried the pairing handle
    When I approve the machine
    Then I see the "Machine approved" heading
    And the terminal is told it is paired as the machine "laptop"
    And I see a link to "Go to your account"
    When I follow the "Go to your account" link
    Then I see the signed-in identity for "Ada Lovelace"

  Scenario: Opening a pairing link while signed out returns to the confirmation after signing in
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    Given a pending pairing is seeded for the machine "laptop"
    When I open the pairing link from the fragment
    Then I see the "Sign in" heading
    And the address bar carries no pairing handle
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the "Approve a machine" heading
    And the confirmation proposes the machine "laptop" and a person slug

  # The sign-up form of the detour: someone with no account at all. The pending
  # pairing survives the whole registration, including a verification link that
  # may open in another tab, and the sign-in that ends it returns here.
  Scenario: Opening a pairing link with no account, then creating one, returns to the confirmation
    Given a pending pairing is seeded for the machine "laptop"
    When I open the pairing link from the fragment
    Then I see the "Sign in" heading
    When I follow the "Create an account" call to action
    And I create an account for "Ada Lovelace"
    Then I see the "Check your email" heading
    When I open the verification link from the latest email
    Then I see the "Set your password" heading
    When I set the password to "correct-horse-battery-staple"
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the "Approve a machine" heading
    And the confirmation proposes the machine "laptop" and a person slug
    When I approve the machine
    Then I see the "Machine approved" heading

  Scenario: Rejecting a pairing refuses the machine and spends the handle
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given a pending pairing is seeded for the machine "laptop"
    When I open the pairing link from the fragment
    Then I see the "Approve a machine" heading
    When I reject the machine
    Then I see the "Pairing rejected" heading
    And the terminal is told the pairing failed with "rejected"
    And I see the instruction to re-run "weave pair"
    And I see a link to "Go to your account"
    When I open the same pairing link again
    Then I see the "Request no longer waiting" heading

  # The browser-visible half of "Ctrl-C leaves nothing behind": a handle that was
  # never seeded renders the same dead state the channel's death produces.
  Scenario: An unknown pairing handle reports that the request is no longer waiting
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I open a pairing link for an unknown handle
    Then I see the "Request no longer waiting" heading
    And the address bar carries no pairing handle

  Scenario: A second machine joins the account's existing person
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given the machine "laptop" is paired
    And a pending pairing is seeded for the machine "desktop"
    When I open the pairing link from the fragment
    Then I see the "Approve a machine" heading
    And the confirmation proposes the machine "desktop" under the existing person
    When I approve the machine
    Then the terminal is told it is paired as the machine "desktop"

  Scenario: A machine that lost its key moves onto a new one and keeps its identity
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given the machine "laptop" is paired
    And "laptop" lost its key and asks to pair again
    When I open the pairing link from the fragment
    Then I see the "Move a machine to a new key" heading
    And the confirmation names "laptop" with nothing to edit
    And the pairing key fingerprint is shown
    When I move the machine to the new key
    Then I see the "Machine approved" heading
    And the terminal is told it is still the machine "laptop"

  Scenario: A request for someone else's machine can only be rejected
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    Given the machine "laptop" is paired
    When I sign out
    Given a unique email address for "Grace Hopper"
    And an account exists for "Grace Hopper" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Grace Hopper"
    Given "laptop" lost its key and asks to pair again
    When I open the pairing link from the fragment
    Then I see the "Not one of your machines" heading
    When I reject the machine
    Then the terminal is told the pairing failed with "rejected"
