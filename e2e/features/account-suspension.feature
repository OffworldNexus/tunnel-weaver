@account
Feature: Suspending an account

  The operator can ban an account from the relay's CLI. A ban is immediate and
  total: whichever session is open dies where it stands, and every way in —
  password, passkey, provider — answers the same fixed sentence from the moment
  the person has proved who they are, and never before. Lifting the ban puts the
  account back the way it was.

  The ban itself is driven through the harness's own endpoint (see
  `support/harness.js`): the CLI is a control-socket client and the suite has no
  socket, so `PUT /account-state` calls the same daemon-side `Suspension` handle
  the control server does.

  Background:
    Given a unique email address for "Ada Lovelace"
    And an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"

  # WVR-178: the ban is pushed, never polled. After the operator's call nothing
  # is clicked and nothing is reloaded, so a console that leaves on its own can
  # only be following the session stream. The existing "signed out everywhere"
  # assertion then shows the cookie behind the page is dead too, rather than the
  # tab having merely forgotten it.
  Scenario: Banning an account signs its open console out on the spot
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When the operator bans my account with the reason "operator-secret-reason"
    Then the console signs me out on its own
    And I am signed out everywhere, this device included
    And the reason the operator recorded is never shown

  # WVR-178: the refusal arrives after the password is proved, which is what
  # keeps the ban from telling a stranger the address exists. The sentence is the
  # relay's one fixed line, and the operator's note never travels with it.
  Scenario: A banned account is refused after the password is proved
    When the operator bans my account with the reason "operator-secret-reason"
    And I submit the password "correct-horse-battery-staple"
    Then I see the suspension refusal
    And the reason the operator recorded is never shown

  # WVR-178: a provider sign-in discloses nothing on the way out — the page is
  # untouched until the callback runs — and the callback ends on the sign-in page
  # carrying the same sentence. Nothing opens a session on the way.
  Scenario: A provider sign-in for a banned account is refused only on the callback
    Given I open the "sign-in" page
    And the fake provider vouches for the address
    When the operator bans my account with the reason "operator-secret-reason"
    Then I do not see the suspension refusal
    When I sign in with the fake provider
    Then I see the suspension refusal
    And the reason the operator recorded is never shown

  # WVR-178: the ban is a state, not a deletion. Lifting it needs no new
  # credentials and no re-registration: the same password walks the whole way in
  # again.
  Scenario: Lifting the ban lets the account sign in again
    When the operator bans my account with the reason "operator-secret-reason"
    And I submit the password "correct-horse-battery-staple"
    Then I see the suspension refusal
    When the operator lifts the ban on my account
    And I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
