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
    # WVR-167: the password is only the first factor. This journey now walks the
    # code step too — stopped at, refused, then accepted — so the second factor
    # is proven to be reached before the console rather than hidden in a helper.
    When I sign in with the password "correct-horse-battery-staple", without the code
    Then I see the "Enter your code" heading
    And exactly one "Your Tunnel Weaver sign-in code" email is sent
    When I submit a wrong code
    Then I see the error "That code is not right. Check it and try again."
    And I see the "Enter your code" heading
    When I enter the code from my email
    Then I see the signed-in identity for "Ada Lovelace"
    When I sign out
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    And the "Password" panel shows "Password is set"
    # WVR-167/WVR-166: the second factor is not a setting — the email block says
    # it is always on and offers no control that could turn it off, and the
    # authenticator apps have a block of their own.
    And the "Email codes" panel shows "Enabled · always on"
    And the "Authenticator apps" panel shows "No authenticator app yet"
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
  #
  # WVR-167: the gate is now two dialogs, the password step-up in front of the
  # confirmation, so this journey carries the step-up's refusals (a wrong
  # password, both ways of leaving it) and the renewal of `certain` that lets the
  # delete through. It lands its deletion the way the harness makes
  # deterministic: the open confirmation is handed back to the step-up by itself
  # the moment the console stops holding `certain` — no click, no refused submit
  # — and the delete then lands from the empty confirmation the password reopens.
  Scenario: Deleting my account from the Danger zone leaves nothing behind
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    # WVR-167: the harness's step-up window is 12 s and the relay reports a fall
    # 5 s before it happens, so the console stops holding `certain` about 7 s
    # after the sign-in. Waited for rather than assumed — the click below must
    # meet the password step-up, not an eager confirmation.
    Then the console holds my session as "strong"
    # WVR-167: leaving the step-up — both ways out — costs nothing: the dialogs
    # close, the console stays where it is, and the account is untouched.
    When I open the delete confirmation
    Then I am asked for my password first
    When I cancel the password step-up
    Then the delete flow is closed
    And the console holds my session as "strong"
    When I open the delete confirmation
    Then I am asked for my password first
    When I dismiss the password step-up with Escape
    Then the delete flow is closed
    # WVR-167: a wrong password is refused on its own field, the dialog stays
    # open, and the level the console holds does not move — a failed proof lifts
    # nothing.
    When I open the delete confirmation
    Then I am asked for my password first
    When I confirm the password "definitely-not-my-password"
    Then the password step-up reports "that is not your password" on its field
    And the password step-up is still open
    And the console holds my session as "strong"
    # WVR-167: the right password renews `certain` over the session stream, in
    # place — no reload — and that renewal is what opens the confirmation.
    When I confirm the password "correct-horse-battery-staple"
    Then confirming my password renews my session to "certain" without a reload
    And I see the "Delete your account?" heading
    Then the delete confirmation is locked
    When I type my email into the confirmation
    Then the delete confirmation is unlocked
    # WVR-167: the confirmation does not outlive the proof behind it. The console
    # holds `certain` for ~7 s after the step-up, and the moment it stops, the
    # open confirmation is handed back to the step-up by itself — no click, no
    # refused submit — and the confirmation the password reopens starts empty, so
    # the address is typed again and the delete lands inside the fresh window.
    When the console holds my session as "strong"
    Then I am asked for my password first
    And the delete confirmation is closed
    When I confirm the password "correct-horse-battery-staple"
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

  # WVR-163: a passkey is a whole way in. This journey registers one from the
  # Security tab — which lands while the sign-in's own `certain` is still fresh,
  # the proof registering asks for — takes both ways the sign-in page offers it
  # (the named button, then the field's autofill with nothing typed), then spends
  # the credential: removing it, and deleting the account while the passkey
  # sign-in's `certain` still holds, so that gate asks for no proof at all.
  Scenario: A passkey signs me in, and the account it protects deletes while that proof is fresh
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    When I add a passkey named "MacBook Pro"
    Then I see "Passkey added. It can sign you in on its own."
    And I see the passkey "MacBook Pro"
    And I see "never used"
    When I sign out
    Then I see the "Sign in" heading
    When I sign in with the passkey from the button
    Then I see the signed-in identity for "Ada Lovelace"
    When I sign out
    Then I see the "Sign in" heading
    And the sign-in field is ready to offer a passkey, and holds nothing
    When the passkey signs me in without a click
    Then I see the signed-in identity for "Ada Lovelace"
    # WVR-163: the passkey sign-in carries user verification, so the session it
    # opens is `certain` — which is why the deletion below meets no step-up. Read
    # while it is still held, as the level falls to `strong` on its own.
    And the console holds my session as "certain"
    When I follow the "Security" link
    Then I see the passkey "MacBook Pro"
    When I remove the passkey "MacBook Pro"
    Then I see "Passkey removed."
    And I see "No passkey yet"
    When I open the delete confirmation
    Then I see the "Delete your account?" heading
    And the delete confirmation is locked
    When I type my email into the confirmation
    Then the delete confirmation is unlocked
    When I confirm the deletion
    Then the deletion lands me signed out on the sign-in page
    And I see "Your account and all its data have been deleted."

  # WVR-163: the other half of the same step-up. The password's way through this
  # gate is the Danger-zone journey's; here the passkey answers it instead, on a
  # session that has lapsed to `strong` — the assertion is offered in the popin
  # beside the password form, and taking it renews `certain` in place.
  Scenario: A passkey answers the step-up in place of the password
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    When I follow the "Security" link
    Then I see the "Security" heading
    When I add a passkey named "MacBook Pro"
    Then I see the passkey "MacBook Pro"
    Then the console holds my session as "strong"
    When I open the delete confirmation
    Then I am asked for my password first
    And the password step-up offers the passkey as well
    When I take the passkey in place of the password
    Then I see the "Delete your account?" heading
    And the delete confirmation is locked
    When I type my email into the confirmation
    Then the delete confirmation is unlocked
    When I confirm the deletion
    Then the deletion lands me signed out on the sign-in page
    And I see "Your account and all its data have been deleted."

  # WVR-166: the authenticator-app lifecycle in one story — create a key, sign in
  # with it (and with nothing emailed), create another behind the password
  # step-up, delete the first without one, and sign in with what is left. The
  # code an app would show is computed locally from the Setup key the relay
  # spells out (`support/totp.js`), so the scenario is the app.
  Scenario: An authenticator app signs me in, and a second one can be added and removed alongside it
    Given an account exists for "Ada Lovelace" with the password "correct-horse-battery-staple"
    When I sign in with the password "correct-horse-battery-staple"
    Then I see the signed-in identity for "Ada Lovelace"
    # The first app, planted while the sign-in's own `certain` is still fresh —
    # the proof enrolling asks for, with no step-up in the way.
    When I follow the "Security" link
    Then I see the "Security" heading
    And the "Authenticator apps" panel shows "No authenticator app yet"
    When I open the add an authenticator app dialog
    Then the add an authenticator app dialog is open
    When I name the authenticator app "Phone" and continue
    Then the add an authenticator app dialog shows a setup key in text
    When I confirm the authenticator app "Phone" with a code it produced
    Then I see "Authenticator app added. It signs you in with a code."
    And I see the authenticator app "Phone"
    # WVR-163: a passkey on the same account. It is the chooser's third way, and
    # a way to finish a sign-in on its own — enrolled here, while the sign-in's
    # own `certain` is still fresh, exactly as the passkey scenario does.
    When I add a passkey named "MacBook Pro"
    Then I see the passkey "MacBook Pro"
    # Signing in again: the app is the factor offered, and no code is emailed.
    When I sign out
    Then I see the "Sign in" heading
    When the mailbox is emptied
    When I sign in with the password "correct-horse-battery-staple", without the code
    Then I see the "Enter your code" heading
    And the code page asks for the code from my authenticator app
    And the code page offers to try another way
    And the code page does not offer "Send a new code"
    And no sign-in code email is sent
    When I enter the code from my authenticator app "Phone"
    Then I see the signed-in identity for "Ada Lovelace"
    # A second app needs `certain`: the password step-up comes first, and the app
    # dialog is never stacked with it.
    When I follow the "Security" link
    Then the console holds my session as "strong"
    When I open the add an authenticator app dialog
    Then I am asked for my password first
    And the add an authenticator app dialog is not open
    When I confirm the password "correct-horse-battery-staple"
    Then the add an authenticator app dialog is open
    When I name the authenticator app "Tablet" and continue
    Then the add an authenticator app dialog shows a setup key in text
    When I confirm the authenticator app "Tablet" with a code it produced
    Then I see "Authenticator app added. It signs you in with a code."
    And I see the authenticator app "Phone"
    And I see the authenticator app "Tablet"
    # Removing one is not a `certain` action, and it is confirmed by typing the
    # app's name back.
    When I open the removal for the authenticator app "Phone"
    Then I am not asked for my password
    And the remove app keycap is locked
    When I type "Phone" into the removal
    Then the remove app keycap is unlocked
    When I confirm the removal of the authenticator app
    Then I see "Authenticator app removed."
    And I do not see the authenticator app "Phone"
    And I see the authenticator app "Tablet"
    # What is left still signs in — and this last pass takes the long way round
    # on purpose: the app's code is what the step asks for by default, "Try
    # another way" lists what the relay says the account can do, and picking the
    # emailed way is what sends a code.
    When I sign out
    Then I see the "Sign in" heading
    When the mailbox is emptied
    When I sign in with the password "correct-horse-battery-staple", without the code
    Then I see the "Enter your code" heading
    And the code page asks for the code from my authenticator app
    When I follow the "Try another way" link
    Then the chooser offers my authenticator app, my email address and my passkey
    When I choose the way "Code by email"
    Then the code page asks for the code from my email
    And the code page offers "Send a new code"
    When I enter the code from my email
    Then I see the signed-in identity for "Ada Lovelace"
    # WVR-163: and the passkey finishes a sign-in of its own — the assertion runs
    # in place from the chooser, with no code step in between.
    When I sign out
    Then I see the "Sign in" heading
    When I sign in with the password "correct-horse-battery-staple", without the code
    Then I see the "Enter your code" heading
    When I follow the "Try another way" link
    Then the chooser offers my authenticator app, my email address and my passkey
    When I take the passkey on the chooser
    Then I see the signed-in identity for "Ada Lovelace"
    And the code step is left behind
