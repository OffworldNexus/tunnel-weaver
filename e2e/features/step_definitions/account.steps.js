/** Account-lifecycle steps: sign-up, password reset and password change. */

import { Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import {
  clearMail,
  latestMailBySubject,
  latestMailLink,
  mailCount,
  mailLinks,
  poll
} from '../support/harness.js';
import {
  SIGN_IN_CODE_SUBJECT,
  createAccount,
  openVerificationLink,
  press,
  setPassword
} from '../support/flow.js';
import { totpCode } from '../support/totp.js';

const RESET_LINK = /https:\/\/localhost:\d+\/reset#token=[0-9a-f]+/g;

When('I create an account for {string}', async function (name) {
  await createAccount(this, name);
});

When('I open the verification link from the latest email', async function () {
  await openVerificationLink(this);
});

When('I set the password to {string}', async function (password) {
  await setPassword(this, password);
});

// ----- password reset --------------------------------------------------------

When('I request a reset link for my email', async function () {
  await assert.seeHeading(this.page, 'Reset your password');
  await this.page.getByLabel('Email', { exact: true }).fill(this.email);
  await press(this, 'Send reset link');
});

When('I take the reset link from the latest email', async function () {
  this.resetLink = await latestMailLink(RESET_LINK);
});

Then('the reset link carries its token in the fragment, never the query string', function () {
  const url = new URL(this.resetLink);
  if (url.pathname !== '/reset' || url.search !== '' || !/^#token=[0-9a-f]+$/.test(url.hash)) {
    throw new Error(`Expected "<base>/reset#token=…", but the link was "${this.resetLink}".`);
  }
});

When('I open the reset link( again)', async function () {
  await this.page.goto(this.resetLink);
});

When('I set the new password to {string}', async function (password) {
  await assert.seeHeading(this.page, 'Choose a new password');
  await this.page.getByLabel('New password', { exact: true }).fill(password);
  await press(this, 'Reset password');
});

Then('no reset email is sent', async function () {
  // The reset mail is sent off the response path: give an absent send time to
  // show up before concluding there is none.
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  const links = await mailLinks(RESET_LINK);
  if (links.length > 0) throw new Error(`Expected no reset email, but got: ${links.join(', ')}`);
});

// WVR-167: arriving at the code step asks the relay for a code. The cooldown
// makes that a no-op right after the password step, so a normal sign-in must
// leave exactly one code email — a second one means the arrival send duplicated.
Then('exactly one {string} email is sent', async function (subject) {
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  const count = await mailCount(subject);
  if (count !== 1) {
    throw new Error(`Expected exactly one ${JSON.stringify(subject)} email, but the mailbox holds ${count}.`);
  }
});

// ----- password change -------------------------------------------------------

When('I change my password from {string} to {string}', async function (current, next) {
  await assert.seeHeading(this.page, 'Change your password');
  await this.page.getByLabel('Current password', { exact: true }).fill(current);
  await this.page.getByLabel('New password', { exact: true }).fill(next);
  await press(this, 'Change password');
});

// One step for any of the Security page's panels: each is an accessible region
// named by its title, so the assertion is the same wherever it is pointed.
Then('the {string} panel shows {string}', async function (panel_name, state) {
  const panel = this.page.getByRole('region', { name: panel_name, exact: true });
  await panel.getByText(state).waitFor();
});

Then('the current password field reports {string}', async function (text) {
  const field = this.page.getByLabel('Current password', { exact: true });
  await assert.seeAlert(this.page, text);
  if ((await field.getAttribute('aria-invalid')) !== 'true') {
    throw new Error('Expected the current password field to be marked invalid.');
  }
  const describedBy = await field.getAttribute('aria-describedby');
  const description = describedBy ? await this.page.locator(`#${describedBy}`).innerText() : '';
  if (!description.includes(text)) {
    throw new Error(`Expected the current password field to be described by "${text}", got "${description}".`);
  }
});

Then('I am signed out everywhere, this device included', async function () {
  await this.open('/app');
  await this.page.waitForURL(/\/sign-in$/);
  await assert.seeHeading(this.page, 'Sign in');
});

Then('the password change notification email is sent', async function () {
  await latestMailBySubject('Your password was changed');
});

// ----- account deletion (WVR-29, WVR-167) ------------------------------------

/** The Danger-zone keycap, never the confirm keycap inside a dialog. */
function dangerButton(page) {
  return page
    .getByRole('region', { name: 'Danger zone' })
    .getByRole('button', { name: 'Delete account', exact: true });
}

/** The delete confirmation dialog (WVR-29). */
function deleteDialog(page) {
  return page.getByRole('dialog', { name: 'Delete your account?' });
}

/** The confirm keycap inside the open dialog, never the Danger-zone opener. */
function confirmButton(page) {
  return deleteDialog(page).getByRole('button', { name: 'Delete account', exact: true });
}

/**
 * The password step-up popin (WVR-167): the gate in front of the confirmation
 * whenever the console is not holding `certain` — which this harness reaches a
 * few seconds after a sign-in or a step-up, so the journey waits for it.
 */
function passwordDialog(page) {
  return page.getByRole('dialog', { name: 'Confirm your password' });
}

/**
 * The level the console *holds* right now (WVR-167).
 *
 * The stream reports the level to hold, not the relay's own: a fall inside the
 * relay's 5-second lead arrives already reported, so `strong` read here means the
 * console has stopped trusting `certain`, seconds before the relay would refuse a
 * `certain` action. That is the level every guard in the console reads, so it is
 * the level a test has to read too.
 *
 * Read from inside the page, so the session cookie is the real one — the way
 * `machine.steps.js` reads a stream — with the two differences
 * `/api/account/me` forces: its frames are named `state` rather than unnamed,
 * and each read opens its own connection, whose first frame is the state at that
 * instant. That last part is what makes a fall observable without waiting on a
 * push.
 */
async function currentLevel(page) {
  return page.evaluate(
    () =>
      new Promise((resolve, reject) => {
        const source = new EventSource('/api/account/me');
        const timer = setTimeout(() => {
          source.close();
          reject(new Error('The session stream sent no state frame.'));
        }, 5_000);
        source.addEventListener('state', (event) => {
          clearTimeout(timer);
          source.close();
          resolve(JSON.parse(event.data).level);
        });
        source.onerror = () => {
          clearTimeout(timer);
          source.close();
          reject(new Error('The session stream errored.'));
        };
      })
  );
}

/** Polls the stream until the level the console holds is `level`. */
async function waitForLevel(world, level) {
  let seen = '';
  await poll(
    async () => {
      seen = await currentLevel(world.page);
      return seen === level ? true : undefined;
    },
    () => `The console never held "${level}"; the stream last said "${seen}".`,
    { timeoutMs: 15_000, everyMs: 200 }
  );
}

// WVR-167: once the console has stopped holding `certain` — which the journey
// waits for before this, since the relay reports a fall seconds early — the
// Danger-zone keycap opens the password step-up, and the confirmation only
// follows it. The marker is set before the click so the flow can prove it never
// reloaded the page: a navigation would wipe the window.
When('I open the delete confirmation', async function () {
  await this.page.evaluate(() => {
    window.__liveProbe = 'kept';
  });
  await dangerButton(this.page).click();
});

// ----- the password step-up (WVR-167) ----------------------------------------

Then('I am asked for my password first', async function () {
  await passwordDialog(this.page).waitFor({ state: 'visible' });
  await assert.seeHeading(this.page, 'Confirm your password');
});

When('I confirm the password {string}', async function (password) {
  const dialog = passwordDialog(this.page);
  await dialog.getByLabel('Password', { exact: true }).fill(password);
  await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
});

// The same three parts the change-password refusal is held to: the alert on the
// field, `aria-invalid`, and the field described by the message — the refusal is
// answered where the mistake was made, not in a dialog that closed.
Then('the password step-up reports {string} on its field', async function (text) {
  const dialog = passwordDialog(this.page);
  const field = dialog.getByLabel('Password', { exact: true });
  await dialog.getByRole('alert').filter({ hasText: text }).waitFor({ state: 'visible' });
  if ((await field.getAttribute('aria-invalid')) !== 'true') {
    throw new Error('Expected the password field to be marked invalid.');
  }
  const describedBy = await field.getAttribute('aria-describedby');
  const description = describedBy ? await dialog.locator(`#${describedBy}`).innerText() : '';
  if (!description.includes(text)) {
    throw new Error(`Expected the password field to be described by "${text}", got "${description}".`);
  }
});

Then('the password step-up is still open', async function () {
  await passwordDialog(this.page).waitFor({ state: 'visible' });
});

When('I cancel the password step-up', async function () {
  const dialog = passwordDialog(this.page);
  await dialog.getByRole('button', { name: 'Cancel', exact: true }).click();
});

When('I dismiss the password step-up with Escape', async function () {
  await passwordDialog(this.page).waitFor({ state: 'visible' });
  await this.page.keyboard.press('Escape');
});

// Nothing is left of the flow: both dialogs gone, and the console still where it
// was — a cancelled step-up ends where it started, account and session intact.
Then('the delete flow is closed', async function () {
  await passwordDialog(this.page).waitFor({ state: 'hidden' });
  await deleteDialog(this.page).waitFor({ state: 'hidden' });
  await assert.seeHeading(this.page, 'Security');
});

// WVR-167: `certain` is renewed over the session stream, and the renewal has to
// land in place — the confirmation the person is about to fill in lives in this
// document.
Then('confirming my password renews my session to {string} without a reload', async function (level) {
  await waitForLevel(this, level);
  const probe = await this.page.evaluate(() => window.__liveProbe);
  if (probe !== 'kept') {
    throw new Error('The page reloaded during the step-up; the renewal must land in place.');
  }
});

Then('the console holds my session as {string}', async function (level) {
  await waitForLevel(this, level);
});

// The gate is convenience only — the relay re-checks the address — but a locked
// keycap is what stops a stray click, so both halves are asserted here.
Then('the delete confirmation is locked', async function () {
  const button = confirmButton(this.page);
  await button.waitFor({ state: 'visible' });
  if (!(await button.isDisabled())) {
    throw new Error('The delete confirmation was unlocked before the address was typed.');
  }
});

When('I type my email into the confirmation', async function () {
  // The accessible name embeds the address ("Type ada@example.com to confirm:"),
  // so the label is matched by its tail and scoped to the open dialog.
  await deleteDialog(this.page).getByLabel(/to confirm:$/).fill(this.email);
});

Then('the delete confirmation is unlocked', async function () {
  const button = confirmButton(this.page);
  await poll(
    async () => (!(await button.isDisabled()) ? true : undefined),
    () => 'The delete confirmation never unlocked after the account address was typed in.'
  );
});

When('I confirm the deletion', async function () {
  await confirmButton(this.page).click();
});

// WVR-167: the confirmation does not outlive the proof behind it — the open
// confirmation is handed back to the step-up the moment the console stops
// holding `certain`, so this asserts it is gone by the time the password is
// asked for again.
Then('the delete confirmation is closed', async function () {
  await deleteDialog(this.page).waitFor({ state: 'hidden' });
});

Then('the deletion lands me signed out on the sign-in page', async function () {
  await this.page.waitForURL(/\/sign-in$/);
  await assert.seeHeading(this.page, 'Sign in');
});

Then('the old session no longer authenticates', async function () {
  // The session stream answers anyone; for no session it sends one `none`
  // state and ends, so the whole body can be read.
  const level = await this.page.evaluate(async () => {
    const body = await (await fetch('/api/account/me')).text();
    const data = body.split('\n').find((line) => line.startsWith('data: '));
    return data ? JSON.parse(data.slice('data: '.length)).level : '';
  });
  if (level !== 'none') {
    throw new Error(`Expected the session stream to say "none" for the deleted session, got "${level}".`);
  }
});

Then('the browser holds no account cookie', async function () {
  const stale = (await this.context.cookies()).filter((cookie) =>
    ['__Host-weaver_session', '__Host-weaver_csrf'].includes(cookie.name)
  );
  if (stale.length > 0) {
    throw new Error(
      `Expected both account cookies to be cleared, but found: ${stale.map((c) => c.name).join(', ')}.`
    );
  }
});

// ----- passkeys (WVR-163) ----------------------------------------------------
//
// A passkey is a whole way in: one gesture, no password and no emailed code.
// Every ceremony here needs the scenario's virtual authenticator to be present
// (`World#present`), and stands presence down again the moment the screen the
// ceremony ends on is reached: the sign-in page starts a *conditional* ceremony
// of its own on load, and a present authenticator would complete that one for
// whoever asked next.

/** The Passkeys panel on the Security page. */
function passkeyPanel(page) {
  return page.getByRole('region', { name: 'Passkeys', exact: true });
}

/** One passkey's row, told apart from its siblings by its name. */
function passkeyRow(page, name) {
  return passkeyPanel(page).getByRole('listitem').filter({ hasText: name });
}

When('I add a passkey named {string}', async function (name) {
  await passkeyPanel(this.page).getByRole('button', { name: /Add a passkey/ }).click();
  const dialog = this.page.getByRole('dialog', { name: 'Add a passkey' });
  await dialog.getByLabel(/Name/).fill(name);
  await this.present(true);
  await this.page.getByRole('button', { name: /Create passkey/ }).click();
  // The dialog closing is the ceremony's own success signal — the toast and the
  // reloaded list both follow it, and either is what the feature asserts on.
  await this.page.getByRole('dialog', { name: 'Add a passkey' }).waitFor({ state: 'hidden' });
  await this.present(false);
});

Then('I see the passkey {string}', async function (name) {
  await passkeyRow(this.page, name).waitFor({ state: 'visible' });
});

// WVR-163: the named button — the way in for a browser that did not offer the
// passkey in the field's autofill. The page's own autofill ceremony is pending
// from load; the click stands it down and issues a modal one of its own.
// Presence is turned on *after* the click, never before: with an authenticator
// already present, the field's own ceremony would answer first and sign the
// person in before the button could be pressed at all.
When('I sign in with the passkey from the button', async function () {
  await assert.seeHeading(this.page, 'Sign in');
  await this.page.getByRole('button', { name: /Sign in with a passkey/ }).click();
  await this.present(true);
  await assert.seeHeading(this.page, 'Overview');
  await this.present(false);
});

// WVR-163: the conditional-UI half. The field carries `username webauthn`, the
// ceremony starts on page load, and a field nobody has typed into is the whole
// point: the passkey is picked out of autofill, not typed for.
Then('the sign-in field is ready to offer a passkey, and holds nothing', async function () {
  await assert.seeHeading(this.page, 'Sign in');
  const field = this.page.getByLabel('Email', { exact: true });
  if ((await field.inputValue()) !== '') {
    throw new Error('The email field is not empty: autofill must sign in with nothing typed.');
  }
  const autocomplete = await field.getAttribute('autocomplete');
  if (autocomplete !== 'username webauthn') {
    throw new Error(`Expected an autofill-ready email field, but its autocomplete is "${autocomplete}".`);
  }
  await assert.seeText(this.page, 'No password, no emailed code');
});

When('the passkey signs me in without a click', async function () {
  // Headless Chrome has no autofill UI to click, so an authenticator that is
  // present answers the page's own ceremony the moment the page loads: nothing
  // typed, nothing clicked, and the person lands signed in.
  await this.present(true);
  await this.open('/sign-in');
  await assert.seeHeading(this.page, 'Overview');
  await this.present(false);
});

When('I remove the passkey {string}', async function (name) {
  await passkeyRow(this.page, name).getByRole('button', { name: /Remove/ }).click();
  const dialog = this.page.getByRole('dialog', { name: 'Remove this passkey?' });
  await dialog.getByLabel(/Type/).fill(name);
  await dialog.getByRole('button', { name: /Remove passkey/ }).click();
});

// WVR-163: the popin offers the assertion beside the password form. The relay
// names `assert_passkey` among the ways up exactly when the account holds a
// passkey, so the offer being there at all is the server's answer, not the
// console's guess.
Then('the password step-up offers the passkey as well', async function () {
  const dialog = passwordDialog(this.page);
  await dialog.getByRole('button', { name: 'Confirm', exact: true }).waitFor({ state: 'visible' });
  await dialog.getByRole('button', { name: 'use a passkey' }).waitFor({ state: 'visible' });
});

When('I take the passkey in place of the password', async function () {
  const dialog = passwordDialog(this.page);
  await dialog.getByRole('button', { name: 'use a passkey' }).click();
  await this.present(true);
  await this.page.getByRole('dialog', { name: 'Delete your account?' }).waitFor({ state: 'visible' });
  await this.present(false);
});

// ----- authenticator apps (WVR-166) ------------------------------------------
//
// An app is a second factor that works without the mailbox: enrolling one is a
// `certain` action (so the password step-up comes first, exactly as it does for
// a passkey or a deletion), sign-in then offers the app instead of emailing a
// code, and removing one is ordinary authenticated work confirmed by naming it.
// The code an app would show is computed locally (`support/totp.js`), from the
// Setup key the relay spelled out — the scenario is the app. Everything else the
// session can do lives behind "Try another way", and is the relay's own answer
// (the ways up it reports) rather than the console's guess.

/** The Authenticator apps panel on the Security page. */
function appPanel(page) {
  return page.getByRole('region', { name: 'Authenticator apps', exact: true });
}

/**
 * One app's row. Its accessible name is `label + ' ' + meta`, and the meta
 * carries a live relative time ("last used just now" → "19s ago"), so only the
 * name's stable prefix is matched.
 */
function appRow(page, name) {
  const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return appPanel(page).getByRole('listitem', { name: new RegExp(`^${escaped} `) });
}

/** The enrolment dialog — never the password step-up, never a removal. */
function appDialog(page) {
  return page.getByRole('dialog', { name: 'Add an authenticator app' });
}

/** The removal confirmation for an app. */
function removeAppDialog(page) {
  return page.getByRole('dialog', { name: 'Remove this authenticator app?' });
}

/** Its confirm keycap, locked until the app's name is typed back. */
function removeAppButton(page) {
  return removeAppDialog(page).getByRole('button', { name: 'Remove app', exact: true });
}

/** Opens the enrolment: on a fresh `certain` the dialog follows with no step-up. */
When('I open the add an authenticator app dialog', async function () {
  await this.page.getByRole('button', { name: 'Add an authenticator app' }).click();
});

Then('the add an authenticator app dialog is open', async function () {
  await appDialog(this.page).waitFor({ state: 'visible' });
});

// WVR-166: the confirmation must not appear before the proof it needs is held,
// so while the step-up asks for the password the dialog is not open at all.
Then('the add an authenticator app dialog is not open', async function () {
  if (await appDialog(this.page).isVisible()) {
    throw new Error('The app dialog must not be open while the step-up asks for the password.');
  }
});

// The name is the label the authenticator app displays, and the URI the QR
// carries is built once — so it is collected before the key is shown, not after.
When('I name the authenticator app {string} and continue', async function (name) {
  const dialog = appDialog(this.page);
  await dialog.getByLabel('Name', { exact: true }).fill(name);
  await dialog.getByRole('button', { name: 'Continue', exact: true }).click();
  // The key only exists once the relay has begun the enrolment, and reading it
  // here is what lets the code be computed from what the person was shown.
  const key = dialog.getByLabel('Setup key');
  await key.waitFor({ state: 'visible' });
  const secret = (await key.innerText()).trim();
  if (!secret) throw new Error('The enrolment dialog showed no setup key.');
  this.appSecrets[name] = secret;
});

Then('the add an authenticator app dialog shows a setup key in text', async function () {
  const key = appDialog(this.page).getByLabel('Setup key');
  await key.waitFor({ state: 'visible' });
  const secret = (await key.innerText()).trim();
  if (secret.length < 8) {
    throw new Error(`Expected a setup key in the dialog, but it read ${JSON.stringify(secret)}.`);
  }
});

// Confirmations use the *current* step: the code is the one an app would show
// now. Sign-ins use the next one (see below), because this is where the step is
// spent — the relay remembers it, and the same code is then refused.
When('I confirm the authenticator app {string} with a code it produced', async function (name) {
  const secret = this.appSecrets[name];
  if (!secret) throw new Error(`No setup key was read for the authenticator app ${JSON.stringify(name)}.`);
  const dialog = appDialog(this.page);
  await dialog.getByLabel('Code from the app').fill(totpCode(secret));
  await dialog.getByRole('button', { name: 'Confirm', exact: true }).click();
  // The dialog closing is the enrolment's own success signal; the toast and the
  // reloaded list both follow it, and either is what the feature asserts on.
  await dialog.waitFor({ state: 'hidden' });
});

Then('I see the authenticator app {string}', async function (name) {
  await appRow(this.page, name).waitFor({ state: 'visible' });
});

Then('I do not see the authenticator app {string}', async function (name) {
  // The list is re-read from the relay after a removal, so its going is polled
  // rather than assumed.
  await poll(
    async () => ((await appRow(this.page, name).count()) === 0 ? true : undefined),
    () => `The authenticator app ${JSON.stringify(name)} is still listed.`
  );
});

// ----- the app is the factor offered, and nothing is emailed (WVR-166) -------

Then('the code page asks for the code from my authenticator app', async function () {
  await assert.seeHeading(this.page, 'Enter your code');
  await assert.seeText(this.page, 'Enter the six-digit code your authenticator app shows for');
});

// One keycap whose name depends on the state: the code step's own secondary
// actions. "Send a new code" belongs to the emailed factor alone; the way to
// everything else is the chooser, whose keycap is a link (`Keycap href`), not a
// button.
Then('the code page offers {string}', async function (label) {
  await this.page.getByRole('button', { name: label, exact: true }).waitFor({ state: 'visible' });
});

Then('the code page does not offer {string}', async function (label) {
  const count = await this.page.getByRole('button', { name: label, exact: true }).count();
  if (count !== 0) {
    throw new Error(`The code page offered ${JSON.stringify(label)} at ${this.page.url()}.`);
  }
});

Then('the code page offers to try another way', async function () {
  await this.page
    .getByRole('link', { name: 'Try another way', exact: true })
    .waitFor({ state: 'visible' });
});

Then('the code page asks for the code from my email', async function () {
  await assert.seeHeading(this.page, 'Enter your code');
  await assert.seeText(this.page, 'We emailed a six-digit code to');
});

// ----- "try another way": the other factors the relay reports (WVR-166) -------

// The chooser lists the session's ways up, in the relay's own preference order.
// With an app and a passkey on the account that is the app's code, the emailed
// one (naming the address the code would go to), and the passkey last — which is
// what keeps the passkey from ever being the default (the relay's `PATHS` order:
// `AuthenticatorPath` first, `PasskeyPath` last).
Then('the chooser offers my authenticator app, my email address and my passkey', async function () {
  await assert.seeHeading(this.page, 'Try another way');
  // The appended row is what proves the relay listed the passkey at all; the
  // reads below then hold the whole offer to that order. Scoped to the ways list
  // on purpose: the root layout's toast viewport also holds buttons, and a
  // console toast can still be on screen this far into a sign-in.
  await this.page.getByRole('button', { name: 'A passkey' }).waitFor({ state: 'visible' });
  const ways = this.page
    .getByRole('list')
    .filter({ has: this.page.getByRole('button', { name: 'A passkey' }) })
    .getByRole('button');
  const labels = (await ways.allInnerTexts()).map((text) => text.split('\n')[0].trim());
  const wanted = ['Code from your authenticator app', 'Code by email', 'A passkey'];
  if (labels.join(' | ') !== wanted.join(' | ')) {
    throw new Error(`Expected the ways up in the relay's order, got: ${JSON.stringify(labels)}.`);
  }
  await assert.seeText(this.page, `We will send a six-digit code to ${this.email}.`);
  await assert.seeText(this.page, 'Use your face, fingerprint, PIN or a security key.');
});

// The whole row is the button, so its accessible name is the label and the detail
// together: the choice is matched on the label's prefix, never the whole string.
// Picking the emailed way is also what sends the code.
When('I choose the way {string}', async function (label) {
  await this.page.getByRole('button', { name: label }).click();
});

// WVR-163/166: the passkey row runs the assertion *in place* — no popin, no code
// step — and the console is what it lands on. Presence is turned on after the
// click, as the sign-in page's own conditional ceremony is pending from load and
// a present authenticator would answer that one instead.
When('I take the passkey on the chooser', async function () {
  await this.page.getByRole('button', { name: 'A passkey' }).click();
  await this.present(true);
  await assert.seeHeading(this.page, 'Overview');
  await this.present(false);
});

// A finished sign-in must not leave the half-way screen behind it: the assertion
// ends on the console, so the code step and the chooser are gone with it.
Then('the code step is left behind', async function () {
  await this.page.waitForURL(/\/app$/);
  const stale = await this.page
    .getByRole('heading', { name: 'Enter your code', exact: true })
    .count();
  if (stale !== 0) {
    throw new Error('The code step is still on the page after the sign-in finished.');
  }
});

// The mailbox is emptied first, so "nothing was emailed" is an exact count and
// not a delta: the registration and the earlier sign-in have already left mail.
When('the mailbox is emptied', async function () {
  await clearMail();
});

Then('no sign-in code email is sent', async function () {
  // The send would be off the response path; give an absent one time to appear
  // before concluding there is none.
  await new Promise((resolve) => setTimeout(resolve, 3_000));
  const count = await mailCount(SIGN_IN_CODE_SUBJECT);
  if (count !== 0) {
    throw new Error(`Expected no sign-in code email, but the mailbox holds ${count}.`);
  }
});

When('I enter the code from my authenticator app {string}', async function (name) {
  const secret = this.appSecrets[name];
  if (!secret) throw new Error(`No setup key was read for the authenticator app ${JSON.stringify(name)}.`);
  // WVR-166: a code is single use, and confirming an app burnt the step it used,
  // so the sign-in asks for the *next* step. The relay accepts one step either
  // side of now, and the confirming step is always ≤ now — which makes now + 30 s
  // strictly ahead of it and still inside the window. Nothing is waited for.
  const next = totpCode(secret, { at: Date.now() + 30_000 });
  await this.page.getByLabel('Code', { exact: true }).fill(next);
  await press(this, 'Continue');
});

// ----- removing one (WVR-166) ------------------------------------------------

When('I open the removal for the authenticator app {string}', async function (name) {
  await appRow(this.page, name)
    .getByRole('button', { name: `Remove ${name}`, exact: true })
    .click();
  await removeAppDialog(this.page).waitFor({ state: 'visible' });
});

// Removal takes a way in away but loses nothing the password does not still
// give, so it is not a `certain` action — the confirmation opens on its own.
Then('I am not asked for my password', async function () {
  if (await passwordDialog(this.page).isVisible()) {
    throw new Error('Removing an authenticator app is not a certain action, but the step-up appeared.');
  }
});

Then('the remove app keycap is locked', async function () {
  const button = removeAppButton(this.page);
  await button.waitFor({ state: 'visible' });
  if (!(await button.isDisabled())) {
    throw new Error('The removal was unlocked before the app name was typed back.');
  }
});

When('I type {string} into the removal', async function (name) {
  await removeAppDialog(this.page)
    .getByRole('textbox', { name: `Type ${name} to confirm:`, exact: true })
    .fill(name);
});

Then('the remove app keycap is unlocked', async function () {
  const button = removeAppButton(this.page);
  await poll(
    async () => (!(await button.isDisabled()) ? true : undefined),
    () => 'The removal never unlocked after the app name was typed back.'
  );
});

When('I confirm the removal of the authenticator app', async function () {
  await removeAppButton(this.page).click();
});
