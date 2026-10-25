/** Account-lifecycle steps: sign-up, password reset and password change. */

import { Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import { latestMailBySubject, latestMailLink, mailCount, mailLinks, poll } from '../support/harness.js';
import { createAccount, openVerificationLink, press, setPassword } from '../support/flow.js';

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

Then('the Password panel shows {string}', async function (state) {
  const panel = this.page.getByRole('region', { name: 'Password', exact: true });
  await panel.getByText(state).waitFor();
});

// WVR-167: the second factor is fixed, not a setting — the panel reports it as
// enabled for email codes and offers no control that could turn it off.
Then('the Two-factor authentication panel shows {string}', async function (state) {
  const panel = this.page.getByRole('region', { name: 'Two-factor authentication', exact: true });
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
