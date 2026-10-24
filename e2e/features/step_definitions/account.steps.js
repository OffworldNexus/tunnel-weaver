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

// ----- account deletion (WVR-29) ---------------------------------------------

/** The confirm keycap inside the open dialog, never the Danger-zone opener. */
function confirmButton(page) {
  return page
    .getByRole('dialog', { name: 'Delete your account?' })
    .getByRole('button', { name: 'Delete account' });
}

When('I open the delete confirmation', async function () {
  const danger = this.page.getByRole('region', { name: 'Danger zone' });
  await danger.getByRole('button', { name: 'Delete account' }).click();
  await this.page
    .getByRole('dialog', { name: 'Delete your account?' })
    .waitFor({ state: 'visible' });
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
  await this.page.getByLabel(/to confirm/).fill(this.email);
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

Then('the deletion lands me signed out on the sign-in page', async function () {
  await this.page.waitForURL(/\/sign-in$/);
  await assert.seeHeading(this.page, 'Sign in');
});

Then('the old session no longer authenticates', async function () {
  const status = await this.page.evaluate(async () => (await fetch('/api/account/me')).status);
  if (status !== 401) {
    throw new Error(`Expected "/api/account/me" to answer 401 for the deleted session, got ${status}.`);
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
