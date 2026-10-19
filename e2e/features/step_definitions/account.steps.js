/** Account-lifecycle steps: sign-up, password reset and password change. */

import { Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import { latestMailBySubject, latestMailLink, mailLinks } from '../support/harness.js';
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
