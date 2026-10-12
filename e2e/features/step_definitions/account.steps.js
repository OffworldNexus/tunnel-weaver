/**
 * Account-lifecycle steps.
 *
 * Each step is a thin wrapper over a flow helper in `support/flow.js`. The
 * Background seeds a unique address per scenario so a persistent temp database
 * cannot collide across reruns.
 */

import { Given, When, Then } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import {
  createAccount,
  expectNoResetLink,
  followForgotPassword,
  openResetLink,
  openResetRequestPage,
  openVerificationLink,
  registerAccount,
  reopenResetLink,
  requestResetLink,
  resetPassword,
  setPassword,
  signIn,
  signOut,
  takeResetLink
} from '../support/flow.js';

/** A per-run, per-scenario address: `wvr36+<slug>-<timestamp><rand>@example.com`. */
function uniqueEmail(name) {
  const slug =
    name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '') || 'user';
  const stamp = `${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
  return `wvr36+${slug}-${stamp}@example.com`;
}

Given('a unique email address for {string}', function (name) {
  this.name = name;
  this.email = uniqueEmail(name);
});

Given(
  'an account exists for {string} with the password {string}',
  async function (name, password) {
    this.name = name;
    this.password = password;
    await registerAccount(this, { name, email: this.email, password });
  }
);

When('I create an account for {string}', async function (name) {
  this.name = name;
  await createAccount(this, { name, email: this.email });
});

When('I open the verification link from the latest email', async function () {
  await openVerificationLink(this);
});

When('I set the password to {string}', async function (password) {
  this.password = password;
  await setPassword(this, password);
});

When('I sign in with the password {string}', async function (password) {
  await signIn(this, { email: this.email, password });
});

When('I sign in with the wrong password {string}', async function (password) {
  await signIn(this, { email: this.email, password });
});

When('I sign out', async function () {
  await signOut(this);
});

When('I open the sign-up page', async function () {
  await this.open('/sign-up');
  await assert.seeHeading(this.page, 'Create your account');
});

// --- password reset (WVR-41) ------------------------------------------------

Given('I open the reset request page', async function () {
  await openResetRequestPage(this);
});

When('I follow the "Forgot password?" link from the sign-in page', async function () {
  await followForgotPassword(this);
});

When('I request a reset link for my email', async function () {
  await requestResetLink(this);
});

Then('I see the acknowledgement that instructions will be emailed', async function () {
  await assert.seeText(
    this.page,
    "If an account exists, we'll email instructions to reset your password. " +
      'Check your inbox and spam folder.',
    { exact: true }
  );
});

When('I take the reset link from the latest email', async function () {
  await takeResetLink(this);
});

Then('the reset link carries its token in the fragment, never the query string', function () {
  const url = new URL(this.resetLink);
  if (url.pathname !== '/reset' || url.search !== '' || !/^#token=[0-9a-f]+$/.test(url.hash)) {
    throw new Error(
      `Expected the reset link to be "<base>/reset#token=…" with no query token, ` +
        `but it was "${this.resetLink}".`
    );
  }
});

When('I open the reset link', async function () {
  await openResetLink(this);
});

When('I set the new password to {string}', async function (password) {
  this.password = password;
  await resetPassword(this, password);
});

Then('I see the reset success notice', async function () {
  await assert.seeText(
    this.page,
    'Your password has been reset. Sign in with your new password.',
    { exact: false }
  );
});

When('I open the same reset link again', async function () {
  await reopenResetLink(this);
});

Then('no reset email is sent', async function () {
  await expectNoResetLink(this);
});
