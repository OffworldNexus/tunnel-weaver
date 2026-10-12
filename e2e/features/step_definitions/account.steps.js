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
  changePassword,
  createAccount,
  expectNoResetLink,
  expectPasswordChangedMail,
  expectSignedOutEverywhere,
  followChangePassword,
  followForgotPassword,
  openResetLink,
  openResetRequestPage,
  openSecurity,
  openVerificationLink,
  registerAccount,
  reopenResetLink,
  requestResetLink,
  resetPassword,
  setPassword,
  signIn,
  signOut,
  submitPasswordChange,
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

// --- password change (WVR-50) ------------------------------------------------

When('I open the Security page', async function () {
  await openSecurity(this);
});

Then('I see the Password panel showing {string}', async function (state) {
  await assert.seeRegion(this.page, 'Password');
  await assert.seeLink(this.page, 'Change password');
  await assert.seeText(this.page, state);
  // `seeText` matches a case-insensitive substring, so "Password is set" is also
  // satisfied by "No password is set". Compare the panel's own lines, dropping
  // the aria-hidden ✓ decoration, so the state is pinned exactly.
  const lines = (await this.page.getByRole('region', { name: 'Password' }).innerText())
    .split('\n')
    .map((line) => line.replace('\u2713', '').trim());
  if (!lines.includes(state)) {
    throw new Error(
      `Expected the Password panel to show "${state}", but it showed: ` +
        `${lines.filter(Boolean).join(' | ')}`
    );
  }
});

When('I follow the "Change password" link from the Password panel', async function () {
  await followChangePassword(this);
});

Then('the change form asks only for the current and new password', async function () {
  await assert.seeLabel(this.page, 'Current password');
  await assert.seeLabel(this.page, 'New password');
  // The delivered design has no repeat field, so nothing may match a
  // confirmation control.
  const confirm = await this.page.getByLabel(/confirm/i).count();
  if (confirm !== 0) {
    throw new Error(
      `Expected no confirmation field on the change form, but ${confirm} control(s) matched /confirm/i.`
    );
  }
});

When('I change my password from {string} to {string}', async function (current, next) {
  await changePassword(this, { current, next });
});

Then('I see the password change success notice', async function () {
  await assert.seeText(
    this.page,
    'Your password has been changed. Sign in with your new password.'
  );
});

Then('I am signed out everywhere, this device included', async function () {
  await expectSignedOutEverywhere(this);
});

Then('the password change notification email is sent', async function () {
  await expectPasswordChangedMail(this);
});

When('I try to change my password from {string} to {string}', async function (current, next) {
  await submitPasswordChange(this, { current, next });
});

Then('I see the change refusal on the current password field', async function () {
  await assert.seeAlert(this.page, 'that is not your current password');
});

When('I open my account page', async function () {
  await this.open('/app');
});
