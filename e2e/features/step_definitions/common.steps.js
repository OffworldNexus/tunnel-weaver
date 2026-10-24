/** Steps shared across features: navigation, what a person sees, and signing in. */

import { Given, Then, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import { SIGN_IN_CODE_SUBJECT, enterSignInCode, press, registerAccount, signIn } from '../support/flow.js';
import { latestMailCode } from '../support/harness.js';

const PAGES = {
  landing: '/',
  'sign-up': '/sign-up',
  'sign-in': '/sign-in',
  'forgot-password': '/forgot-password',
  reset: '/reset',
  verify: '/verify',
  'existing-account': '/existing-account',
  'check-email': '/check-email',
  'set-password': '/set-password',
  'verify-code': '/verify-code',
  'reset request': '/forgot-password',
  account: '/app'
};

/** A per-scenario address, so a persistent database cannot collide across runs. */
function uniqueEmail(name) {
  const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
  return `e2e+${slug}-${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}@example.com`;
}

Given('a unique email address for {string}', function (name) {
  this.name = name;
  this.email = uniqueEmail(name);
});

Given('an account exists for {string} with the password {string}', async function (name, password) {
  await registerAccount(this, name, password);
});

Given('I open the {string} page', async function (page) {
  await this.open(PAGES[page]);
});

When('I follow the {string} link', async function (name) {
  // Calls to action repeat across the landing page.
  await this.page.getByRole('link', { name, exact: true }).first().click();
});

When('I sign in with the password {string}', async function (password) {
  await signIn(this, password);
  // The password is only the first factor: the sign-in is complete once the
  // emailed code is entered (WVR-167).
  await enterSignInCode(this);
});

When('I sign in with the wrong password {string}', async function (password) {
  // A wrong password never reaches the second factor; the caller asserts the
  // generic refusal.
  await signIn(this, password);
});

// WVR-167: the two halves of the sign-in, exposed so a feature can assert the
// code step is reached (and what it refuses) rather than having both factors
// run inside one step.
When('I sign in with the password {string}, without the code', async function (password) {
  await signIn(this, password);
  await assert.seeHeading(this.page, 'Enter your code');
});

When('I enter the code from my email', async function () {
  await enterSignInCode(this);
});

When('I submit a wrong code', async function () {
  // Derived from the newest code, never hardcoded, so it can never collide
  // with the one that was actually emailed.
  const code = await latestMailCode(SIGN_IN_CODE_SUBJECT);
  const wrong = code === '000000' ? '000001' : '000000';
  await this.page.getByLabel('Code', { exact: true }).fill(wrong);
  await press(this, 'Continue');
});

When('I sign out', async function () {
  await press(this, 'Sign out');
  await assert.seeHeading(this.page, 'Sign in');
});

Then('I see the {string} heading', async function (name) {
  await assert.seeHeading(this.page, name);
});

Then('I see a link to {string}', async function (name) {
  await assert.seeLink(this.page, name);
});

Then('I do not see a link to {string}', async function (name) {
  await assert.seeNoLink(this.page, name);
});

// WVR-168: a signed-in visitor who reaches an account-entry page is sent on to
// the console instead.
Then('I land on my console', async function () {
  await this.page.waitForURL(/\/app$/);
  await assert.seeHeading(this.page, 'Overview');
});

Then('I see the error {string}', async function (text) {
  await assert.seeAlert(this.page, text);
});

Then('I see {string}', async function (text) {
  await assert.seeText(this.page, text);
});

Then('the verified email is shown as the account address', async function () {
  await assert.seeFieldValue(this.page, 'Email', this.email);
});

Then('I see the signed-in identity for {string}', async function (name) {
  // The console's own chrome: the overview's page title is the heading, and the
  // identity lives in the sidebar rather than the old account-denormalised
  // definition list this branch replaced.
  await assert.seeHeading(this.page, 'Overview');
  await assert.seeText(this.page, name);
  await assert.seeText(this.page, this.email);
});
