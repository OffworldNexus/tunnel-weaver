/**
 * Account-lifecycle steps.
 *
 * Each step is a thin wrapper over a flow helper in `support/flow.js`. The
 * Background seeds a unique address per scenario so a persistent temp database
 * cannot collide across reruns.
 */

import { Given, When } from '@cucumber/cucumber';
import * as assert from '../support/assertions.js';
import {
  createAccount,
  openVerificationLink,
  registerAccount,
  setPassword,
  signIn,
  signOut
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
