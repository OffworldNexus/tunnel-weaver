/**
 * The legs of the account journey shared by several steps. Each one waits for
 * the screen it ends on. Locators are role/label based: no CSS, no sleeps.
 */

import * as assert from './assertions.js';
import { latestMailLink } from './harness.js';

const VERIFY_LINK = /https:\/\/localhost:\d+\/verify\?token=[0-9a-f]+/g;

/**
 * Presses a button by its exact name. A submit gated by the proof-of-work
 * widget stays disabled until it solves; the click waits for that.
 */
export async function press(world, name) {
  await world.page.getByRole('button', { name, exact: true }).click();
}

/** Opens `pathname` unless the page is already on it, then waits for `heading`. */
async function ensureOn(world, pathname, heading) {
  if (new URL(world.page.url()).pathname !== pathname) await world.open(pathname);
  await assert.seeHeading(world.page, heading);
}

export async function createAccount(world, name) {
  await ensureOn(world, '/sign-up', 'Create your account');
  await world.page.getByLabel('Name', { exact: true }).fill(name);
  await world.page.getByLabel('Email', { exact: true }).fill(world.email);
  await press(world, 'Continue with email');
  await assert.seeHeading(world.page, 'Check your email');
}

/** Opens the newest verification link; ends on set-password or existing-account. */
export async function openVerificationLink(world) {
  await world.page.goto(await latestMailLink(VERIFY_LINK));
  await world.page.waitForURL(/\/(set-password|existing-account)$/);
}

export async function setPassword(world, password) {
  await assert.seeHeading(world.page, 'Set your password');
  await world.page.getByLabel('New password', { exact: true }).fill(password);
  await press(world, 'Save password');
  await assert.seeHeading(world.page, 'Sign in');
}

/** Sign up, verify and set a password, ending on the sign-in form. */
export async function registerAccount(world, name, password) {
  await createAccount(world, name);
  await openVerificationLink(world);
  await setPassword(world, password);
}

/** Submits the sign-in form; the caller asserts the outcome. */
export async function signIn(world, password) {
  await ensureOn(world, '/sign-in', 'Sign in');
  await world.page.getByLabel('Email', { exact: true }).fill(world.email);
  await world.page.getByLabel('Password', { exact: true }).fill(password);
  await press(world, 'Sign in');
}
