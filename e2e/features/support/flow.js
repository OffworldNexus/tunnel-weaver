/**
 * Declarative UI flows shared by the step definitions.
 *
 * Each helper drives one leg of the account journey and waits for the *next
 * screen* to settle, so steps stay one-liners and scenarios never reinvent the
 * sequence. Locators are role/label based — no CSS, no sleeps.
 */

import * as assert from './assertions.js';

/** Opens the public landing page. */
export async function openLanding(world) {
  await world.open('/');
}

/**
 * Follows a landing call to action by its accessible name. CTAs repeat across
 * the landing (top bar, hero, closing panel), so the first match is used.
 */
export async function followCallToAction(world, name) {
  const link = world.page.getByRole('link', { name, exact: true }).first();
  await link.waitFor({ state: 'visible' });
  await link.click();
}

/** Navigates to the sign-up form unless we are already there. */
async function ensureOnSignUp(world) {
  if (!new URL(world.page.url()).pathname.startsWith('/sign-up')) {
    await world.open('/sign-up');
  }
  await assert.seeHeading(world.page, 'Create your account');
}

/** Navigates to the sign-in form unless we are already there. */
async function ensureOnSignIn(world) {
  if (!new URL(world.page.url()).pathname.startsWith('/sign-in')) {
    await world.open('/sign-in');
  }
  await assert.seeHeading(world.page, 'Sign in');
}

/**
 * Fills the sign-up form and submits it, landing on "Check your email". The
 * submit stays disabled until the invisible proof-of-work widget solves, which
 * Playwright's click auto-wait handles.
 */
export async function createAccount(world, { name, email }) {
  await ensureOnSignUp(world);
  await world.page.getByLabel('Name').fill(name);
  await world.page.getByLabel('Email').fill(email);
  await world.page.getByRole('button', { name: 'Continue with email' }).click();
  await assert.seeHeading(world.page, 'Check your email');
}

/** Opens the newest verification link; ends on set-password or existing-account. */
export async function openVerificationLink(world) {
  const link = await world.latestVerificationLink();
  await world.page.goto(link);
  await world.page.waitForURL(/\/(set-password|existing-account)(\?.*)?$/, { timeout: 20_000 });
}

/** Sets the account password; ends back on the sign-in form. */
export async function setPassword(world, password) {
  await assert.seeHeading(world.page, 'Set your password');
  await world.page.getByLabel('New password').fill(password);
  await world.page.getByRole('button', { name: 'Save password' }).click();
  await assert.seeHeading(world.page, 'Sign in');
}

/** Submits the sign-in form. The caller asserts whichever outcome follows. */
export async function signIn(world, { email, password }) {
  await ensureOnSignIn(world);
  await world.page.getByLabel('Email').fill(email);
  await world.page.getByLabel('Password').fill(password);
  await world.page.getByRole('button', { name: 'Sign in' }).click();
}

/** Signs out of the signed-in shell; ends back on the sign-in form. */
export async function signOut(world) {
  await world.page.getByRole('button', { name: 'Sign out' }).click();
  await assert.seeHeading(world.page, 'Sign in');
}

/**
 * The whole registration journey in one call: sign up → verify → set password,
 * leaving the browser on the sign-in form. Used by the Background-style step
 * that needs an existing account without repeating the happy-path steps.
 */
export async function registerAccount(world, { name, email, password }) {
  await createAccount(world, { name, email });
  await openVerificationLink(world);
  await setPassword(world, password);
}
