/**
 * The legs of the account journey shared by several steps. Each one waits for
 * the screen it ends on. Locators are role/label based: no CSS, no sleeps.
 */

import * as assert from './assertions.js';
import { latestMailCode } from './harness.js';

/** Subject of the emailed sign-up verification code (WVR-169). */
export const VERIFICATION_SUBJECT = 'Verify your email address';

/** Subject of the emailed second-factor code (WVR-167). */
export const SIGN_IN_CODE_SUBJECT = 'Your Tunnel Weaver sign-in code';

/**
 * The one message every refused sign-up shows — the first submission and the
 * SSO return alike (WVR-98).
 */
export const SIGNUP_REFUSAL = "Sign-ups with this address aren't open on this relay.";

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

/**
 * Fills and submits the sign-up form. It asserts nothing about the destination,
 * so a caller can assert a refusal instead of the code step (WVR-98).
 */
export async function attemptCreateAccount(world, name) {
  await ensureOn(world, '/sign-up', 'Create your account');
  await world.page.getByLabel('Name', { exact: true }).fill(name);
  await world.page.getByLabel('Email', { exact: true }).fill(world.email);
  await press(world, 'Continue with email');
}

export async function createAccount(world, name) {
  await attemptCreateAccount(world, name);
  await assert.seeHeading(world.page, 'Enter your code');
}

/**
 * Types the six-digit code from the newest `subject` email into a code page
 * and submits it. The signup verification page and the sign-in code step share
 * the heading, the field and the submit, so one leg serves both.
 */
async function enterEmailedCode(world, subject) {
  await assert.seeHeading(world.page, 'Enter your code');
  await world.page.getByLabel('Code', { exact: true }).fill(await latestMailCode(subject));
  await press(world, 'Continue');
}

/**
 * Enters the signup verification code on `/verify`; ends on set-password or,
 * for an address that already has an account, existing-account.
 */
export async function enterVerificationCode(world) {
  await enterEmailedCode(world, VERIFICATION_SUBJECT);
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
  await enterVerificationCode(world);
  await setPassword(world, password);
}

/**
 * Submits the sign-in form — the password, the first factor. The caller asserts
 * the outcome: a refusal stays here with an error, a success lands on the code
 * step (`/verify-code`).
 */
export async function signIn(world, password) {
  await ensureOn(world, '/sign-in', 'Sign in');
  await world.page.getByLabel('Email', { exact: true }).fill(world.email);
  await world.page.getByLabel('Password', { exact: true }).fill(password);
  await press(world, 'Sign in');
}

/**
 * Enters the emailed second-factor code, completing the sign-in (WVR-167). The
 * caller asserts the destination: the console, or `/pair` on a pairing detour.
 */
export const enterSignInCode = (world) => enterEmailedCode(world, SIGN_IN_CODE_SUBJECT);
