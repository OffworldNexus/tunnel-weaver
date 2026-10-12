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
export async function ensureOnSignIn(world) {
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

/**
 * Submits the sign-in form. The caller asserts whichever outcome follows.
 *
 * Labels are matched exactly: the post-reset success toast is a live region
 * whose accessible name ("…password has been reset…") otherwise collides with a
 * loose `getByLabel('Password')` and trips Playwright's strict mode.
 */
export async function signIn(world, { email, password }) {
  await ensureOnSignIn(world);
  await world.page.getByLabel('Email', { exact: true }).fill(email);
  await world.page.getByLabel('Password', { exact: true }).fill(password);
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

// --- password reset (WVR-41) ------------------------------------------------

/** Navigates to `/forgot-password` and waits for the request form. */
export async function openResetRequestPage(world) {
  if (!new URL(world.page.url()).pathname.startsWith('/forgot-password')) {
    await world.open('/forgot-password');
  }
  await assert.seeHeading(world.page, 'Reset your password');
}

/** From the sign-in form, follows "Forgot password?" to the request form. */
export async function followForgotPassword(world) {
  await ensureOnSignIn(world);
  await world.page.getByRole('link', { name: 'Forgot password?', exact: true }).click();
  await assert.seeHeading(world.page, 'Reset your password');
}

/**
 * Fills and submits the reset-request form. The submit stays disabled until the
 * invisible proof-of-work widget reads "Ready to go."; the keycap's layered art
 * defeats Playwright's stability check, so the click is forced.
 */
export async function requestResetLink(world, email = world.email) {
  await assert.seeHeading(world.page, 'Reset your password');
  await world.page.getByLabel('Email', { exact: true }).fill(email);
  await assert.seeText(world.page, 'Ready to go.', { exact: true });
  await world.page.getByRole('button', { name: /Send reset link/ }).click({ force: true });
  await assert.seeHeading(world.page, 'Reset request accepted');
}

/**
 * Reads the newest reset link out of the capture mailbox. The reset email is
 * sent off the response path, so the read polls the mailbox rather than
 * assuming the message is already there.
 */
export async function takeResetLink(world) {
  world.resetLink = await world.latestResetLink();
}

/** Opens the reset link taken earlier, waiting for the live form. */
export async function openResetLink(world) {
  await world.page.goto(world.resetLink);
  await assert.seeHeading(world.page, 'Choose a new password');
}

/** Sets the password on the reset form; ends back on the sign-in screen. */
export async function resetPassword(world, password) {
  await assert.seeHeading(world.page, 'Choose a new password');
  await world.page.getByLabel('New password', { exact: true }).fill(password);
  await world.page.getByRole('button', { name: /Reset password/ }).click({ force: true });
  await assert.seeHeading(world.page, 'Sign in');
}

/** Reopens the spent reset link; expects the recoverable dead-link state. */
export async function reopenResetLink(world) {
  await world.page.goto(world.resetLink);
  await assert.seeHeading(world.page, 'Link expired or used');
}

/**
 * Waits a short grace period, then asserts the mailbox holds no reset link at
 * all. The reset email is emitted off the response path, so an immediate read
 * would race the (absent) send.
 */
export async function expectNoResetLink(world, { graceMs = 3_000 } = {}) {
  await new Promise((resolve) => setTimeout(resolve, graceMs));
  const links = await world.resetLinks();
  if (links.length > 0) {
    throw new Error(
      `Expected no reset email for an address without an account, but the mailbox held ` +
        `${links.length}: ${links.join(', ')}`
    );
  }
}

// --- password change (WVR-50) -----------------------------------------------

/**
 * Follows a link by its exact accessible name. Keycap links are built from
 * layered pedestal/ring/cap/face spans, which defeat Playwright's stability
 * check, so the click is forced (same caveat as the sign-in keycap).
 */
export async function followLink(world, name) {
  const link = world.page.getByRole('link', { name, exact: true });
  await link.waitFor({ state: 'visible' });
  await link.click({ force: true });
}

/**
 * Opens the Security page from the signed-in shell. The Account nav's
 * "Security" entry is a plain link; the `/app/security` h1 shares its name, so
 * the locator is pinned to the link role.
 */
export async function openSecurity(world) {
  await world.page.getByRole('navigation', { name: 'Account' }).waitFor({ state: 'visible' });
  await followLink(world, 'Security');
  await assert.seeHeading(world.page, 'Security');
}

/** Follows the Password panel's "Change password" keycap link. */
export async function followChangePassword(world) {
  await followLink(world, 'Change password');
  await assert.seeHeading(world.page, 'Change your password');
}

/**
 * Fills the change form. Labels are matched exactly: a bare `Password` would be
 * ambiguous, and a loose one could be satisfied by a live region's name.
 */
async function fillChangeForm(world, { current, next }) {
  await assert.seeHeading(world.page, 'Change your password');
  await world.page.getByLabel('Current password', { exact: true }).fill(current);
  await world.page.getByLabel('New password', { exact: true }).fill(next);
}

/**
 * Submits the change form without assuming an outcome, so both the success and
 * the refusal leg can share it. The submit keycap's label flips to "Saving…"
 * mid-flight, so the click is forced rather than re-resolved.
 */
export async function submitPasswordChange(world, { current, next }) {
  await fillChangeForm(world, { current, next });
  await world.page
    .getByRole('button', { name: 'Change password', exact: true })
    .click({ force: true });
}

/**
 * Changes the password successfully. The relay ends every session — this one
 * included — so the SPA lands on sign-in carrying the success notice.
 */
export async function changePassword(world, { current, next }) {
  await submitPasswordChange(world, { current, next });
  await assert.seeHeading(world.page, 'Sign in');
}

/**
 * Proves the acting session is gone too: the signed-in shell can no longer be
 * reached, and the guard returns the browser to sign-in. Assert the path rather
 * than the live region, which the sign-in page consumes on render.
 */
export async function expectSignedOutEverywhere(world) {
  await world.page.goto(world.url('/app'));
  await world.page.waitForURL(/\/sign-in(\?.*)?$/, { timeout: 20_000 });
  await assert.seeHeading(world.page, 'Sign in');
}

/**
 * Waits for the change-notification email. It is sent off the response path, so
 * the read polls the capture mailbox (mirroring `takeResetLink`).
 */
export async function expectPasswordChangedMail(world) {
  await world.latestMailBySubject('Your password was changed');
}
