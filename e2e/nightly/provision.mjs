#!/usr/bin/env node
/**
 * Nightly account + pairing provisioner.
 *
 * Drives the *real* account and pairing pages of a live relay — the same pages a
 * person uses — so the nightly can exercise the genuine end-to-end journey
 * (sign up, verify by emailed code, set a password, sign in, approve a machine)
 * without a seeded identity and without any development affordance.
 *
 * It is deliberately small and loud: every subcommand asserts the screen it
 * expects, and any failure prints the URL, the visible text and a screenshot,
 * then exits non-zero. It never guesses success.
 *
 * The pairing link is produced outside the browser (the link `weave pair`
 * prints) and handed in as `--link`. A signed-in session is carried between
 * invocations as a Playwright storage-state file (`--state`), so `signup` can
 * sign in once and `approve` can reuse that session.
 *
 * Both emailed codes — the signup verification code (WVR-169) and the sign-in
 * code (WVR-167) — are read back from Resend's Receiving API here rather than by
 * the caller: the signup flow lives in the tab's session storage and a sign-in
 * code is only valid for that sign-in, so each has to be read and entered inside
 * the same browser session that asked for it. That is why signing up, verifying
 * and the first sign-in are one subcommand.
 *
 * Run from the `e2e` workspace so `playwright` resolves:
 *
 *   node nightly/provision.mjs signup  --base https://<admin> --email <addr> \
 *                                      --password <pw>
 *   node nightly/provision.mjs approve --base https://<admin> --link <pair-url> \
 *                                      --machine laptop --person nightly
 */

import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { chromium } from 'playwright';

/** Resend's inbound-message endpoint: where the relay's own mail is read back. */
const RECEIVING = 'https://api.resend.com/emails/receiving';

/** The subject of the signup verification code. */
const VERIFICATION_SUBJECT = /verify your email/i;

/** The subject of the second-factor sign-in code. */
const SIGNIN_SUBJECT = /sign-in code/i;

/** Exit non-zero with the URL, the DOM text and a screenshot. */
async function fail(reason, page, screenshotPath) {
  console.error(`provision: FAILED: ${reason}`);
  if (page && !page.isClosed()) {
    console.error(`provision: url: ${page.url()}`);
    try {
      const text = await page.locator('body').innerText();
      console.error(`provision: visible text:\n${text}`);
    } catch {
      /* the page may be gone mid-navigation */
    }
    try {
      await page.screenshot({ path: screenshotPath, fullPage: true });
      console.error(`provision: screenshot: ${screenshotPath}`);
    } catch {
      /* best effort */
    }
  }
  process.exit(1);
}

/** Waits until `page` is on a path matching `pattern`. */
async function waitForPath(page, pattern, what, screenshotPath) {
  try {
    await page.waitForURL(pattern, { timeout: 30_000 });
  } catch (error) {
    await fail(`never reached ${what} (${pattern}): ${error.message}`, page, screenshotPath);
  }
}

/** Waits for a heading with the exact accessible text. */
async function waitForHeading(page, name, what, screenshotPath) {
  try {
    await page.getByRole('heading', { name, exact: true }).waitFor({ timeout: 30_000 });
  } catch (error) {
    await fail(`never saw the ${what} screen ("${name}"): ${error.message}`, page, screenshotPath);
  }
}

/** Opens a browser and a context, reusing `--state` if it exists. */
async function openBrowser({ state }) {
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    ignoreHTTPSErrors: true,
    ...(existsSync(state) ? { storageState: state } : {})
  });
  const page = await context.newPage();
  page.setDefaultTimeout(30_000);
  return { browser, context, page };
}

/** Presses a button; a proof-of-work submit stays disabled until the widget solves. */
async function press(page, name, screenshotPath) {
  try {
    await page.getByRole('button', { name, exact: true }).click({ timeout: 45_000 });
  } catch (error) {
    await fail(`could not press "${name}": ${error.message}`, page, screenshotPath);
  }
}

/** The Resend API key this run reads the mailbox with. */
function resendKey() {
  const key = process.env.RESEND_API_KEY;
  if (!key) {
    console.error('provision: RESEND_API_KEY is required to read the emailed codes back');
    process.exit(2);
  }
  return key;
}

/** Every id already in the receiving mailbox, so an older run's mail is ignored. */
async function receivedIds(key) {
  const res = await fetch(`${RECEIVING}?limit=20`, {
    headers: { Authorization: `Bearer ${key}` }
  });
  if (!res.ok) {
    console.error(`provision: the receiving API answered ${res.status}`);
    process.exit(2);
  }
  const body = await res.json();
  return new Set((body.data ?? []).map((message) => message.id));
}

/**
 * Waits for the six-digit code the relay just mailed, read back through Resend's
 * Receiving API — never from the relay's own database. Only a message that
 * arrived after `seen` was taken, addressed to `email` and carrying a subject
 * matching `subject`, can be the one just asked for.
 */
async function waitForCode(key, email, seen, subject, page, screenshotPath) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const list = await fetch(`${RECEIVING}?limit=20`, {
      headers: { Authorization: `Bearer ${key}` }
    });
    const body = await list.json();
    const message = (body.data ?? []).find(
      (candidate) =>
        !seen.has(candidate.id) &&
        (candidate.to ?? []).includes(email) &&
        subject.test(candidate.subject ?? '')
    );
    if (message) {
      const detail = await fetch(`${RECEIVING}/${message.id}`, {
        headers: { Authorization: `Bearer ${key}` }
      });
      const content = await detail.json();
      const code = /\b\d{6}\b/.exec(`${content.text ?? ''}\n${content.html ?? ''}`);
      if (code) {
        return code[0];
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000));
  }
  await fail(`never received a "${subject.source}" email at ${email}`, page, screenshotPath);
}

function common() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      base: { type: 'string' },
      email: { type: 'string' },
      name: { type: 'string', default: 'nightly' },
      password: { type: 'string' },
      link: { type: 'string' },
      machine: { type: 'string', default: 'laptop' },
      person: { type: 'string', default: 'nightly' },
      state: { type: 'string', default: '/tmp/weave-provision-state.json' },
      screenshot: { type: 'string', default: '/tmp/weave-provision-failure.png' }
    }
  });
  const command = positionals[0];
  if (!command) {
    console.error('usage: provision.mjs <signup|approve> [options]');
    process.exit(2);
  }
  if (!values.base) {
    console.error('provision: --base <https://admin-host> is required');
    process.exit(2);
  }
  return { command, ...values };
}

/**
 * Submits the code page — `/verify` and `/verify-code` share the heading, the
 * field and the submit — with the code read back after `seen` was taken.
 */
async function enterCode(page, key, email, seen, subject, screenshotPath) {
  await waitForHeading(page, 'Enter your code', 'code', screenshotPath);
  const code = await waitForCode(key, email, seen, subject, page, screenshotPath);
  await page.getByLabel('Code', { exact: true }).fill(code);
  await press(page, 'Continue', screenshotPath);
}

/** `signup` — create the account, verify it by code, set the password, sign in. */
async function signup(opts) {
  if (!opts.email || !opts.password) {
    console.error('provision: signup requires --email and --password');
    process.exit(2);
  }
  const key = resendKey();
  const { browser, context, page } = await openBrowser(opts);
  try {
    await page.goto(new URL('/sign-up', opts.base).toString());
    await waitForHeading(page, 'Create your account', 'sign-up', opts.screenshot);
    await page.getByLabel('Name', { exact: true }).fill(opts.name);
    await page.getByLabel('Email', { exact: true }).fill(opts.email);
    // The receiving mailbox is shared across runs: only a message that arrives
    // after this snapshot can be this signup's.
    let seen = await receivedIds(key);
    await press(page, 'Continue with email', opts.screenshot);
    await waitForPath(page, /\/verify$/, 'the verification step', opts.screenshot);
    await enterCode(page, key, opts.email, seen, VERIFICATION_SUBJECT, opts.screenshot);
    await waitForPath(page, /\/(set-password|existing-account)$/, 'set-password', opts.screenshot);
    if (new URL(page.url()).pathname.startsWith('/existing-account')) {
      await fail(`the address already had an account: ${opts.email}`, page, opts.screenshot);
    }
    await waitForHeading(page, 'Set your password', 'set-password', opts.screenshot);
    await page.getByLabel('New password', { exact: true }).fill(opts.password);
    await press(page, 'Save password', opts.screenshot);
    await waitForHeading(page, 'Sign in', 'sign-in', opts.screenshot);

    await page.getByLabel('Email', { exact: true }).fill(opts.email);
    await page.getByLabel('Password', { exact: true }).fill(opts.password);
    // WVR-167: the password is only the first factor. The code is read back
    // here, after the password is submitted and before anything could ask for
    // another one, and entered in the session that asked for it.
    seen = await receivedIds(key);
    await press(page, 'Sign in', opts.screenshot);
    await waitForPath(page, /\/verify-code$/, 'the second-factor step', opts.screenshot);
    await enterCode(page, key, opts.email, seen, SIGNIN_SUBJECT, opts.screenshot);
    await waitForPath(page, /\/app$/, 'the signed-in shell', opts.screenshot);
    await context.storageState({ path: opts.state });
    console.log(`provision: signed up, verified and signed in as ${opts.email}`);
  } catch (error) {
    await fail(error.message, page, opts.screenshot);
  } finally {
    await context.close();
    await browser.close();
  }
}

/** `approve` — open the pairing link and approve the machine (and person). */
async function approve(opts) {
  if (!opts.link) {
    console.error('provision: approve requires --link');
    process.exit(2);
  }
  const { browser, context, page } = await openBrowser(opts);
  try {
    await page.goto(opts.link);
    await waitForHeading(page, 'Approve a machine', 'pair', opts.screenshot);
    // A first pairing lets the person name the machine and proposes the person
    // slug; the nightly pins both so the tunnel hostname is predictable.
    await page.getByLabel('Machine name', { exact: true }).fill(opts.machine);
    if ((await page.getByLabel('Person slug', { exact: true }).count()) > 0) {
      await page.getByLabel('Person slug', { exact: true }).fill(opts.person);
    }
    await press(page, 'Approve this machine', opts.screenshot);
    await waitForHeading(page, 'Machine approved', 'machine-approved', opts.screenshot);
    console.log(`provision: approved machine ${opts.person}/${opts.machine}`);
  } catch (error) {
    await fail(error.message, page, opts.screenshot);
  } finally {
    await context.close();
    await browser.close();
  }
}

const opts = common();
if (opts.command === 'signup') await signup(opts);
else if (opts.command === 'approve') await approve(opts);
else {
  console.error(`provision: unknown command "${opts.command}"`);
  process.exit(2);
}
