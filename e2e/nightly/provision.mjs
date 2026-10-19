#!/usr/bin/env node
/**
 * Nightly account + pairing provisioner.
 *
 * Drives the *real* account and pairing pages of a live relay — the same pages a
 * person uses — so the nightly can exercise the genuine end-to-end journey
 * (sign up, verify by email link, set a password, sign in, approve a machine)
 * without a seeded identity and without any development affordance.
 *
 * It is deliberately small and loud: every subcommand asserts the screen it
 * expects, and any failure prints the URL, the visible text and a screenshot,
 * then exits non-zero. It never guesses success.
 *
 * The verification link and the pairing link are produced outside the browser
 * (the link the relay prints and the link `weave pair` prints) and handed in as
 * `--link`. A signed-in session is carried between invocations as a Playwright
 * storage-state file (`--state`), so `verify` can sign in once and `approve` can
 * reuse that session.
 *
 * Run from the `e2e` workspace so `playwright` resolves:
 *
 *   node nightly/provision.mjs signup  --base https://<admin> --email <addr>
 *   node nightly/provision.mjs verify  --base https://<admin> --email <addr> \
 *                                      --password <pw> --link <verify-url>
 *   node nightly/provision.mjs approve --base https://<admin> --link <pair-url> \
 *                                      --machine laptop --person nightly
 */

import { existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { chromium } from 'playwright';

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
    console.error('usage: provision.mjs <signup|verify|approve> [options]');
    process.exit(2);
  }
  if (!values.base) {
    console.error('provision: --base <https://admin-host> is required');
    process.exit(2);
  }
  return { command, ...values };
}

/** `signup` — create the account and stop on "Check your email". */
async function signup(opts) {
  if (!opts.email) {
    console.error('provision: signup requires --email');
    process.exit(2);
  }
  const { browser, context, page } = await openBrowser(opts);
  try {
    await page.goto(new URL('/sign-up', opts.base).toString());
    await waitForHeading(page, 'Create your account', 'sign-up', opts.screenshot);
    await page.getByLabel('Name', { exact: true }).fill(opts.name);
    await page.getByLabel('Email', { exact: true }).fill(opts.email);
    await press(page, 'Continue with email', opts.screenshot);
    await waitForHeading(page, 'Check your email', 'check-email', opts.screenshot);
    await context.storageState({ path: opts.state });
    console.log(`provision: signup started for ${opts.email}`);
  } catch (error) {
    await fail(error.message, page, opts.screenshot);
  } finally {
    await context.close();
    await browser.close();
  }
}

/** `verify` — open the emailed link, set the password, then sign in. */
async function verify(opts) {
  if (!opts.email || !opts.password || !opts.link) {
    console.error('provision: verify requires --email, --password and --link');
    process.exit(2);
  }
  const { browser, context, page } = await openBrowser(opts);
  try {
    await page.goto(opts.link);
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
    await press(page, 'Sign in', opts.screenshot);
    await waitForPath(page, /\/app$/, 'the signed-in shell', opts.screenshot);
    await context.storageState({ path: opts.state });
    console.log(`provision: verified and signed in as ${opts.email}`);
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
else if (opts.command === 'verify') await verify(opts);
else if (opts.command === 'approve') await approve(opts);
else {
  console.error(`provision: unknown command "${opts.command}"`);
  process.exit(2);
}
