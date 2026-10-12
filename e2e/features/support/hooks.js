/**
 * Suite lifecycle: one harness + one browser per run; one isolated context per
 * scenario. This keeps scenarios independent (fresh cookies, sessionStorage and
 * cache) while paying for the browser launch only once.
 */

import { After, AfterAll, Before, BeforeAll, setDefaultTimeout } from '@cucumber/cucumber';
import { chromium } from 'playwright';
import { clearMail, startHarness, stopHarness } from './harness.js';

// Generous per-step budget: the first navigation compiles and hydrates the SPA.
setDefaultTimeout(60_000);

/** @type {import('playwright').Browser | undefined} */
let browser;

BeforeAll(async function () {
  await startHarness();
  browser = await chromium.launch({ headless: true });
});

AfterAll(async function () {
  if (browser) {
    await browser.close();
    browser = undefined;
  }
  await stopHarness();
});

Before(async function () {
  // A fresh context per scenario: no shared cookies, storage or cache, and the
  // self-signed cert is accepted for the whole origin.
  this.context = await browser.newContext({ ignoreHTTPSErrors: true });
  this.page = await this.context.newPage();
  this.page.setDefaultTimeout(20_000);
  // Start every scenario with an empty capture buffer so "the latest email"
  // can only refer to mail this scenario caused.
  await clearMail();
});

After(async function (scenario) {
  const failed = scenario?.result?.status === 'FAILED';
  if (failed && this.page && !this.page.isClosed()) {
    const screenshot = await this.page.screenshot({ fullPage: true }).catch(() => null);
    if (screenshot) await this.attach(screenshot, 'image/png');
    const html = await this.page.content().catch(() => null);
    if (html) await this.attach(html, 'text/html');
    await this.attach(`url: ${this.page.url()}`, 'text/plain');
  }
  if (this.context) {
    await this.context.close();
  }
  this.context = undefined;
  this.page = undefined;
});
