/**
 * One harness and one browser per run; a fresh context per scenario, so no
 * cookies or storage leak between scenarios.
 */

import { After, AfterAll, Before, BeforeAll, setDefaultTimeout } from '@cucumber/cucumber';
import { chromium } from 'playwright';
import { clearMail, startHarness, stopHarness } from './harness.js';

setDefaultTimeout(60_000);

let browser;

BeforeAll(async function () {
  await startHarness();
  browser = await chromium.launch({ headless: true });
});

AfterAll(async function () {
  await browser?.close();
  await stopHarness();
});

Before(async function () {
  // The harness certificate is self-signed.
  this.context = await browser.newContext({ ignoreHTTPSErrors: true });
  this.page = await this.context.newPage();
  this.page.setDefaultTimeout(20_000);
  this.page.on('request', (request) => this.requestUrls.push(request.url()));
  // WVR-163: a virtual authenticator is the only authenticator a CI runner has.
  // Presence is off (see `World#present`): with it on, the conditional ceremony
  // the sign-in page starts on load would sign a scenario in unasked, and a
  // registration would fire the moment one was started.
  this.cdp = await this.context.newCDPSession(this.page);
  await this.cdp.send('WebAuthn.enable');
  const authenticator = await this.cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: false
    }
  });
  this.authenticatorId = authenticator.authenticatorId;
  // "The latest email" can then only be mail this scenario caused.
  await clearMail();
});

After(async function (scenario) {
  if (scenario.result?.status === 'FAILED') {
    const screenshot = await this.page.screenshot({ fullPage: true }).catch(() => null);
    if (screenshot) await this.attach(screenshot, 'image/png');
    await this.attach(`url: ${this.page.url()}`, 'text/plain');
  }
  // Gone with the context either way; removed first so the CDP session does not
  // outlive the page it was attached to.
  await this.cdp
    .send('WebAuthn.removeVirtualAuthenticator', { authenticatorId: this.authenticatorId })
    .catch(() => {});
  await this.context.close();
});
