/**
 * The live harness the whole suite runs against (WVR-36).
 *
 * Boots `weaver-server --example e2e_server` exactly once per run, reads the two
 * `E2E_*` lines it flushes to stdout, and exposes the capture-mailbox over a
 * tiny HTTP client. The example prefers a prebuilt binary so a warm checkout
 * pays no `cargo` startup cost; a cold one is built on demand.
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** `e2e/features/support` → the repository root. */
const HERE = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(HERE, '..', '..', '..');

/** The binary `cargo build -p weaver-server --example e2e_server` produces. */
const PREBUILT = path.join(REPO_ROOT, 'target', 'debug', 'examples', 'e2e_server');

/** Shared, process-wide harness state. */
export const harness = {
  /** `https://localhost:<https-port>` — the SPA/API origin. */
  baseUrl: undefined,
  /** `http://127.0.0.1:<mail-port>` — the capture-mailbox origin. */
  mailUrl: undefined
};

let child = null;
/** The last lines of the harness's stderr, surfaced if startup fails. */
let stderrTail = [];

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** A single best-effort reachability probe that never throws. */
function probe(url) {
  return new Promise((resolve) => {
    const mod = url.startsWith('https:') ? https : http;
    const request = mod.get(
      url,
      { rejectUnauthorized: false, timeout: 2000 },
      (response) => {
        response.resume();
        resolve(response.statusCode >= 200 && response.statusCode < 500);
      }
    );
    request.on('error', () => resolve(false));
    request.on('timeout', () => {
      request.destroy();
      resolve(false);
    });
  });
}

/** Polls `predicate` until true, the harness dies, or `timeoutMs` elapses. */
async function waitUntil(predicate, { timeoutMs, description }) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (child && child.exitCode !== null) {
      throw new Error(
        `The e2e harness exited early (code ${child.exitCode}) while waiting for ${description}.\n` +
          `--- harness stderr (tail) ---\n${stderrTail.join('\n')}`
      );
    }
    if (await predicate()) return;
    if (Date.now() >= deadline) {
      throw new Error(
        `Timed out after ${timeoutMs}ms waiting for ${description}.\n` +
          `--- harness stderr (tail) ---\n${stderrTail.join('\n')}`
      );
    }
    await delay(100);
  }
}

/**
 * Starts the harness if it is not already running and waits until both URLs are
 * known and reachable. Idempotent across scenarios.
 */
export async function startHarness({ timeoutMs = 300_000 } = {}) {
  if (harness.baseUrl && harness.mailUrl) return harness;

  const usePrebuilt = existsSync(PREBUILT);
  const command = usePrebuilt ? PREBUILT : 'cargo';
  const args = usePrebuilt
    ? []
    : ['run', '--quiet', '-p', 'weaver-server', '--example', 'e2e_server'];

  stderrTail = [];
  const urls = {};
  child = spawn(command, args, {
    cwd: REPO_ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: process.env
  });

  child.stdout.setEncoding('utf8');
  let stdoutBuffer = '';
  child.stdout.on('data', (chunk) => {
    stdoutBuffer += chunk;
    let newline;
    while ((newline = stdoutBuffer.indexOf('\n')) !== -1) {
      const line = stdoutBuffer.slice(0, newline).trim();
      stdoutBuffer = stdoutBuffer.slice(newline + 1);
      if (line.startsWith('E2E_BASE_URL=')) urls.baseUrl = line.slice('E2E_BASE_URL='.length);
      if (line.startsWith('E2E_MAIL_URL=')) urls.mailUrl = line.slice('E2E_MAIL_URL='.length);
    }
  });

  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    for (const line of chunk.split('\n')) {
      if (line.trim()) stderrTail.push(line.replace(/\u001b\[[0-9;]*m/g, ''));
    }
    if (stderrTail.length > 40) stderrTail = stderrTail.slice(-40);
  });

  await waitUntil(() => urls.baseUrl && urls.mailUrl, {
    timeoutMs,
    description: 'the harness to print E2E_BASE_URL and E2E_MAIL_URL'
  });

  await waitUntil(() => probe(`${urls.mailUrl}/health`), {
    timeoutMs: 30_000,
    description: `the capture-mailbox at ${urls.mailUrl} to answer`
  });
  await waitUntil(() => probe(`${urls.baseUrl}/`), {
    timeoutMs: 30_000,
    description: `the HTTPS edge at ${urls.baseUrl} to answer`
  });

  harness.baseUrl = urls.baseUrl;
  harness.mailUrl = urls.mailUrl;
  return harness;
}

/** Stops the harness, escalating to SIGKILL if it will not exit promptly. */
export async function stopHarness() {
  if (!child) return;
  const proc = child;
  child = null;
  if (proc.exitCode !== null || proc.signalCode !== null) return;

  const exited = new Promise((resolve) => proc.once('exit', resolve));
  proc.kill('SIGTERM');
  const force = setTimeout(() => proc.kill('SIGKILL'), 5000);
  await exited;
  clearTimeout(force);
}

// ----- capture-mailbox client -----------------------------------------------

/** The captured messages, oldest first (as the endpoint returns them). */
export async function messages() {
  const response = await fetch(`${harness.mailUrl}/messages`);
  if (!response.ok) {
    throw new Error(`GET ${harness.mailUrl}/messages failed with ${response.status}`);
  }
  return response.json();
}

/**
 * The most recent captured message with an exact subject. Like the reset mail,
 * the change notification is sent off the response path (WVR-50), so this polls
 * the mailbox instead of assuming the message has already been captured.
 */
export async function latestMailBySubject(subject, { timeoutMs = 20_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const captured = await messages();
    for (let index = captured.length - 1; index >= 0; index -= 1) {
      if (captured[index].subject === subject) return captured[index];
    }
    if (Date.now() >= deadline) {
      throw new Error(
        `No captured message with subject ${JSON.stringify(subject)} among ${captured.length}: ` +
          `${captured.map((message) => JSON.stringify(message.subject)).join(', ') || '<none>'}`
      );
    }
    await delay(250);
  }
}

// ----- pairing seed ---------------------------------------------------------

/**
 * Seeds a pending pairing and returns its handle (64 hex characters).
 *
 * Test-only endpoint on the capture-mail harness: it lets the browser half of
 * pairing run without a CLI or a key agent. The harness stands in for the CLI's
 * channel, so what the terminal would have received is readable afterwards with
 * {@link pairingOutcome}.
 *
 * `target` is `{ machine: '<hostname>' }` for a new machine, or
 * `{ machineId: <id> }` for an existing machine moving onto a new key.
 */
/** A fresh fabricated key byte per seed: a real pairing mints a new key each time. */
let seedKey = 0;

function nextSeedKey() {
  seedKey += 1;
  return ((seedKey - 1) % 254) + 1;
}

export async function seedPairing(target) {
  const query = new URLSearchParams({ key: String(nextSeedKey()) });
  if (target.machineId !== undefined) query.set('machine_id', String(target.machineId));
  else query.set('machine', target.machine);
  const response = await fetch(`${harness.mailUrl}/pair/seed?${query}`, { method: 'POST' });
  if (!response.ok) {
    throw new Error(`POST ${harness.mailUrl}/pair/seed failed with ${response.status}`);
  }
  const body = await response.json();
  if (typeof body.handle !== 'string' || body.handle.length === 0) {
    throw new Error(`The pairing seed returned no handle: ${JSON.stringify(body)}`);
  }
  if (typeof body.fingerprint !== 'string' || body.fingerprint.length === 0) {
    throw new Error(`The pairing seed returned no fingerprint: ${JSON.stringify(body)}`);
  }
  return { handle: body.handle, fingerprint: body.fingerprint };
}

/**
 * The message the seeded "terminal" received on its channel, once one arrived.
 *
 * Polls until the relay has sent an outcome (`approved` or `failed`), since the
 * verdict travels to the channel asynchronously after the browser's request.
 */
export async function pairingOutcome(handle) {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const response = await fetch(
      `${harness.mailUrl}/pair/outcome?handle=${encodeURIComponent(handle)}`
    );
    if (!response.ok) {
      throw new Error(`GET ${harness.mailUrl}/pair/outcome failed with ${response.status}`);
    }
    const body = await response.json();
    if (body.state !== 'pending') return body;
    if (Date.now() >= deadline) {
      throw new Error('The terminal never received an outcome for this pairing.');
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

/**
 * The URL the CLI prints for a handle, built by the product itself.
 *
 * The harness builds it with the same `weave::pair::pairing_url` the CLI calls,
 * so a scenario opens the exact link the terminal prints. A scenario that
 * hand-built the fragment would validate the test's assumption instead of the
 * product's contract — and pass while the product was broken.
 */
export async function pairingUrl(handle) {
  const response = await fetch(
    `${harness.mailUrl}/pair/link?handle=${encodeURIComponent(handle)}`
  );
  if (!response.ok) {
    throw new Error(`GET ${harness.mailUrl}/pair/link failed with ${response.status}`);
  }
  const body = await response.json();
  if (typeof body.url !== 'string' || body.url.length === 0) {
    throw new Error(`The pair link returned no URL: ${JSON.stringify(body)}`);
  }
  return body.url;
}

/** Drops every captured message. */
export async function clearMail() {
  const response = await fetch(`${harness.mailUrl}/messages`, { method: 'DELETE' });
  if (!response.ok) {
    throw new Error(`DELETE ${harness.mailUrl}/messages failed with ${response.status}`);
  }
}

/** The most recent `/verify?token=…` link, or a loud error if none arrived. */
export async function latestVerificationLink() {
  const captured = await messages();
  for (let index = captured.length - 1; index >= 0; index -= 1) {
    const message = captured[index];
    const haystack = `${message.text}\n${message.html}`;
    const match = haystack.match(/https:\/\/localhost:\d+\/verify\?token=[0-9a-f]+/);
    if (match) return match[0];
  }
  throw new Error(
    `No verification link found among ${captured.length} captured message(s): ` +
      `${captured.map((message) => JSON.stringify(message.subject)).join(', ') || '<none>'}`
  );
}

/**
 * Every `/reset#token=…` link captured so far, oldest first. The token lives in
 * the URL *fragment* (WVR-41: it must never appear as a query parameter), so
 * the pattern only matches the fragment form.
 */
const RESET_LINK_PATTERN = /https:\/\/localhost:\d+\/reset#token=[0-9a-f]+/g;

/** All captured password-reset links. */
export async function resetLinks() {
  const captured = await messages();
  const links = [];
  for (const message of captured) {
    const haystack = `${message.text}\n${message.html}`;
    links.push(...(haystack.match(RESET_LINK_PATTERN) ?? []));
  }
  return links;
}

/**
 * The most recent `/reset#token=…` link. The reset email is sent off the
 * response path (to keep the request timing-blind), so this polls the mailbox
 * instead of assuming the message has already been captured.
 */
export async function latestResetLink({ timeoutMs = 20_000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const links = await resetLinks();
    if (links.length > 0) return links[links.length - 1];
    if (Date.now() >= deadline) {
      const captured = await messages();
      throw new Error(
        `No reset link found among ${captured.length} captured message(s): ` +
          `${captured.map((message) => JSON.stringify(message.subject)).join(', ') || '<none>'}`
      );
    }
    await delay(250);
  }
}
