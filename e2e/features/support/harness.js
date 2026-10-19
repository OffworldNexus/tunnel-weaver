/**
 * The live harness the whole suite runs against.
 *
 * Starts the prebuilt `weaver-server --example e2e_server` once per run and
 * reads the two origins it prints once both listeners are bound:
 *
 *   E2E_BASE_URL=https://localhost:<port>   the SPA/API origin
 *   E2E_MAIL_URL=http://127.0.0.1:<port>    the capture mailbox and pairing seed
 */

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const BINARY = path.join(REPO_ROOT, 'target', 'debug', 'examples', 'e2e_server');

export const harness = { baseUrl: '', mailUrl: '' };

let child = null;

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Calls `attempt` until it returns something other than `undefined`, else
 * throws `failure()` after `timeoutMs`. Mail and pairing outcomes are delivered
 * off the response path, so reads poll instead of assuming they have arrived.
 */
export async function poll(attempt, failure, { timeoutMs = 20_000, everyMs = 100 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const value = await attempt();
    if (value !== undefined) return value;
    if (Date.now() >= deadline) throw new Error(await failure());
    await delay(everyMs);
  }
}

export async function startHarness() {
  if (!existsSync(BINARY)) {
    throw new Error(`${BINARY} is missing: run \`pnpm test\`, which builds it first.`);
  }
  child = spawn(BINARY, [], { cwd: REPO_ROOT, stdio: ['ignore', 'pipe', 'pipe'] });

  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr = (stderr + chunk).slice(-8_000);
  });

  let stdout = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    harness.baseUrl = stdout.match(/^E2E_BASE_URL=(\S+)$/m)?.[1] ?? '';
    harness.mailUrl = stdout.match(/^E2E_MAIL_URL=(\S+)$/m)?.[1] ?? '';
  });

  await poll(
    () => {
      if (child.exitCode !== null) throw new Error(`The e2e harness exited early:\n${stderr}`);
      return harness.baseUrl && harness.mailUrl ? true : undefined;
    },
    () => `The e2e harness never printed its origins:\n${stderr}`,
    { timeoutMs: 60_000 }
  );
}

export async function stopHarness() {
  if (!child || child.exitCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  const force = setTimeout(() => child.kill('SIGKILL'), 5000);
  await exited;
  clearTimeout(force);
}

/** A JSON call to the harness's own endpoints. */
async function call(method, route, query = {}) {
  const url = `${harness.mailUrl}${route}?${new URLSearchParams(query)}`;
  const response = await fetch(url, { method });
  if (!response.ok) throw new Error(`${method} ${url} failed with ${response.status}`);
  return method === 'DELETE' ? null : response.json();
}

// ----- capture mailbox -------------------------------------------------------

export const clearMail = () => call('DELETE', '/messages');

const describeMailbox = async () => {
  const captured = await call('GET', '/messages');
  return `the mailbox holds ${captured.length}: ${captured.map((m) => JSON.stringify(m.subject)).join(', ')}`;
};

/** Every captured link matching `pattern` (global), oldest first. */
export async function mailLinks(pattern) {
  const captured = await call('GET', '/messages');
  return captured.flatMap((message) => `${message.text}\n${message.html}`.match(pattern) ?? []);
}

/** The newest captured link matching `pattern`, polling until one arrives. */
export const latestMailLink = (pattern) =>
  poll(
    async () => (await mailLinks(pattern)).at(-1),
    async () => `No link matching ${pattern}: ${await describeMailbox()}`
  );

/** The newest captured message with an exact subject, polling until one arrives. */
export const latestMailBySubject = (subject) =>
  poll(
    async () => (await call('GET', '/messages')).findLast((message) => message.subject === subject),
    async () => `No message with subject ${JSON.stringify(subject)}: ${await describeMailbox()}`
  );

// ----- pairing ---------------------------------------------------------------

/** A fresh key per seed, as a real pairing mints a new key each time. */
let seedKey = 0;

/**
 * Seeds a pending pairing, the way `weave pair` would open one, and returns its
 * `{ handle, fingerprint }`. `target` is `{ machine: '<hostname>' }` for a new
 * machine or `{ machine_id: <id> }` for an existing one moving onto a new key.
 */
export const seedPairing = (target) =>
  call('POST', '/pair/seed', { key: String((seedKey++ % 254) + 1), ...target });

/** The link the CLI prints for a handle, built by the CLI's own code. */
export const pairingUrl = async (handle) => (await call('GET', '/pair/link', { handle })).url;

/** What the stand-in terminal was told: `{ type: 'approved' | 'failed', … }`. */
export const pairingOutcome = (handle) =>
  poll(
    async () => {
      const outcome = await call('GET', '/pair/outcome', { handle });
      return outcome.state === 'pending' ? undefined : outcome;
    },
    () => 'The terminal never received an outcome for this pairing.',
    { timeoutMs: 10_000, everyMs: 50 }
  );
