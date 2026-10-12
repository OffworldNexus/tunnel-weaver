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
