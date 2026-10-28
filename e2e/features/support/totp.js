/**
 * Everything an authenticator app does, so a scenario can be the app (WVR-166).
 *
 * This is a plain function of `(secret, time)`, exactly as
 * `crates/weaver-server/src/account/totp.rs` is: RFC 6238 TOTP — base32-decode
 * the key the relay spelled out, HMAC-SHA-1 over the big-endian step, then
 * RFC 4226's dynamic truncation. No state, so the relay and the test agree on a
 * code without agreeing on anything but the clock. `node:crypto` is all it
 * needs; no new dependency.
 */

import { createHmac } from 'node:crypto';

/**
 * RFC 6238's own test secret, in the base32 the Setup key carries: the ASCII
 * digits `12345678901234567890`. Its codes are the RFC's table, so a wrong
 * implementation here cannot pass silently — at T = 59 it shows `287082` (six
 * digits, this relay's width) or `94287082` (the RFC's eight).
 */
export const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

/**
 * Unpadded RFC 4648 base32 -> bytes, the spelling an authenticator app accepts.
 *
 * Production never decodes one — the relay generates its own secrets and only
 * ever spells them out — so this exists for the tests alone. Bits are masked to
 * what has not been emitted yet, so the accumulator stays a small exact integer
 * rather than running off the end of JavaScript's 32-bit bitwise operators.
 */
export function base32Decode(encoded) {
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const out = [];
  let bits = 0;
  let held = 0;
  for (const char of encoded.trim().replace(/=+$/, '').toUpperCase()) {
    const value = ALPHABET.indexOf(char);
    if (value < 0) throw new Error(`Not a base32 character: ${JSON.stringify(char)}`);
    bits = bits * 32 + value;
    held += 5;
    while (held >= 8) {
      held -= 8;
      out.push((bits >> held) & 0xff);
      bits &= (1 << held) - 1;
    }
  }
  return Buffer.from(out);
}

/**
 * The code an app holding `base32` shows at `at`.
 *
 * `at` defaults to now, and a caller asks for the *step* it means by passing a
 * time inside it, because a step is 30 s wide: `Date.now() + 30_000` is exactly
 * the next step, `Date.now() - 30_000` the one before. That distinction is what
 * a sign-in after a confirmation needs — the relay accepts one step either side
 * of now, and confirming an enrolment burns the step it used, so the very same
 * code is then refused ("That code has already been used."). The confirming
 * step is always ≤ now, which makes now + 30 s strictly ahead of it and still
 * inside the window, so no step boundary has to be waited for.
 */
export function totpCode(base32, { at = Date.now(), digits = 6, stepSecs = 30 } = {}) {
  const step = Math.floor(at / 1000 / stepSecs);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const digest = createHmac('sha1', base32Decode(base32)).update(counter).digest();
  // RFC 4226's dynamic truncation: the low nibble of the last byte picks the
  // four bytes to use, and the top bit is dropped so the result stays positive.
  const offset = digest[digest.length - 1] & 0x0f;
  const truncated = digest.readUInt32BE(offset) & 0x7fffffff;
  return String(truncated % 10 ** digits).padStart(digits, '0');
}
