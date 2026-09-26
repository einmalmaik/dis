/**
 * dis-altcha — Proof-of-Work CAPTCHA (ALTCHA) challenge generation and verification.
 *
 * Provides local, self-hosted, privacy-first Proof-of-Work CAPTCHA generation
 * and verification via DIS cryptographic primitives (HMAC-SHA-256, SHA-256 hex,
 * and constant-time signature equality).
 */

import {
  sha256Hex,
  hmacSha256WithKey,
  importHmacSha256Key,
  constantTimeEqual,
} from '../integrity/index.js';
import { randomBytes, randomInt } from '../random/index.js';
import { utf8ToBytes, bytesToHex } from '../core/encoding.js';
import { DisInvalidArgumentError } from '../core/errors.js';

export interface AltchaChallenge {
  algorithm: 'SHA-256';
  challenge: string;
  maxnumber: number;
  salt: string;
  signature: string;
}

export interface AltchaPayload {
  algorithm: string;
  challenge: string;
  number: number;
  salt: string;
  signature: string;
}

export interface CreateAltchaChallengeOptions {
  /** Maximum number range for the random target nonce. Defaults to 50,000. */
  maxnumber?: number;
  /** Challenge lifetime in seconds. Defaults to 300 (5 minutes). */
  expiresInSeconds?: number;
}

/**
 * Creates an ALTCHA Proof-of-Work challenge signed with HMAC-SHA-256.
 */
export async function createAltchaChallenge(
  hmacKey: CryptoKey | Uint8Array,
  options: CreateAltchaChallengeOptions = {},
): Promise<AltchaChallenge> {
  const maxnumber = options.maxnumber ?? 50000;
  if (maxnumber < 1) {
    throw new DisInvalidArgumentError('maxnumber must be >= 1');
  }
  const expiresInSeconds = options.expiresInSeconds ?? 300;
  if (expiresInSeconds < 1) {
    throw new DisInvalidArgumentError('expiresInSeconds must be >= 1');
  }

  const expiresAt = Math.floor(Date.now() / 1000) + expiresInSeconds;
  const saltHex = bytesToHex(randomBytes(16));
  const salt = `${saltHex}?expires=${expiresAt}`;
  const targetNumber = randomInt(0, maxnumber);

  const challenge = await sha256Hex(utf8ToBytes(salt + targetNumber));

  const key = hmacKey instanceof Uint8Array
    ? await importHmacSha256Key(hmacKey, ['sign'])
    : hmacKey;

  const sigBytes = await hmacSha256WithKey(key, utf8ToBytes(challenge));
  const signature = bytesToHex(sigBytes);

  return {
    algorithm: 'SHA-256',
    challenge,
    maxnumber,
    salt,
    signature,
  };
}

/**
 * Verifies an ALTCHA solution payload.
 *
 * Checks:
 * 1. Valid payload structure and SHA-256 algorithm.
 * 2. Salt expiration timestamp.
 * 3. Replay prevention via optional replayCache (Map or Set).
 * 4. Constant-time HMAC-SHA-256 signature verification.
 * 5. Proof-of-Work verification: SHA-256(salt + number) === challenge.
 */
export async function verifyAltchaSolution(
  hmacKey: CryptoKey | Uint8Array,
  payload: string | AltchaPayload,
  replayCache?: Map<string, number> | Set<string>,
): Promise<{ valid: boolean; signature?: string; expiresAt?: number }> {
  let parsed: AltchaPayload;
  if (typeof payload === 'string') {
    try {
      // Decode base64 or URL-safe base64
      const normalized = payload.replace(/-/g, '+').replace(/_/g, '/');
      const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
      const jsonStr = atob(padded);
      parsed = JSON.parse(jsonStr);
    } catch {
      return { valid: false };
    }
  } else if (typeof payload === 'object' && payload !== null) {
    parsed = payload;
  } else {
    return { valid: false };
  }

  if (
    !parsed ||
    parsed.algorithm !== 'SHA-256' ||
    typeof parsed.challenge !== 'string' ||
    typeof parsed.salt !== 'string' ||
    typeof parsed.signature !== 'string' ||
    typeof parsed.number !== 'number' ||
    !Number.isInteger(parsed.number) ||
    parsed.number < 0
  ) {
    return { valid: false };
  }

  // Check expiry parameter in salt
  const qIndex = parsed.salt.indexOf('?');
  if (qIndex === -1) {
    return { valid: false };
  }
  const params = new URLSearchParams(parsed.salt.slice(qIndex + 1));
  const expiresStr = params.get('expires');
  if (!expiresStr) {
    return { valid: false };
  }
  const expiresAt = parseInt(expiresStr, 10);
  const now = Math.floor(Date.now() / 1000);
  if (isNaN(expiresAt) || expiresAt < now) {
    return { valid: false };
  }

  // Replay check
  if (replayCache) {
    if (replayCache instanceof Map) {
      if (replayCache.has(parsed.signature)) {
        return { valid: false };
      }
    } else if (replayCache instanceof Set) {
      if (replayCache.has(parsed.signature)) {
        return { valid: false };
      }
    }
  }

  // Verify HMAC signature in constant time
  const key = hmacKey instanceof Uint8Array
    ? await importHmacSha256Key(hmacKey, ['sign'])
    : hmacKey;

  const expectedSigBytes = await hmacSha256WithKey(key, utf8ToBytes(parsed.challenge));
  const expectedSig = bytesToHex(expectedSigBytes);

  const expectedSigBuf = utf8ToBytes(expectedSig);
  const suppliedSigBuf = utf8ToBytes(parsed.signature);

  if (
    expectedSigBuf.length !== suppliedSigBuf.length ||
    !constantTimeEqual(expectedSigBuf, suppliedSigBuf)
  ) {
    return { valid: false };
  }

  // Verify Proof-of-Work
  const computedChallenge = await sha256Hex(utf8ToBytes(parsed.salt + parsed.number));
  if (computedChallenge.toLowerCase() !== parsed.challenge.toLowerCase()) {
    return { valid: false };
  }

  // Record in replay cache
  if (replayCache) {
    if (replayCache instanceof Map) {
      replayCache.set(parsed.signature, expiresAt * 1000);
    } else if (replayCache instanceof Set) {
      replayCache.add(parsed.signature);
    }
  }

  return {
    valid: true,
    signature: parsed.signature,
    expiresAt,
  };
}

/**
 * Solves an ALTCHA challenge (Proof-of-Work) by finding the nonce.
 * Returns the base64-encoded solution payload. Useful for client-side and tests.
 */
export async function solveAltchaChallenge(challenge: AltchaChallenge): Promise<string> {
  const max = challenge.maxnumber;
  for (let i = 0; i <= max; i++) {
    const hash = await sha256Hex(utf8ToBytes(challenge.salt + i));
    if (hash.toLowerCase() === challenge.challenge.toLowerCase()) {
      const solution: AltchaPayload = {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number: i,
        salt: challenge.salt,
        signature: challenge.signature,
      };
      return btoa(JSON.stringify(solution));
    }
  }
  throw new Error('Could not solve ALTCHA challenge within maxnumber range');
}
