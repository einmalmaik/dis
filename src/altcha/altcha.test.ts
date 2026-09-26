import { describe, expect, it } from 'vitest';
import {
  createAltchaChallenge,
  verifyAltchaSolution,
  solveAltchaChallenge,
} from './index.js';
import { randomBytes } from '../random/index.js';

describe('dis-altcha', () => {
  const hmacKey = randomBytes(32);

  it('generates a valid challenge and verifies a correct solution', async () => {
    const challenge = await createAltchaChallenge(hmacKey, {
      maxnumber: 500,
      expiresInSeconds: 60,
    });

    expect(challenge.algorithm).toBe('SHA-256');
    expect(challenge.maxnumber).toBe(500);
    expect(challenge.salt).toContain('?expires=');
    expect(typeof challenge.signature).toBe('string');
    expect(challenge.signature).toHaveLength(64); // 32 bytes hex

    const solutionB64 = await solveAltchaChallenge(challenge);
    const replayCache = new Map<string, number>();

    const res1 = await verifyAltchaSolution(hmacKey, solutionB64, replayCache);
    expect(res1.valid).toBe(true);
    expect(res1.signature).toBe(challenge.signature);
    expect(replayCache.has(challenge.signature)).toBe(true);

    // Replay attack must fail
    const res2 = await verifyAltchaSolution(hmacKey, solutionB64, replayCache);
    expect(res2.valid).toBe(false);
  });

  it('rejects tampered number', async () => {
    const challenge = await createAltchaChallenge(hmacKey, { maxnumber: 100 });
    const solutionB64 = await solveAltchaChallenge(challenge);
    const decoded = JSON.parse(atob(solutionB64));

    // Tamper number
    decoded.number = decoded.number + 1;
    const tamperedB64 = btoa(JSON.stringify(decoded));

    const res = await verifyAltchaSolution(hmacKey, tamperedB64);
    expect(res.valid).toBe(false);
  });

  it('rejects forged HMAC signature', async () => {
    const challenge = await createAltchaChallenge(hmacKey, { maxnumber: 100 });
    const solutionB64 = await solveAltchaChallenge(challenge);
    const decoded = JSON.parse(atob(solutionB64));

    // Forge signature
    decoded.signature = '0000000000000000000000000000000000000000000000000000000000000000';
    const tamperedB64 = btoa(JSON.stringify(decoded));

    const res = await verifyAltchaSolution(hmacKey, tamperedB64);
    expect(res.valid).toBe(false);
  });

  it('rejects expired salt', async () => {
    const challenge = await createAltchaChallenge(hmacKey, {
      maxnumber: 100,
      expiresInSeconds: 1,
    });
    const solutionB64 = await solveAltchaChallenge(challenge);

    // Modify salt to be already expired in the past
    const decoded = JSON.parse(atob(solutionB64));
    decoded.salt = decoded.salt.replace(/expires=\d+/, 'expires=1000000000');
    const tamperedB64 = btoa(JSON.stringify(decoded));

    const res = await verifyAltchaSolution(hmacKey, tamperedB64);
    expect(res.valid).toBe(false);
  });

  it('rejects non-base64 or malformed payload fail-closed', async () => {
    expect((await verifyAltchaSolution(hmacKey, 'invalid-base64!!!')).valid).toBe(false);
    expect((await verifyAltchaSolution(hmacKey, btoa('{"not":"altcha"}'))).valid).toBe(false);
  });
});
