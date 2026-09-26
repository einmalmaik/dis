/**
 * dis-altcha — Proof-of-Work CAPTCHA (ALTCHA) challenge generation and verification.
 *
 * Provides local, self-hosted, privacy-first Proof-of-Work CAPTCHA generation
 * and verification via DIS cryptographic primitives (HMAC-SHA-256, SHA-256 hex,
 * and constant-time signature equality).
 */
interface AltchaChallenge {
    algorithm: 'SHA-256';
    challenge: string;
    maxnumber: number;
    salt: string;
    signature: string;
}
interface AltchaPayload {
    algorithm: string;
    challenge: string;
    number: number;
    salt: string;
    signature: string;
}
interface CreateAltchaChallengeOptions {
    /** Maximum number range for the random target nonce. Defaults to 50,000. */
    maxnumber?: number;
    /** Challenge lifetime in seconds. Defaults to 300 (5 minutes). */
    expiresInSeconds?: number;
}
/**
 * Creates an ALTCHA Proof-of-Work challenge signed with HMAC-SHA-256.
 */
declare function createAltchaChallenge(hmacKey: CryptoKey | Uint8Array, options?: CreateAltchaChallengeOptions): Promise<AltchaChallenge>;
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
declare function verifyAltchaSolution(hmacKey: CryptoKey | Uint8Array, payload: string | AltchaPayload, replayCache?: Map<string, number> | Set<string>): Promise<{
    valid: boolean;
    signature?: string;
    expiresAt?: number;
}>;
/**
 * Solves an ALTCHA challenge (Proof-of-Work) by finding the nonce.
 * Returns the base64-encoded solution payload. Useful for client-side and tests.
 */
declare function solveAltchaChallenge(challenge: AltchaChallenge): Promise<string>;

export { type AltchaChallenge, type AltchaPayload, type CreateAltchaChallengeOptions, createAltchaChallenge, solveAltchaChallenge, verifyAltchaSolution };
