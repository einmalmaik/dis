/**
 * dis-integrity — hashing and verification helpers.
 *
 * Provides SHA-256 digests (base64) and constant-time comparison. Used for
 * file-chunk integrity, manifest roots, and any place that must verify a
 * payload has not been altered. Confidential payloads still rely on AEAD;
 * these helpers cover integrity of already-encrypted / public material.
 */

import { subtle } from '../core/provider.js';
import { base64ToBytes, bytesToBase64, utf8ToBytes } from '../core/encoding.js';
import { DisIntegrityError } from '../core/errors.js';

/** SHA-256 of raw bytes, base64-encoded. */
export async function sha256Base64(data: Uint8Array): Promise<string> {
    const digest = await subtle().digest('SHA-256', data as BufferSource);
    return bytesToBase64(new Uint8Array(digest));
}

/** SHA-256 of a UTF-8 string, base64-encoded. */
export async function sha256StringBase64(data: string): Promise<string> {
    return sha256Base64(utf8ToBytes(data));
}

/** SHA-256 of the JSON serialisation of `value`, base64-encoded. */
export async function sha256JsonBase64(value: unknown): Promise<string> {
    return sha256StringBase64(JSON.stringify(value));
}

/** Constant-time equality of two byte arrays. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a[i]! ^ b[i]!;
    }
    return result === 0;
}

/** Constant-time equality of two base64 strings (compared as decoded bytes). */
export function constantTimeEqualBase64(a: string, b: string): boolean {
    return constantTimeEqual(base64ToBytes(a), base64ToBytes(b));
}

/**
 * Verifies that `data` hashes (SHA-256) to `expectedBase64`, throwing
 * {@link DisIntegrityError} on mismatch. Comparison is constant-time.
 */
export async function verifyPayloadIntegrity(
    data: Uint8Array,
    expectedBase64: string,
): Promise<void> {
    const actual = await sha256Base64(data);
    if (!constantTimeEqualBase64(actual, expectedBase64)) {
        throw new DisIntegrityError();
    }
}
