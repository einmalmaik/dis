/**
 * dis-integrity — hashing and verification helpers.
 *
 * Provides SHA-256 digests (base64) and constant-time comparison. Used for
 * file-chunk integrity, manifest roots, and any place that must verify a
 * payload has not been altered. Confidential payloads still rely on AEAD;
 * these helpers cover integrity of already-encrypted / public material.
 */

import { subtle } from '../core/provider.js';
import {
    base64ToBytes,
    bytesToBase64,
    bytesToBase64Url,
    bytesToHex,
    utf8ToBytes,
} from '../core/encoding.js';
import { DisIntegrityError } from '../core/errors.js';

/** SHA-256 of raw bytes, returned as a fresh `Uint8Array` digest. */
export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
    const digest = await subtle().digest('SHA-256', data as BufferSource);
    return new Uint8Array(digest);
}

/** SHA-256 of raw bytes, base64-encoded. */
export async function sha256Base64(data: Uint8Array): Promise<string> {
    return bytesToBase64(await sha256Bytes(data));
}

/** SHA-256 of raw bytes, unpadded-base64url-encoded. */
export async function sha256Base64Url(data: Uint8Array): Promise<string> {
    return bytesToBase64Url(await sha256Bytes(data));
}

/** SHA-256 of raw bytes, lower-case hex-encoded. */
export async function sha256Hex(data: Uint8Array): Promise<string> {
    return bytesToHex(await sha256Bytes(data));
}

/**
 * SHA-1 of raw bytes, lower-case hex-encoded.
 *
 * SHA-1 is collision-broken and MUST NOT be used for any security decision.
 * It is provided solely for legacy interop where a remote protocol mandates
 * it — specifically the HaveIBeenPwned k-anonymity range API, which keys on
 * the SHA-1 of the password. Callers uppercase the hex as the API requires.
 */
export async function sha1Hex(data: Uint8Array): Promise<string> {
    const digest = await subtle().digest('SHA-1', data as BufferSource);
    return bytesToHex(new Uint8Array(digest));
}

/** Imports raw bytes as an HMAC-SHA-256 key. */
export async function importHmacSha256Key(
    keyBytes: Uint8Array,
    usages: KeyUsage[] = ['sign', 'verify'],
): Promise<CryptoKey> {
    return subtle().importKey(
        'raw',
        keyBytes as BufferSource,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        usages,
    );
}

/** Computes HMAC-SHA-256 over `data` with an already-imported key. */
export async function hmacSha256WithKey(key: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const sig = await subtle().sign('HMAC', key, data as BufferSource);
    return new Uint8Array(sig);
}

/** Computes HMAC-SHA-256 over `data` with raw key bytes. */
export async function hmacSha256(keyBytes: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
    const key = await importHmacSha256Key(keyBytes, ['sign']);
    return hmacSha256WithKey(key, data);
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
