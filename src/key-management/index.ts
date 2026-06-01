/**
 * dis-key-management — key hierarchy, wrapping, and rotation.
 *
 * Implements the two-tier key model used by Singra Vault:
 *   - A high-entropy random *content key* (the "UserKey") encrypts vault data.
 *   - The content key is wrapped under a *key-encryption key* (KEK) that is
 *     derived from the KDF output via HKDF-Expand (domain-separated `info`).
 *
 * Because the content key is independent of the password, changing the master
 * password only re-wraps the content key — no vault data is re-encrypted. This
 * is what makes {@link rotateWrappedKey} cheap and safe.
 *
 * Wrapped keys carry a stable, versioned prefix. The default scheme is byte
 * compatible with Singra's `usk-wrap-v2:` envelope.
 */

import { decryptBytes, decryptString, encryptBytes } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import { base64ToBytes } from '../core/encoding.js';
import { subtle } from '../core/provider.js';
import { AES_KEY_LENGTH } from '../core/constants.js';
import { DisInvalidArgumentError } from '../core/errors.js';

/** Describes how a content key is wrapped: envelope prefix + HKDF domain. */
export interface KeyWrapScheme {
    /** Stable envelope prefix written for new wraps, e.g. `usk-wrap-v2:`. */
    readonly prefix: string;
    /** HKDF-Expand `info` for deriving the KEK from KDF output. */
    readonly hkdfInfo: string;
}

/**
 * Default wrap scheme. Byte-compatible with Singra Vault so existing
 * `encrypted_user_key` values decrypt unchanged. The `info` label is part of
 * the format contract and must not be renamed without a new scheme version.
 */
export const DEFAULT_KEY_WRAP_SCHEME: KeyWrapScheme = {
    prefix: 'usk-wrap-v2:',
    hkdfInfo: 'singra-vault-wrap-v1',
};

export { importAesGcmKey };

export interface UserKeyBundle {
    /** Wrapped content key: `<prefix><base64(IV||CT||tag)>`. */
    readonly encryptedUserKey: string;
    /** Non-extractable AES-GCM content key, ready for vault operations. */
    readonly userKey: CryptoKey;
}

/** Derives the KEK from raw KDF output via HKDF-Expand (zero salt, RFC 5869). */
async function deriveWrapKeyBytes(
    kdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme,
): Promise<Uint8Array> {
    const baseKey = await subtle().importKey('raw', kdfOutputBytes as BufferSource, 'HKDF', false, [
        'deriveBits',
    ]);
    const bits = await subtle().deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            // Zero salt is correct: IKM is already high-entropy Argon2id output.
            salt: new Uint8Array(32) as BufferSource,
            info: new TextEncoder().encode(scheme.hkdfInfo) as BufferSource,
        },
        baseKey,
        256,
    );
    return new Uint8Array(bits);
}

/** Generates fresh random content-key bytes (caller must wipe). */
export function generateContentKeyBytes(): Uint8Array {
    return randomBytes(AES_KEY_LENGTH);
}

/**
 * Creates a new random content key and wraps it under the KEK derived from
 * `kdfOutputBytes`. For new accounts. The caller still owns `kdfOutputBytes`.
 */
export async function createWrappedUserKey(
    kdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme = DEFAULT_KEY_WRAP_SCHEME,
): Promise<UserKeyBundle> {
    const userKeyBytes = generateContentKeyBytes();
    let wrapKeyBytes: Uint8Array | null = null;
    try {
        wrapKeyBytes = await deriveWrapKeyBytes(kdfOutputBytes, scheme);
        const wrapKey = await importAesGcmKey(wrapKeyBytes);
        const encryptedUserKey = `${scheme.prefix}${await encryptBytes(userKeyBytes, wrapKey)}`;
        const userKey = await importAesGcmKey(userKeyBytes);
        return { encryptedUserKey, userKey };
    } finally {
        userKeyBytes.fill(0);
        wrapKeyBytes?.fill(0);
    }
}

/** Unwraps a wrapped content key to raw bytes (caller must wipe). */
export async function unwrapUserKeyBytes(
    encryptedUserKey: string,
    kdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme = DEFAULT_KEY_WRAP_SCHEME,
): Promise<Uint8Array> {
    let wrapKeyBytes: Uint8Array | null = null;
    try {
        wrapKeyBytes = await deriveWrapKeyBytes(kdfOutputBytes, scheme);
        const wrapKey = await importAesGcmKey(wrapKeyBytes);
        if (encryptedUserKey.startsWith(scheme.prefix)) {
            return await decryptBytes(encryptedUserKey.slice(scheme.prefix.length), wrapKey);
        }
        // Legacy wrappers encrypted a base64 string (no prefix). Read-compatible.
        const userKeyBase64 = await decryptString(encryptedUserKey, wrapKey);
        return base64ToBytes(userKeyBase64);
    } finally {
        wrapKeyBytes?.fill(0);
    }
}

/** Unwraps a wrapped content key and imports it as an AES-GCM CryptoKey. */
export async function unwrapUserKey(
    encryptedUserKey: string,
    kdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme = DEFAULT_KEY_WRAP_SCHEME,
): Promise<CryptoKey> {
    const userKeyBytes = await unwrapUserKeyBytes(encryptedUserKey, kdfOutputBytes, scheme);
    try {
        return await importAesGcmKey(userKeyBytes);
    } finally {
        userKeyBytes.fill(0);
    }
}

/**
 * Wraps a *deterministic* content key derived directly from `kdfOutputBytes`,
 * for EXISTING accounts migrating to the two-tier key model. The content key
 * equals the raw KDF output, so vault data previously encrypted directly under
 * that output remains readable without re-encryption. The KEK is still
 * domain-separated (HKDF `info`), so the wrapper is independent of the key.
 */
export async function createDeterministicWrappedUserKey(
    kdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme = DEFAULT_KEY_WRAP_SCHEME,
): Promise<UserKeyBundle> {
    // Copy so callers can wipe their buffer without aliasing the returned key.
    const userKeyBytes = new Uint8Array(kdfOutputBytes);
    let wrapKeyBytes: Uint8Array | null = null;
    try {
        wrapKeyBytes = await deriveWrapKeyBytes(kdfOutputBytes, scheme);
        const wrapKey = await importAesGcmKey(wrapKeyBytes);
        const encryptedUserKey = `${scheme.prefix}${await encryptBytes(userKeyBytes, wrapKey)}`;
        const userKey = await importAesGcmKey(userKeyBytes);
        return { encryptedUserKey, userKey };
    } finally {
        userKeyBytes.fill(0);
        wrapKeyBytes?.fill(0);
    }
}

/** Generates a fresh AES-256-GCM key and returns it as a JWK JSON string. */
export async function generateAesGcmKeyJwk(): Promise<string> {
    const key = await subtle().generateKey({ name: 'AES-GCM', length: 256 }, true, [
        'encrypt',
        'decrypt',
    ]);
    const jwk = await subtle().exportKey('jwk', key);
    return JSON.stringify(jwk);
}

/** Imports an AES-256-GCM key from a JWK JSON string for the given usages. */
export async function importAesGcmKeyFromJwk(
    jwkString: string,
    usages: ReadonlyArray<KeyUsage>,
): Promise<CryptoKey> {
    const jwk = JSON.parse(jwkString) as JsonWebKey;
    return subtle().importKey('jwk', jwk, { name: 'AES-GCM', length: 256 }, false, [...usages]);
}

/**
 * Re-wraps an existing content key under a new KDF output (new master password
 * / new salt). The content key itself is unchanged, so NO vault data is
 * re-encrypted — only the wrapper string changes.
 */
export async function rotateWrappedKey(
    encryptedUserKey: string,
    oldKdfOutputBytes: Uint8Array,
    newKdfOutputBytes: Uint8Array,
    scheme: KeyWrapScheme = DEFAULT_KEY_WRAP_SCHEME,
): Promise<string> {
    if (!encryptedUserKey) {
        throw new DisInvalidArgumentError('encryptedUserKey is required');
    }
    const userKeyBytes = await unwrapUserKeyBytes(encryptedUserKey, oldKdfOutputBytes, scheme);
    let newWrapKeyBytes: Uint8Array | null = null;
    try {
        newWrapKeyBytes = await deriveWrapKeyBytes(newKdfOutputBytes, scheme);
        const newWrapKey = await importAesGcmKey(newWrapKeyBytes);
        return `${scheme.prefix}${await encryptBytes(userKeyBytes, newWrapKey)}`;
    } finally {
        userKeyBytes.fill(0);
        newWrapKeyBytes?.fill(0);
    }
}
