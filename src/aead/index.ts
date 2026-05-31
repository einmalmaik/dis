/**
 * dis-aead — authenticated encryption with associated data.
 *
 * Primitive: AES-256-GCM via WebCrypto. Output format is
 * `base64(IV(12) || ciphertext || authTag(16))`, byte-compatible with Singra
 * Vault. A fresh random 96-bit IV is generated per call. Associated data (AAD)
 * is authenticated but not stored; the same AAD must be supplied on decrypt,
 * which lets callers bind ciphertext to a context (e.g. an entry id) and defeat
 * ciphertext-swap attacks.
 */

import { subtle, getCryptoProvider } from '../core/provider.js';
import {
    base64ToBytes,
    bytesToBase64,
    bytesToUtf8,
    utf8ToBytes,
} from '../core/encoding.js';
import { AES_GCM_IV_LENGTH, AES_GCM_TAG_LENGTH } from '../core/constants.js';
import { DisDecryptionError, DisInvalidArgumentError } from '../core/errors.js';

function aad(value?: string): Uint8Array | undefined {
    return value ? utf8ToBytes(value) : undefined;
}

/** Encrypts bytes with AES-256-GCM. Caller still owns/wipes `plaintextBytes`. */
export async function encryptBytes(
    plaintextBytes: Uint8Array,
    key: CryptoKey,
    associatedData?: string,
): Promise<string> {
    const iv = new Uint8Array(AES_GCM_IV_LENGTH);
    getCryptoProvider().getRandomValues(iv);
    const additionalData = aad(associatedData);
    let ciphertextBytes: Uint8Array | null = null;
    let combined: Uint8Array | null = null;
    try {
        const ciphertext = await subtle().encrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: AES_GCM_TAG_LENGTH,
                ...(additionalData && { additionalData }),
            },
            key,
            plaintextBytes as BufferSource,
        );
        ciphertextBytes = new Uint8Array(ciphertext);
        combined = new Uint8Array(iv.length + ciphertextBytes.byteLength);
        combined.set(iv, 0);
        combined.set(ciphertextBytes, iv.length);
        return bytesToBase64(combined);
    } finally {
        iv.fill(0);
        additionalData?.fill(0);
        ciphertextBytes?.fill(0);
        combined?.fill(0);
    }
}

/** Decrypts AES-256-GCM bytes. Returned buffer is secret — caller must wipe it. */
export async function decryptBytes(
    encryptedBase64: string,
    key: CryptoKey,
    associatedData?: string,
): Promise<Uint8Array> {
    const combined = base64ToBytes(encryptedBase64);
    if (combined.length <= AES_GCM_IV_LENGTH) {
        combined.fill(0);
        throw new DisInvalidArgumentError('Invalid encrypted data');
    }
    const iv = combined.slice(0, AES_GCM_IV_LENGTH);
    const ciphertext = combined.slice(AES_GCM_IV_LENGTH);
    const additionalData = aad(associatedData);
    try {
        const plaintext = await subtle().decrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: AES_GCM_TAG_LENGTH,
                ...(additionalData && { additionalData }),
            },
            key,
            ciphertext as BufferSource,
        );
        return new Uint8Array(plaintext);
    } catch {
        // Do not distinguish wrong-key / tampered / AAD-mismatch (no oracle).
        throw new DisDecryptionError();
    } finally {
        combined.fill(0);
        iv.fill(0);
        ciphertext.fill(0);
        additionalData?.fill(0);
    }
}

/** Encrypts a UTF-8 string. The intermediate plaintext bytes are wiped. */
export async function encryptString(
    plaintext: string,
    key: CryptoKey,
    associatedData?: string,
): Promise<string> {
    const plaintextBytes = utf8ToBytes(plaintext);
    try {
        return await encryptBytes(plaintextBytes, key, associatedData);
    } finally {
        plaintextBytes.fill(0);
    }
}

/** Decrypts to a UTF-8 string. The intermediate plaintext bytes are wiped. */
export async function decryptString(
    encryptedBase64: string,
    key: CryptoKey,
    associatedData?: string,
): Promise<string> {
    let plaintextBytes: Uint8Array | null = null;
    try {
        plaintextBytes = await decryptBytes(encryptedBase64, key, associatedData);
        return bytesToUtf8(plaintextBytes);
    } finally {
        plaintextBytes?.fill(0);
    }
}
