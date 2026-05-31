import { describe, expect, it } from 'vitest';
import { decryptBytes, decryptString, encryptBytes, encryptString } from './index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { base64ToBytes } from '../core/encoding.js';
import { randomBytes } from '../random/index.js';
import { DisDecryptionError, DisInvalidArgumentError } from '../core/errors.js';

async function freshKey(): Promise<CryptoKey> {
    return importAesGcmKey(randomBytes(32));
}

describe('aead AES-256-GCM', () => {
    it('round-trips strings', async () => {
        const key = await freshKey();
        const ct = await encryptString('hello world', key);
        expect(await decryptString(ct, key)).toBe('hello world');
    });

    it('round-trips bytes', async () => {
        const key = await freshKey();
        const data = randomBytes(100);
        const ct = await encryptBytes(data, key);
        const pt = await decryptBytes(ct, key);
        expect([...pt]).toEqual([...data]);
    });

    it('uses a fresh random IV per call (no nonce reuse)', async () => {
        const key = await freshKey();
        const a = await encryptString('same', key);
        const b = await encryptString('same', key);
        expect(a).not.toBe(b);
        // First 12 bytes are the IV; they must differ.
        expect(base64ToBytes(a).slice(0, 12)).not.toEqual(base64ToBytes(b).slice(0, 12));
    });

    it('authenticates AAD: wrong AAD fails to decrypt', async () => {
        const key = await freshKey();
        const ct = await encryptString('secret', key, 'entry-1');
        await expect(decryptString(ct, key, 'entry-2')).rejects.toBeInstanceOf(DisDecryptionError);
        await expect(decryptString(ct, key)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('fails closed on tampered ciphertext', async () => {
        const key = await freshKey();
        const ct = await encryptString('secret', key);
        const bytes = base64ToBytes(ct);
        bytes[bytes.length - 1] ^= 0xff;
        const tampered = btoa(String.fromCharCode(...bytes));
        await expect(decryptString(tampered, key)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('rejects too-short ciphertext', async () => {
        const key = await freshKey();
        await expect(decryptBytes('AAAA', key)).rejects.toBeInstanceOf(DisInvalidArgumentError);
    });

    it('does not decrypt under a different key', async () => {
        const ct = await encryptString('secret', await freshKey());
        await expect(decryptString(ct, await freshKey())).rejects.toBeInstanceOf(DisDecryptionError);
    });
});
