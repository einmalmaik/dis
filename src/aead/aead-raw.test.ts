import { describe, expect, it } from 'vitest';
import {
    aesGcmDecrypt,
    aesGcmEncrypt,
    generateAesGcmKey,
    importAesGcmRawKey,
} from './index.js';
import { utf8ToBytes } from '../core/encoding.js';
import { DisDecryptionError } from '../core/errors.js';

const KEY = new Uint8Array(32).fill(5);
const NONCE = new Uint8Array(12).fill(9);

describe('aead — raw AES-256-GCM', () => {
    it('round-trips with raw key bytes (ciphertext = ct||tag, no nonce prefix)', async () => {
        const pt = utf8ToBytes('op-log record plaintext');
        const ct = await aesGcmEncrypt(KEY, NONCE, pt);
        // ciphertext length = plaintext + 16-byte tag
        expect(ct.length).toBe(pt.length + 16);
        const back = await aesGcmDecrypt(KEY, NONCE, ct);
        expect(Array.from(back)).toEqual(Array.from(pt));
    });

    it('binds associated data', async () => {
        const pt = utf8ToBytes('payload');
        const aad = utf8ToBytes('record-aad');
        const ct = await aesGcmEncrypt(KEY, NONCE, pt, aad);
        const ok = await aesGcmDecrypt(KEY, NONCE, ct, aad);
        expect(Array.from(ok)).toEqual(Array.from(pt));
        await expect(aesGcmDecrypt(KEY, NONCE, ct, utf8ToBytes('wrong-aad')))
            .rejects.toBeInstanceOf(DisDecryptionError);
        await expect(aesGcmDecrypt(KEY, NONCE, ct)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('throws DisDecryptionError on tampered ciphertext', async () => {
        const ct = await aesGcmEncrypt(KEY, NONCE, utf8ToBytes('data'));
        ct[0] ^= 0xff;
        await expect(aesGcmDecrypt(KEY, NONCE, ct)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('works with a generated non-extractable key and an imported raw key', async () => {
        const gen = await generateAesGcmKey();
        const nonce = new Uint8Array(12).fill(2);
        const ct = await aesGcmEncrypt(gen, nonce, utf8ToBytes('x'));
        expect(Array.from(await aesGcmDecrypt(gen, nonce, ct))).toEqual(Array.from(utf8ToBytes('x')));

        const imported = await importAesGcmRawKey(KEY, ['encrypt', 'decrypt']);
        const ct2 = await aesGcmEncrypt(imported, NONCE, utf8ToBytes('y'));
        // cross-check: raw-bytes decrypt matches imported-key encrypt
        expect(Array.from(await aesGcmDecrypt(KEY, NONCE, ct2))).toEqual(Array.from(utf8ToBytes('y')));
    });
});
