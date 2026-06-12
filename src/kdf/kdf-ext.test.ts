import { describe, expect, it } from 'vitest';
import {
    argon2idRaw,
    deriveHkdfAesGcmKey,
    deriveHkdfSha256Bits,
} from './index.js';
import { aesGcmDecrypt, aesGcmEncrypt } from '../aead/index.js';
import { utf8ToBytes } from '../core/encoding.js';

describe('kdf — argon2idRaw', () => {
    it('is deterministic for fixed params and salt', async () => {
        const salt = new Uint8Array(16).fill(7);
        const params = {
            password: 'CODEABCD',
            salt,
            memorySize: 16384,
            iterations: 2,
            parallelism: 1,
            hashLength: 32,
        } as const;
        const a = await argon2idRaw(params);
        const b = await argon2idRaw(params);
        expect(a.length).toBe(32);
        expect(Array.from(a)).toEqual(Array.from(b));
    });

    it('differs when the salt changes', async () => {
        const base = {
            password: 'CODEABCD',
            memorySize: 16384,
            iterations: 2,
            parallelism: 1,
            hashLength: 32,
        };
        const a = await argon2idRaw({ ...base, salt: new Uint8Array(16).fill(1) });
        const b = await argon2idRaw({ ...base, salt: new Uint8Array(16).fill(2) });
        expect(Array.from(a)).not.toEqual(Array.from(b));
    });
});

describe('kdf — HKDF-SHA-256', () => {
    it('deriveHkdfSha256Bits is deterministic and length-controlled', async () => {
        const ikm = utf8ToBytes('input-keying-material');
        const info = utf8ToBytes('context');
        const a = await deriveHkdfSha256Bits(ikm, { info });
        const b = await deriveHkdfSha256Bits(ikm, { info });
        expect(a.length).toBe(32);
        expect(Array.from(a)).toEqual(Array.from(b));
        const long = await deriveHkdfSha256Bits(ikm, { info, lengthBits: 512 });
        expect(long.length).toBe(64);
    });

    it('salt changes the derived bits', async () => {
        const ikm = utf8ToBytes('ikm');
        const info = utf8ToBytes('info');
        const noSalt = await deriveHkdfSha256Bits(ikm, { info });
        const withSalt = await deriveHkdfSha256Bits(ikm, { info, salt: new Uint8Array(32).fill(9) });
        expect(Array.from(noSalt)).not.toEqual(Array.from(withSalt));
    });

    it('deriveHkdfAesGcmKey yields a usable AES-GCM key', async () => {
        const ikm = new Uint8Array(32).fill(3);
        const key = await deriveHkdfAesGcmKey(ikm, { info: utf8ToBytes('wrap') });
        const nonce = new Uint8Array(12).fill(1);
        const pt = utf8ToBytes('secret');
        const ct = await aesGcmEncrypt(key, nonce, pt);
        const back = await aesGcmDecrypt(key, nonce, ct);
        expect(Array.from(back)).toEqual(Array.from(pt));
    });
});
