import { describe, expect, it } from 'vitest';
import {
    CURRENT_KDF_VERSION,
    DEFAULT_KDF_PARAMS,
    deriveAesGcmKey,
    deriveRawKey,
    generateSalt,
} from './index.js';
import { encryptString, decryptString } from '../aead/index.js';
import { bytesToBase64 } from '../core/encoding.js';
import { DisError } from '../core/errors.js';

describe('kdf Argon2id', () => {
    const salt = bytesToBase64(new Uint8Array(16).fill(7));

    it('is deterministic for the same password/salt/version', async () => {
        const a = await deriveRawKey('correct horse', salt, { version: 1 });
        const b = await deriveRawKey('correct horse', salt, { version: 1 });
        expect([...a]).toEqual([...b]);
        expect(a.length).toBe(32);
    });

    it('produces different output for different versions (param separation)', async () => {
        const v1 = await deriveRawKey('pw', salt, { version: 1 });
        const v2 = await deriveRawKey('pw', salt, { version: 2 });
        expect([...v1]).not.toEqual([...v2]);
    });

    it('produces different output for different passwords', async () => {
        const a = await deriveRawKey('pw-a', salt, { version: 1 });
        const b = await deriveRawKey('pw-b', salt, { version: 1 });
        expect([...a]).not.toEqual([...b]);
    });

    it('throws on unknown KDF version', async () => {
        await expect(deriveRawKey('pw', salt, { version: 999 })).rejects.toBeInstanceOf(DisError);
    });

    it('derives a usable AES-GCM key', async () => {
        const key = await deriveAesGcmKey('pw', salt, { version: CURRENT_KDF_VERSION });
        const ct = await encryptString('data', key);
        expect(await decryptString(ct, key)).toBe('data');
    });

    it('HKDF strengthening changes the derived key', async () => {
        const base = await deriveRawKey('pw', salt, { version: 1 });
        const strengthened = await deriveRawKey('pw', salt, {
            version: 1,
            strengthen: { hkdfSalt: new Uint8Array(32).fill(9), info: 'device-key-v1' },
        });
        expect([...base]).not.toEqual([...strengthened]);
        expect(strengthened.length).toBe(32);
    });

    it('generates 16-byte salts', () => {
        const s = generateSalt();
        expect(atob(s).length).toBe(16);
        expect(generateSalt()).not.toBe(s);
    });

    it('keeps released v1/v2 parameters immutable', () => {
        expect(DEFAULT_KDF_PARAMS[1]).toEqual({
            memory: 65536,
            iterations: 3,
            parallelism: 4,
            hashLength: 32,
        });
        expect(DEFAULT_KDF_PARAMS[2]!.memory).toBe(131072);
    });
});
