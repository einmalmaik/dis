/**
 * Phase 1 GATE — Singra ⇄ DIS byte-compatibility golden vectors.
 *
 * These vectors were produced by the *legacy* in-tree Singra `cryptoService`
 * (singravault) and are hard-coded here so DIS proves — in its own CI, with no
 * dependency on the apps — that it stays byte-compatible with already-stored
 * production ciphertext. If any of these break, the apps can NO LONGER read
 * data sealed by older builds: treat a failure here as a release blocker.
 *
 * Inputs are deterministic (fixed password + fixed salt). KDF outputs are
 * asserted exactly; AEAD/vault/user-key vectors assert that DIS decrypts the
 * exact bytes legacy Singra wrote (random-IV ciphertexts can't be reproduced,
 * only decrypted).
 */
import { describe, expect, it } from 'vitest';
import {
    deriveRawKey,
    deriveMasterKey,
    decryptString,
    decryptVaultEntry,
    unwrapUserKeyBytes,
} from '../index.js';

const PW = 'correct horse battery staple';
const SALT = 'ZGV0ZXJtaW5pc3RpYy1zYWx0LTE2Qg==';

const b64ToBytes = (b64: string): Uint8Array =>
    Uint8Array.from(Buffer.from(b64, 'base64'));

describe('Singra golden vectors (legacy → DIS)', () => {
    it('KDF v1/v2: DIS reproduces the exact Argon2id bytes legacy derived', async () => {
        const vectors: Record<1 | 2, string> = {
            1: '1ehUGlF3Tb7w90vk/872uy/4uLebUW/Vzz6b6eAoGiM=',
            2: 'SF/WwUBBYz38cCp0KAmtN0dPq+O5lpGfFs5I89HfWZI=',
        };
        for (const version of [1, 2] as const) {
            const raw = await deriveRawKey(PW, SALT, { version });
            expect([...raw]).toEqual([...b64ToBytes(vectors[version])]);
            raw.fill(0);
        }
    });

    it('AEAD: DIS decrypts legacy ciphertext (with + without AAD)', async () => {
        const key = await deriveMasterKey(PW, SALT, { version: 2 });
        const withAad = '1lXWfk5cncBHIX2ntRh54N0TiwIkNL0WNdA4m2vM/6fQI/wcAw==';
        const noAad = 'GOi+biTwduypJ/A9MCzWWgV3UuS0gWkQd/KZGbdLx7FB/C7nzDPUOdny3uI=';
        expect(await decryptString(withAad, key, 'aad-1')).toBe('hello DIS');
        expect(await decryptString(noAad, key)).toBe('hello DIS no aad');
    });

    it('Vault item: DIS decrypts the legacy sv-vault-v1 envelope (entryId AAD)', async () => {
        const key = await deriveMasterKey(PW, SALT, { version: 2 });
        const entryId = '11111111-1111-4111-8111-111111111111';
        const sealed =
            'sv-vault-v1:nOVpHlEQUrM/okRGd9iJZU/LyfYx5A0a3VAzAbjRWNhutkew4vmfTZML4oUTbJChb4pNblxsEE/mLRAuJJl0KgHmuFhM+bH1CPFDLBwokh8=';
        expect(await decryptVaultEntry(sealed, key, entryId)).toEqual({
            username: 'alice',
            password: 's3cret',
            notes: 'n',
        });
    });

    it('User key wrap: DIS unwraps the legacy usk-wrap-v2 bundle to 32 bytes', async () => {
        const kdfOut = await deriveRawKey(PW, SALT, { version: 2 });
        const encryptedUserKey =
            'usk-wrap-v2:OcV0IQUJiYf5E3f1a144DuFJnoy8l6cSx2tyfl09GZED0iwWm5A96tkMyq6+3G/Ao6TQw/GBNGw7UK06';
        const userKey = await unwrapUserKeyBytes(encryptedUserKey, kdfOut);
        expect(userKey.length).toBe(32);
        kdfOut.fill(0);
        userKey.fill(0);
    });
});
