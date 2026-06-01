import { describe, expect, it } from 'vitest';
import {
    createWrappedUserKey,
    rotateWrappedKey,
    unwrapUserKey,
    unwrapUserKeyBytes,
    DEFAULT_KEY_WRAP_SCHEME,
} from './index.js';
import { encryptVaultEntry, decryptVaultEntry } from '../vault-encryption/index.js';
import { randomBytes } from '../random/index.js';

describe('key management', () => {
    it('wraps and unwraps the content key under a KEK', async () => {
        const kdfOut = randomBytes(32);
        const bundle = await createWrappedUserKey(kdfOut);
        expect(bundle.encryptedUserKey.startsWith(DEFAULT_KEY_WRAP_SCHEME.prefix)).toBe(true);

        const unwrapped = await unwrapUserKeyBytes(bundle.encryptedUserKey, kdfOut);
        expect(unwrapped.length).toBe(32);
    });

    it('content key encrypts/decrypts vault data after unwrap', async () => {
        const kdfOut = randomBytes(32);
        const bundle = await createWrappedUserKey(kdfOut);
        const sealed = await encryptVaultEntry({ secret: 42 }, bundle.userKey, 'e1');

        const reUnwrapped = await unwrapUserKey(bundle.encryptedUserKey, kdfOut);
        expect(await decryptVaultEntry(sealed, reUnwrapped, 'e1')).toEqual({ secret: 42 });
    });

    it('rotation re-wraps without changing the content key (no data re-encryption)', async () => {
        const oldKdf = randomBytes(32);
        const newKdf = randomBytes(32);
        const bundle = await createWrappedUserKey(oldKdf);
        const sealed = await encryptVaultEntry({ secret: 'keep-me' }, bundle.userKey, 'e1');

        const rotated = await rotateWrappedKey(bundle.encryptedUserKey, oldKdf, newKdf);
        expect(rotated).not.toBe(bundle.encryptedUserKey);

        // Old KDF output no longer unwraps the rotated key.
        await expect(unwrapUserKeyBytes(rotated, oldKdf)).rejects.toBeTruthy();

        // New KDF output unwraps to the SAME content key — old data still reads.
        const newKey = await unwrapUserKey(rotated, newKdf);
        expect(await decryptVaultEntry(sealed, newKey, 'e1')).toEqual({ secret: 'keep-me' });
    });

    it('fails to unwrap with the wrong KDF output', async () => {
        const bundle = await createWrappedUserKey(randomBytes(32));
        await expect(unwrapUserKeyBytes(bundle.encryptedUserKey, randomBytes(32))).rejects.toBeTruthy();
    });
});
