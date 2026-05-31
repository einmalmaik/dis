import { describe, expect, it } from 'vitest';
import {
    constantTimeEqual,
    sha256StringBase64,
    verifyPayloadIntegrity,
} from './index.js';
import { utf8ToBytes } from '../core/encoding.js';
import { DisIntegrityError } from '../core/errors.js';

describe('integrity', () => {
    it('matches the known SHA-256 vector for "abc"', async () => {
        // SHA-256("abc") = ba7816bf... ; base64 of that digest:
        expect(await sha256StringBase64('abc')).toBe('ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=');
    });

    it('constant-time equality', () => {
        expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2]))).toBe(true);
        expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 3]))).toBe(false);
        expect(constantTimeEqual(new Uint8Array([1]), new Uint8Array([1, 2]))).toBe(false);
    });

    it('verifyPayloadIntegrity passes on match and throws on mismatch', async () => {
        const data = utf8ToBytes('payload');
        const expected = await sha256StringBase64('payload');
        await expect(verifyPayloadIntegrity(data, expected)).resolves.toBeUndefined();
        await expect(
            verifyPayloadIntegrity(utf8ToBytes('tampered'), expected),
        ).rejects.toBeInstanceOf(DisIntegrityError);
    });
});
