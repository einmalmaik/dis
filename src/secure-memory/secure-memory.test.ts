import { describe, expect, it } from 'vitest';
import { SecureBuffer, withSecureBuffer, zeroBuffers } from './index.js';
import { DisError } from '../core/errors.js';

describe('SecureBuffer', () => {
    it('zeros contents on destroy and blocks use-after-destroy', () => {
        const buf = SecureBuffer.fromBytes(new Uint8Array([1, 2, 3, 4]));
        expect(buf.use((d) => d.length)).toBe(4);
        buf.destroy();
        expect(buf.isDestroyed).toBe(true);
        expect(() => buf.use((d) => d.length)).toThrowError(DisError);
        // Idempotent destroy.
        expect(() => buf.destroy()).not.toThrow();
    });

    it('compares in constant time via equals', () => {
        const a = SecureBuffer.fromBytes(new Uint8Array([1, 2, 3]));
        expect(a.equals(new Uint8Array([1, 2, 3]))).toBe(true);
        expect(a.equals(new Uint8Array([1, 2, 4]))).toBe(false);
        expect(a.equals(new Uint8Array([1, 2]))).toBe(false);
        a.destroy();
    });

    it('parses hex and rejects invalid hex', () => {
        const buf = SecureBuffer.fromHex('00ff-10');
        expect(buf.toBytes()).toEqual(new Uint8Array([0, 255, 16]));
        buf.destroy();
        expect(() => SecureBuffer.fromHex('zz')).toThrowError(DisError);
        expect(() => SecureBuffer.fromHex('abc')).toThrowError(DisError);
    });

    it('withSecureBuffer always destroys', async () => {
        let captured: SecureBuffer | null = null;
        await withSecureBuffer(new Uint8Array([9, 9]), async (s) => {
            captured = s;
            expect(s.size).toBe(2);
        });
        expect(captured!.isDestroyed).toBe(true);
    });

    it('zeroBuffers tolerates null/undefined', () => {
        const a = new Uint8Array([1, 2]);
        zeroBuffers(a, null, undefined);
        expect([...a]).toEqual([0, 0]);
    });
});
