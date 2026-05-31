import { describe, expect, it } from 'vitest';
import { base64ToBytes, bytesToBase64, bytesToUtf8, concatBytes, utf8ToBytes } from './encoding.js';

describe('encoding', () => {
    it('round-trips base64', () => {
        const data = new Uint8Array([0, 1, 2, 255, 254, 128]);
        expect([...base64ToBytes(bytesToBase64(data))]).toEqual([...data]);
    });

    it('matches known base64 vectors', () => {
        expect(bytesToBase64(utf8ToBytes('hello'))).toBe('aGVsbG8=');
        expect(bytesToUtf8(base64ToBytes('aGVsbG8='))).toBe('hello');
    });

    it('handles large buffers without stack overflow', () => {
        const big = new Uint8Array(200000).map((_, i) => i % 256);
        expect([...base64ToBytes(bytesToBase64(big))]).toEqual([...big]);
    });

    it('concatenates byte arrays', () => {
        expect([...concatBytes(new Uint8Array([1]), new Uint8Array([2, 3]))]).toEqual([1, 2, 3]);
    });
});
