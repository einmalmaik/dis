import { describe, expect, it } from 'vitest';
import { fillRandom, randomInt } from './index.js';
import { DisInvalidArgumentError } from '../core/errors.js';

describe('random — randomInt', () => {
    it('always returns values within the inclusive range', () => {
        for (let i = 0; i < 2000; i++) {
            const v = randomInt(0, 30); // 31 = backup-code charset size
            expect(v).toBeGreaterThanOrEqual(0);
            expect(v).toBeLessThanOrEqual(30);
            expect(Number.isInteger(v)).toBe(true);
        }
    });

    it('returns the only value for a singleton range', () => {
        expect(randomInt(7, 7)).toBe(7);
    });

    it('covers the full range over many draws', () => {
        const seen = new Set<number>();
        for (let i = 0; i < 5000; i++) seen.add(randomInt(0, 9));
        for (let n = 0; n <= 9; n++) expect(seen.has(n)).toBe(true);
    });

    it('rejects invalid bounds', () => {
        expect(() => randomInt(5, 1)).toThrow(DisInvalidArgumentError);
        expect(() => randomInt(1.5, 3)).toThrow(DisInvalidArgumentError);
    });
});

describe('random — fillRandom', () => {
    it('fills the provided view in place', () => {
        const buf = new Uint8Array(32);
        const out = fillRandom(buf);
        expect(out).toBe(buf);
        expect(buf.some((b) => b !== 0)).toBe(true);
    });
});
