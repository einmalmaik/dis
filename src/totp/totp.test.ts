import { describe, expect, it } from 'vitest';
import * as OTPAuth from 'otpauth';
import {
    TOTP_DIGITS,
    TOTP_PERIOD_SECONDS,
    buildTotpUri,
    buildTotpUriWithOptions,
    generateTotpCode,
    generateTotpSecret,
    verifyTotpCode,
} from './index.js';

describe('totp', () => {
    it('generates a base32 160-bit secret', () => {
        const secret = generateTotpSecret();
        expect(secret).toMatch(/^[A-Z2-7]+$/);
        // 20 bytes -> 32 base32 chars (unpadded)
        expect(secret.length).toBe(32);
    });

    it('builds an otpauth:// URI with the pinned parameters', () => {
        const secret = generateTotpSecret();
        const uri = buildTotpUri({ issuer: 'Singra', label: 'user@example.com', secret });
        expect(uri).toContain('otpauth://totp/');
        expect(uri).toContain('algorithm=SHA1');
        expect(uri).toContain('digits=6');
        expect(uri).toContain('period=30');
    });

    it('verifies a freshly generated code (interop with raw otpauth)', () => {
        const secret = generateTotpSecret();
        const totp = new OTPAuth.TOTP({
            algorithm: 'SHA1',
            digits: TOTP_DIGITS,
            period: TOTP_PERIOD_SECONDS,
            secret: OTPAuth.Secret.fromBase32(secret),
        });
        const code = totp.generate();
        expect(verifyTotpCode(secret, code)).toBe(true);
        expect(verifyTotpCode(secret, `${code} `)).toBe(true); // whitespace tolerated
    });

    it('rejects a wrong code and malformed secret without throwing', () => {
        const secret = generateTotpSecret();
        expect(verifyTotpCode(secret, '000000')).toBe(false);
        expect(verifyTotpCode('not-base32!!', '123456')).toBe(false);
    });

    it('generateTotpCode matches raw otpauth across algorithms/digits/periods', () => {
        const secret = generateTotpSecret();
        const timestamp = 1765432100000;
        for (const algorithm of ['SHA1', 'SHA256', 'SHA512'] as const) {
            for (const digits of [6, 8]) {
                for (const period of [30, 60]) {
                    const expected = new OTPAuth.TOTP({
                        algorithm,
                        digits,
                        period,
                        secret: OTPAuth.Secret.fromBase32(secret),
                    }).generate({ timestamp });
                    expect(
                        generateTotpCode(secret, { algorithm, digits, period, timestamp }),
                    ).toBe(expected);
                }
            }
        }
    });

    it('generateTotpCode defaults to the pinned Singra parameter set', () => {
        const secret = generateTotpSecret();
        const code = generateTotpCode(secret);
        expect(code).toMatch(/^\d{6}$/);
        expect(verifyTotpCode(secret, code)).toBe(true);
    });

    it('generateTotpCode throws on a malformed secret', () => {
        expect(() => generateTotpCode('not-base32!!')).toThrow();
    });

    it('buildTotpUriWithOptions embeds the explicit parameters', () => {
        const secret = generateTotpSecret();
        const uri = buildTotpUriWithOptions(
            { issuer: 'GitHub', label: 'octocat', secret },
            { algorithm: 'SHA256', digits: 8, period: 60 },
        );
        expect(uri).toContain('otpauth://totp/');
        expect(uri).toContain('algorithm=SHA256');
        expect(uri).toContain('digits=8');
        expect(uri).toContain('period=60');
    });
});
