import { describe, expect, it } from 'vitest';
import {
    hmacSha256,
    hmacSha256WithKey,
    importHmacSha256Key,
    sha1Hex,
    sha256Base64Url,
    sha256Bytes,
    sha256Hex,
} from './index.js';
import { utf8ToBytes } from '../core/encoding.js';

// NIST / RFC known-answer vectors.
const ABC = utf8ToBytes('abc');

describe('integrity — hashing extensions', () => {
    it('matches the SHA-256("abc") known-answer vector', async () => {
        expect(await sha256Hex(ABC)).toBe(
            'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
        );
        expect((await sha256Bytes(ABC)).length).toBe(32);
    });

    it('matches the SHA-1("abc") known-answer vector', async () => {
        expect(await sha1Hex(ABC)).toBe('a9993e364706816aba3e25717850c26c9cd0d89d');
    });

    it('produces unpadded base64url (no +, /, =)', async () => {
        const out = await sha256Base64Url(ABC);
        expect(out).not.toMatch(/[+/=]/);
    });
});

describe('integrity — HMAC-SHA-256', () => {
    // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There".
    const key = new Uint8Array(20).fill(0x0b);
    const data = utf8ToBytes('Hi There');
    const expected =
        'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7';

    function toHex(bytes: Uint8Array): string {
        return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    it('matches the RFC 4231 vector via raw-key helper', async () => {
        expect(toHex(await hmacSha256(key, data))).toBe(expected);
    });

    it('matches via an imported CryptoKey and is verifiable', async () => {
        const k = await importHmacSha256Key(key);
        expect(toHex(await hmacSha256WithKey(k, data))).toBe(expected);
    });
});
