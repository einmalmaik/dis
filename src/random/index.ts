/**
 * dis-random — secure random generation.
 *
 * Always sources entropy from the active crypto provider's CSPRNG
 * (`getRandomValues`). DIS never uses `Math.random` for any value that affects
 * confidentiality, integrity, or unpredictability.
 */

import { getCryptoProvider } from '../core/provider.js';
import { DisInvalidArgumentError } from '../core/errors.js';

/** Returns `length` cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
    if (!Number.isInteger(length) || length <= 0) {
        throw new DisInvalidArgumentError('randomBytes length must be a positive integer');
    }
    const out = new Uint8Array(length);
    getCryptoProvider().getRandomValues(out);
    return out;
}

/** Returns a RFC 4122 v4 UUID using the provider's CSPRNG. */
export function randomUuid(): string {
    const provider = getCryptoProvider() as { randomUUID?: () => string };
    if (typeof provider.randomUUID === 'function') {
        return provider.randomUUID();
    }
    // Fallback: build a v4 UUID from random bytes.
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6]! & 0x0f) | 0x40;
    bytes[8] = (bytes[8]! & 0x3f) | 0x80;
    const hex: string[] = [];
    for (let i = 0; i < 16; i++) hex.push(bytes[i]!.toString(16).padStart(2, '0'));
    return (
        `${hex[0]}${hex[1]}${hex[2]}${hex[3]}-${hex[4]}${hex[5]}-${hex[6]}${hex[7]}-` +
        `${hex[8]}${hex[9]}-${hex[10]}${hex[11]}${hex[12]}${hex[13]}${hex[14]}${hex[15]}`
    );
}
