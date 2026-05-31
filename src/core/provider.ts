/**
 * Pluggable crypto provider abstraction.
 *
 * DIS does not invent cryptography. It binds to an audited primitive provider.
 * The default provider is the platform WebCrypto implementation
 * (`globalThis.crypto`), which is available in modern browsers and in Node >= 20.
 *
 * Exposing this as an interface keeps the door open for substituting a
 * hardware-backed or test provider without touching call sites, and keeps the
 * rest of DIS free of direct global access.
 */

import { DisError } from './errors.js';

/** Minimal subset of the WebCrypto API that DIS relies on. */
export interface CryptoProvider {
    getRandomValues<T extends ArrayBufferView>(array: T): T;
    readonly subtle: SubtleCrypto;
}

let activeProvider: CryptoProvider | null = null;

function resolvePlatformProvider(): CryptoProvider {
    const candidate = (globalThis as { crypto?: Crypto }).crypto;
    if (!candidate || typeof candidate.getRandomValues !== 'function' || !candidate.subtle) {
        throw new DisError(
            'PROVIDER_UNAVAILABLE',
            'No WebCrypto provider available. Provide one via setCryptoProvider().',
        );
    }
    return candidate;
}

/** Returns the active crypto provider, falling back to platform WebCrypto. */
export function getCryptoProvider(): CryptoProvider {
    if (!activeProvider) {
        activeProvider = resolvePlatformProvider();
    }
    return activeProvider;
}

/**
 * Overrides the active crypto provider. Intended for tests and for
 * environments that supply a non-global WebCrypto implementation.
 * Pass `null` to reset to platform auto-detection.
 */
export function setCryptoProvider(provider: CryptoProvider | null): void {
    activeProvider = provider;
}

/** Convenience accessor for `SubtleCrypto`. */
export function subtle(): SubtleCrypto {
    return getCryptoProvider().subtle;
}
