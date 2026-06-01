/**
 * dis-format-versioning — versioned, prefix-tagged cipher envelopes.
 *
 * Every persisted ciphertext carries an explicit, human-readable version
 * prefix (e.g. `sv-vault-v1:`). Parsing dispatches strictly by prefix and
 * fails closed for unknown versions in the same family, so a future format can
 * never be silently misread as a legacy payload. Payloads with no recognised
 * prefix are reported as `legacy`, letting callers decide whether to allow them
 * (e.g. only on an explicit migration path).
 */

import { DisInvalidArgumentError, DisUnsupportedFormatVersionError } from '../core/errors.js';

/** Describes a family of versioned envelopes and its current prefix. */
export interface VersionedCipherEnvelopeSpec {
    /** The prefix written for the current version, e.g. `sv-vault-v1:`. */
    readonly currentPrefix: string;
    /** The shared family prefix, e.g. `sv-vault-`. */
    readonly familyPrefix: string;
    /** Human-readable subject used in error messages, e.g. `vault item`. */
    readonly subject: string;
}

export type VersionedCipherEnvelope =
    | { readonly version: 1; readonly payload: string }
    | { readonly version: 'legacy'; readonly payload: string };

/** Wraps a base64 ciphertext in the spec's current version prefix. */
export function formatEnvelope(spec: VersionedCipherEnvelopeSpec, encryptedBase64: string): string {
    if (!encryptedBase64) {
        throw new DisInvalidArgumentError(`Empty ${spec.subject} ciphertext`);
    }
    return `${spec.currentPrefix}${encryptedBase64}`;
}

/**
 * Parses an envelope. Returns `version: 1` for the current prefix, throws for
 * an unknown in-family version, and returns `version: 'legacy'` otherwise.
 */
export function parseEnvelope(
    spec: VersionedCipherEnvelopeSpec,
    encryptedData: string,
): VersionedCipherEnvelope {
    if (encryptedData.startsWith(spec.currentPrefix)) {
        const payload = encryptedData.slice(spec.currentPrefix.length);
        if (!payload) {
            throw new DisInvalidArgumentError(`Invalid ${spec.subject} encryption envelope`);
        }
        return { version: 1, payload };
    }
    if (encryptedData.startsWith(spec.familyPrefix)) {
        throw new DisUnsupportedFormatVersionError(
            `Unsupported ${spec.subject} encryption envelope version`,
        );
    }
    return { version: 'legacy', payload: encryptedData };
}

/** True if `encryptedData` is in the spec's current (v1) envelope format. */
export function isCurrentEnvelope(
    spec: VersionedCipherEnvelopeSpec,
    encryptedData: string,
): boolean {
    try {
        return parseEnvelope(spec, encryptedData).version === 1;
    } catch {
        return false;
    }
}
