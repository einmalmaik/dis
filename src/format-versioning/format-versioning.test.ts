import { describe, expect, it } from 'vitest';
import {
    formatEnvelope,
    isCurrentEnvelope,
    parseEnvelope,
    type VersionedCipherEnvelopeSpec,
} from './index.js';
import { DisUnsupportedFormatVersionError } from '../core/errors.js';

const spec: VersionedCipherEnvelopeSpec = {
    currentPrefix: 'sv-vault-v1:',
    familyPrefix: 'sv-vault-',
    subject: 'vault item',
};

describe('format versioning', () => {
    it('formats and parses the current version', () => {
        const env = formatEnvelope(spec, 'BASE64');
        expect(env).toBe('sv-vault-v1:BASE64');
        const parsed = parseEnvelope(spec, env);
        expect(parsed).toEqual({ version: 1, payload: 'BASE64' });
        expect(isCurrentEnvelope(spec, env)).toBe(true);
    });

    it('treats unprefixed data as legacy', () => {
        expect(parseEnvelope(spec, 'rawbase64')).toEqual({ version: 'legacy', payload: 'rawbase64' });
        expect(isCurrentEnvelope(spec, 'rawbase64')).toBe(false);
    });

    it('fails closed on unknown in-family version', () => {
        expect(() => parseEnvelope(spec, 'sv-vault-v7:x')).toThrowError(
            DisUnsupportedFormatVersionError,
        );
        expect(isCurrentEnvelope(spec, 'sv-vault-v7:x')).toBe(false);
    });
});
