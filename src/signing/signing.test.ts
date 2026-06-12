import { describe, expect, it } from 'vitest';
import {
    ECDSA_P256_SIGNATURE_LENGTH,
    generateEcdsaP256KeyPair,
    importEcdsaP256PublicKeySpki,
    signEcdsaP256,
    verifyEcdsaP256,
} from './index.js';
import { utf8ToBytes } from '../core/encoding.js';
import { DisInvalidArgumentError } from '../core/errors.js';

describe('signing — ECDSA P-256', () => {
    it('produces a fixed 64-byte raw r||s signature that verifies', async () => {
        const { privateKey, publicKey } = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('vault-operation-canonical-body');
        const sig = await signEcdsaP256(privateKey, data);
        expect(sig.length).toBe(ECDSA_P256_SIGNATURE_LENGTH);
        expect(await verifyEcdsaP256(publicKey, sig, data)).toBe(true);
    });

    it('round-trips a public key through SPKI export/import', async () => {
        const { privateKey, publicKeySpki } = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('payload');
        const sig = await signEcdsaP256(privateKey, data);
        const imported = await importEcdsaP256PublicKeySpki(publicKeySpki);
        expect(await verifyEcdsaP256(imported, sig, data)).toBe(true);
    });

    it('rejects a tampered payload', async () => {
        const { privateKey, publicKey } = await generateEcdsaP256KeyPair();
        const sig = await signEcdsaP256(privateKey, utf8ToBytes('original'));
        expect(await verifyEcdsaP256(publicKey, sig, utf8ToBytes('tampered'))).toBe(false);
    });

    it('rejects a signature from a different key', async () => {
        const a = await generateEcdsaP256KeyPair();
        const b = await generateEcdsaP256KeyPair();
        const data = utf8ToBytes('payload');
        const sig = await signEcdsaP256(a.privateKey, data);
        expect(await verifyEcdsaP256(b.publicKey, sig, data)).toBe(false);
    });

    it('throws on a wrong-length signature', async () => {
        const { publicKey } = await generateEcdsaP256KeyPair();
        await expect(verifyEcdsaP256(publicKey, new Uint8Array(10), utf8ToBytes('x')))
            .rejects.toBeInstanceOf(DisInvalidArgumentError);
    });
});
