/**
 * dis-signing — asymmetric digital signatures.
 *
 * Primitive: ECDSA over the NIST P-256 curve with SHA-256, via WebCrypto.
 * Public keys are exchanged as SPKI bytes; private keys are generated
 * non-extractable so they never leave the device. Signatures are the raw
 * `r || s` concatenation WebCrypto produces (fixed 64 bytes for P-256), which
 * is the exact wire form Singra Vault's op-log device signatures use.
 *
 * Canonicalisation of the signed payload is the caller's responsibility — DIS
 * signs and verifies opaque byte strings and never interprets their structure.
 */

import { subtle } from '../core/provider.js';
import { DisInvalidArgumentError } from '../core/errors.js';

const ECDSA_P256_ALGORITHM = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const ECDSA_P256_PARAMS = { name: 'ECDSA', hash: 'SHA-256' } as const;

/** Raw byte length of a P-256 ECDSA signature (`r || s`, 32 bytes each). */
export const ECDSA_P256_SIGNATURE_LENGTH = 64;

export interface EcdsaP256KeyPair {
    readonly privateKey: CryptoKey;
    readonly publicKey: CryptoKey;
    /** SPKI-encoded public key bytes, ready to be base64url-encoded for storage. */
    readonly publicKeySpki: Uint8Array;
}

/**
 * Generates a fresh non-extractable ECDSA P-256 key pair and exports the
 * public key as SPKI bytes.
 */
export async function generateEcdsaP256KeyPair(): Promise<EcdsaP256KeyPair> {
    const keyPair = await subtle().generateKey(
        ECDSA_P256_ALGORITHM,
        /* extractable */ false,
        ['sign', 'verify'],
    );
    const spki = await subtle().exportKey('spki', keyPair.publicKey);
    return {
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
        publicKeySpki: new Uint8Array(spki),
    };
}

/** Imports an SPKI-encoded P-256 public key for signature verification. */
export async function importEcdsaP256PublicKeySpki(spki: Uint8Array): Promise<CryptoKey> {
    return subtle().importKey(
        'spki',
        spki as BufferSource,
        ECDSA_P256_ALGORITHM,
        false,
        ['verify'],
    );
}

/**
 * Signs `data` with an ECDSA P-256 private key, returning the raw 64-byte
 * `r || s` signature. Throws {@link DisInvalidArgumentError} if WebCrypto
 * returns an unexpected length (defends against curve/algorithm misuse).
 */
export async function signEcdsaP256(privateKey: CryptoKey, data: Uint8Array): Promise<Uint8Array> {
    const signature = await subtle().sign(ECDSA_P256_PARAMS, privateKey, data as BufferSource);
    const bytes = new Uint8Array(signature);
    if (bytes.length !== ECDSA_P256_SIGNATURE_LENGTH) {
        throw new DisInvalidArgumentError('unexpected ECDSA signature byte length');
    }
    return bytes;
}

/**
 * Verifies a raw 64-byte `r || s` ECDSA P-256 signature over `data`. Returns
 * `false` for an invalid signature; throws {@link DisInvalidArgumentError} if
 * the signature is not the expected length.
 */
export async function verifyEcdsaP256(
    publicKey: CryptoKey,
    signature: Uint8Array,
    data: Uint8Array,
): Promise<boolean> {
    if (signature.length !== ECDSA_P256_SIGNATURE_LENGTH) {
        throw new DisInvalidArgumentError('unexpected ECDSA signature byte length');
    }
    try {
        return await subtle().verify(
            ECDSA_P256_PARAMS,
            publicKey,
            signature as BufferSource,
            data as BufferSource,
        );
    } catch {
        return false;
    }
}
