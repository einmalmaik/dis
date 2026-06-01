/**
 * dis-asymmetric — RSA-OAEP public-key operations.
 *
 * Primitive: RSA-OAEP (4096-bit modulus, SHA-256) via WebCrypto. Used by the
 * Singra sharing / emergency-access profile to wrap symmetric material for a
 * recipient's public key. DIS does not invent any asymmetric scheme — this is
 * a thin, audited wrapper over WebCrypto so applications never touch the raw
 * `crypto.subtle` surface.
 *
 * Key material is exported/imported as JWK (the format Singra persists), so
 * existing stored keys remain byte-compatible. Wire format for ciphertext is
 * `base64(rsa_oaep_output)`, identical to the legacy implementation.
 */

import { subtle } from '../core/provider.js';
import { base64ToBytes, bytesToBase64, bytesToUtf8, utf8ToBytes } from '../core/encoding.js';

/** RSA-OAEP modulus length in bits. Part of the key-generation format contract. */
export const RSA_OAEP_MODULUS_LENGTH = 4096;

const RSA_OAEP_ALGORITHM = {
    name: 'RSA-OAEP',
    hash: 'SHA-256',
} as const;

/**
 * Generates an extractable RSA-OAEP-4096 key pair (SHA-256, e=65537).
 * Extractable so the private key can be exported as JWK and wrapped at rest.
 */
export async function generateRsaOaepKeyPair(): Promise<CryptoKeyPair> {
    return subtle().generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: RSA_OAEP_MODULUS_LENGTH,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt'],
    );
}

/** Exports an RSA key (public or private) as a JWK object. */
export async function exportJwk(key: CryptoKey): Promise<JsonWebKey> {
    return subtle().exportKey('jwk', key);
}

/** Imports an RSA-OAEP public key (JWK) for `encrypt`. Extractable. */
export async function importRsaOaepPublicKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return subtle().importKey('jwk', jwk, RSA_OAEP_ALGORITHM, true, ['encrypt']);
}

/** Imports an RSA-OAEP private key (JWK) for `decrypt`. Non-extractable. */
export async function importRsaOaepPrivateKey(jwk: JsonWebKey): Promise<CryptoKey> {
    return subtle().importKey('jwk', jwk, RSA_OAEP_ALGORITHM, false, ['decrypt']);
}

/** Encrypts a UTF-8 string under an RSA-OAEP public key. Returns base64. */
export async function rsaOaepEncrypt(plaintext: string, publicKey: CryptoKey): Promise<string> {
    const encoded = utf8ToBytes(plaintext);
    try {
        const encrypted = await subtle().encrypt({ name: 'RSA-OAEP' }, publicKey, encoded as BufferSource);
        return bytesToBase64(new Uint8Array(encrypted));
    } finally {
        encoded.fill(0);
    }
}

/** Decrypts base64 RSA-OAEP ciphertext under an RSA-OAEP private key. */
export async function rsaOaepDecrypt(ciphertextBase64: string, privateKey: CryptoKey): Promise<string> {
    const encrypted = base64ToBytes(ciphertextBase64);
    let plaintextBytes: Uint8Array | null = null;
    try {
        const decrypted = await subtle().decrypt({ name: 'RSA-OAEP' }, privateKey, encrypted as BufferSource);
        plaintextBytes = new Uint8Array(decrypted);
        return bytesToUtf8(plaintextBytes);
    } finally {
        encrypted.fill(0);
        plaintextBytes?.fill(0);
    }
}
