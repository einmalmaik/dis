/**
 * Cryptographic constants shared across DIS modules.
 *
 * These values are part of the on-the-wire / on-disk format contract. Changing
 * any released constant is a breaking format change and MUST be expressed as a
 * new format version, never an in-place edit.
 */

/** AES-GCM IV length in bytes (96 bits — the recommended GCM nonce size). */
export const AES_GCM_IV_LENGTH = 12;

/** AES-GCM authentication tag length in bits. */
export const AES_GCM_TAG_LENGTH = 128;

/** Symmetric key length in bytes (AES-256). */
export const AES_KEY_LENGTH = 32;

/** Salt length in bytes (128 bits) for password-based key derivation. */
export const KDF_SALT_LENGTH = 16;
