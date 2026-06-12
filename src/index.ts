/**
 * DIS — Defensive Integration Shield
 * Powered by DIS — Defensive Integration Shield.
 *
 * Stable public SDK facade. Applications should depend on this surface (or the
 * individual `@dis/shield/<module>` entry points) and never call low-level
 * WebCrypto directly. Internal cryptographic changes are designed not to break
 * these signatures.
 */

export const DIS_BRANDING = 'Powered by DIS — Defensive Integration Shield' as const;

// ---- Stable high-level API ------------------------------------------------

// Vault entries
export {
    encryptVaultEntry,
    decryptVaultEntry,
    decryptVaultEntryForMigration,
    isCurrentVaultEntryEnvelope,
    VAULT_ITEM_ENVELOPE_V1_PREFIX,
    type VaultEntryData,
    type VaultEntryMigrationResult,
} from './vault-encryption/index.js';

// Attachments / files
export {
    encryptAttachment,
    decryptAttachment,
    encryptChunk,
    decryptChunk,
    generateFileKeyBytes,
    importFileKey,
    DEFAULT_CHUNK_SIZE,
    FILE_MANIFEST_V1_PREFIX,
    type AttachmentContext,
    type FileManifestV1,
    type FileChunkManifest,
    type EncryptAttachmentInput,
    type DecryptAttachmentInput,
} from './file-encryption/index.js';

// Key derivation (deriveMasterKey == deriveAesGcmKey)
export {
    deriveAesGcmKey as deriveMasterKey,
    deriveRawKey,
    importAesGcmKey,
    generateSalt,
    CURRENT_KDF_VERSION,
    DEFAULT_KDF_PARAMS,
    type KdfParams,
    type DeriveRawKeyOptions,
} from './kdf/index.js';

// Key management / rotation (rotateEncryptionKeys == rotateWrappedKey)
export {
    createWrappedUserKey,
    unwrapUserKey,
    unwrapUserKeyBytes,
    rotateWrappedKey as rotateEncryptionKeys,
    generateContentKeyBytes,
    DEFAULT_KEY_WRAP_SCHEME,
    type UserKeyBundle,
    type KeyWrapScheme,
} from './key-management/index.js';

// Post-quantum hybrid key wrapping (ML-KEM-768 + RSA-4096) for sharing /
// emergency-access keys. Optional: requires the `@noble/post-quantum` peer.
export {
    generatePQKeyPair,
    generateHybridKeyPair,
    hybridEncrypt,
    hybridDecrypt,
    hybridWrapKey,
    hybridUnwrapKey,
    isHybridEncrypted,
    isCurrentStandardEncrypted,
    migrateToHybrid,
    buildSharedKeyWrapAad,
    HYBRID_VERSION,
    SECURITY_STANDARD_VERSION,
    type PQKeyPair,
    type HybridKeyPair,
    type SharedKeyWrapAadInput,
} from './post-quantum/index.js';

// Integrity & hashing
export {
    verifyPayloadIntegrity,
    sha256Bytes,
    sha256Base64,
    sha256Base64Url,
    sha256Hex,
    sha1Hex,
    sha256JsonBase64,
    hmacSha256,
    hmacSha256WithKey,
    importHmacSha256Key,
    constantTimeEqual,
} from './integrity/index.js';

// Digital signatures (ECDSA P-256)
export {
    generateEcdsaP256KeyPair,
    importEcdsaP256PublicKeySpki,
    signEcdsaP256,
    verifyEcdsaP256,
    ECDSA_P256_SIGNATURE_LENGTH,
    type EcdsaP256KeyPair,
} from './signing/index.js';

// Time-based one-time passwords (TOTP)
export {
    generateTotpSecret,
    buildTotpUri,
    verifyTotpCode,
    type TotpParams,
} from './totp/index.js';

// Migrations (migrateEncryptedPayload via the registry)
export {
    MigrationRegistry,
    type Migration,
    type MigrationContext,
    type VersionDetector,
} from './migrations/index.js';

// ---- Lower-level building blocks (re-exported for advanced use) -----------

export {
    encryptBytes,
    decryptBytes,
    encryptString,
    decryptString,
    aesGcmEncrypt,
    aesGcmDecrypt,
    importAesGcmRawKey,
    generateAesGcmKey,
} from './aead/index.js';

export {
    argon2idRaw,
    deriveHkdfSha256Bits,
    deriveHkdfAesGcmKey,
    type Argon2idRawParams,
} from './kdf/index.js';

export {
    SecureBuffer,
    withSecureBuffer,
    zeroBuffers,
} from './secure-memory/index.js';

export { randomBytes, randomInt, fillRandom, randomUuid } from './random/index.js';

export {
    formatEnvelope,
    parseEnvelope,
    isCurrentEnvelope,
    type VersionedCipherEnvelopeSpec,
    type VersionedCipherEnvelope,
} from './format-versioning/index.js';

export {
    setCryptoProvider,
    getCryptoProvider,
    type CryptoProvider,
} from './core/provider.js';

export {
    DisError,
    DisInvalidArgumentError,
    DisDecryptionError,
    DisUnsupportedFormatVersionError,
    DisIntegrityError,
    DisLegacyPayloadError,
    type DisErrorCode,
} from './core/errors.js';
