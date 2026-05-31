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

// Integrity
export {
    verifyPayloadIntegrity,
    sha256Base64,
    sha256JsonBase64,
    constantTimeEqual,
} from './integrity/index.js';

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
} from './aead/index.js';

export {
    SecureBuffer,
    withSecureBuffer,
    zeroBuffers,
} from './secure-memory/index.js';

export { randomBytes, randomUuid } from './random/index.js';

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
