/**
 * dis-file-encryption / dis-attachment-streams — chunked file & attachment
 * encryption.
 *
 * Model (byte-compatible with Singra Premium):
 *   - A fresh random per-file AES-256 key encrypts the file content.
 *   - The file is split into fixed-size chunks; each chunk is sealed with
 *     AES-256-GCM and a per-chunk AAD binding it to owner/item/file/revision/
 *     manifest-root/index/count (defeats reorder, splice and cross-file swap).
 *   - The file key is wrapped by an outer vault key (supplied as a callback),
 *     bound by a file-key AAD.
 *   - A manifest records chunk hashes and a manifest root; it is sealed with
 *     the vault key under a manifest AAD and wrapped in `sv-file-manifest-v1:`.
 *
 * DIS owns the cryptography and the format. It is storage-agnostic: callers
 * supply chunk read/write callbacks, so transport (e.g. object storage, local
 * FS) stays in the application.
 */

import { decryptBytes, encryptBytes } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';
import { sha256Base64, sha256JsonBase64 } from '../integrity/index.js';
import { AES_KEY_LENGTH } from '../core/constants.js';
import { DisInvalidArgumentError } from '../core/errors.js';

/** Default chunk size (4 MiB), matching the Singra Premium format. */
export const DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024;

export const FILE_MANIFEST_V1_PREFIX = 'sv-file-manifest-v1:';

/** Opaque binding context for an attachment. Ids are treated as opaque strings. */
export interface AttachmentContext {
    readonly ownerId: string;
    readonly vaultItemId: string;
    readonly fileId: string;
}

/** Encrypts text with the outer vault key (e.g. DIS aead.encryptString). */
export type VaultEncryptText = (plaintext: string, aad?: string) => Promise<string>;
export type VaultDecryptText = (encrypted: string, aad?: string) => Promise<string>;
export type VaultEncryptBytes = (plaintext: Uint8Array, aad?: string) => Promise<string>;
export type VaultDecryptBytes = (encrypted: string, aad?: string) => Promise<Uint8Array>;

export interface FileChunkManifest {
    readonly index: number;
    readonly plaintext_size: number;
    readonly ciphertext_size: number;
    readonly ciphertext_sha256: string;
}

export interface FileManifestV1 {
    readonly version: 1;
    readonly algorithm: 'AES-256-GCM';
    readonly file_id: string;
    readonly file_revision: number;
    readonly previous_manifest_hash: string | null;
    readonly manifest_root: string;
    readonly owner_id: string;
    readonly vault_item_id: string;
    readonly original_name: string;
    readonly mime_type: string | null;
    readonly original_size: number;
    readonly last_modified: number | null;
    readonly uploaded_at: string;
    readonly chunk_size: number;
    readonly chunk_count: number;
    readonly wrapped_file_key: string;
    readonly chunks: readonly FileChunkManifest[];
    readonly preview: null;
    readonly notes: null;
}

// ---- Canonical AAD scheme (format contract) -------------------------------

export function manifestAad(ctx: AttachmentContext): string {
    return `sv-file-manifest-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

export function fileKeyAad(ctx: AttachmentContext): string {
    return `sv-file-key-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}`;
}

export function chunkAad(
    ctx: AttachmentContext,
    fileRevision: number,
    manifestRoot: string,
    chunkIndex: number,
    chunkCount: number,
): string {
    return (
        `sv-file-chunk-v1:${ctx.ownerId}:${ctx.vaultItemId}:${ctx.fileId}:` +
        `${fileRevision}:${manifestRoot}:${chunkIndex}:${chunkCount}`
    );
}

// ---- File-key handling ----------------------------------------------------

/** Generates fresh per-file AES-256 key bytes (caller must wipe). */
export function generateFileKeyBytes(): Uint8Array {
    return randomBytes(AES_KEY_LENGTH);
}

/** Imports raw file-key bytes as a non-extractable AES-GCM key. */
export function importFileKey(rawKey: Uint8Array): Promise<CryptoKey> {
    return importAesGcmKey(rawKey);
}

// ---- Chunk crypto ---------------------------------------------------------

/** Seals one plaintext chunk. `plaintext` is wiped before returning. */
export async function encryptChunk(
    plaintext: Uint8Array,
    fileKey: CryptoKey,
    aad: string,
): Promise<string> {
    try {
        return await encryptBytes(plaintext, fileKey, aad);
    } finally {
        plaintext.fill(0);
    }
}

/** Opens one chunk. Returned bytes are plaintext — caller must wipe. */
export async function decryptChunk(
    encryptedBase64: string,
    fileKey: CryptoKey,
    aad: string,
): Promise<Uint8Array> {
    return decryptBytes(encryptedBase64, fileKey, aad);
}

// ---- Manifest helpers -----------------------------------------------------

interface PlannedChunk {
    readonly index: number;
    readonly plaintext_size: number;
}

/**
 * Computes the manifest root: a SHA-256 over the planned chunk layout. Binding
 * each chunk's AAD to this root prevents chunk-count / size tampering.
 */
export async function computeManifestRoot(input: {
    fileId: string;
    fileRevision: number;
    chunkSize: number;
    chunkCount: number;
    chunks: readonly PlannedChunk[];
}): Promise<string> {
    return sha256JsonBase64({
        file_id: input.fileId,
        file_revision: input.fileRevision,
        chunk_size: input.chunkSize,
        chunk_count: input.chunkCount,
        chunks: input.chunks.map((c) => ({
            index: c.index,
            storage_path: undefined,
            plaintext_size: c.plaintext_size,
        })),
    });
}

/** SHA-256 (base64) of a ciphertext chunk, for the manifest. */
export function chunkCiphertextHash(ciphertextBase64: string): Promise<string> {
    return sha256Base64(new TextEncoder().encode(ciphertextBase64));
}

export interface EncryptAttachmentInput {
    readonly context: AttachmentContext;
    readonly fileRevision?: number;
    readonly chunkSize?: number;
    /** Total plaintext size in bytes (used to plan chunks). */
    readonly totalSize: number;
    /** Returns the plaintext bytes for chunk `[start, end)`. */
    readonly readChunk: (start: number, end: number) => Promise<Uint8Array>;
    /** Persists a sealed chunk; returns its stored ciphertext size in bytes. */
    readonly writeChunk: (index: number, ciphertextBase64: string) => Promise<number>;
    /** Wraps the per-file key with the outer vault key. */
    readonly wrapFileKey: VaultEncryptBytes;
    readonly metadata: {
        readonly original_name: string;
        readonly mime_type: string | null;
        readonly last_modified: number | null;
    };
}

export interface EncryptAttachmentResult {
    readonly manifest: FileManifestV1;
    readonly manifestRoot: string;
}

/**
 * Encrypts an attachment chunk-by-chunk and produces a sealed manifest.
 * Storage is delegated to `readChunk`/`writeChunk`. The returned manifest's
 * `wrapped_file_key` is bound to the file via {@link fileKeyAad}.
 */
export async function encryptAttachment(
    input: EncryptAttachmentInput,
): Promise<EncryptAttachmentResult> {
    const chunkSize = input.chunkSize ?? DEFAULT_CHUNK_SIZE;
    if (chunkSize <= 0) throw new DisInvalidArgumentError('chunkSize must be positive');
    const fileRevision = input.fileRevision ?? 1;
    const chunkCount = Math.max(1, Math.ceil(input.totalSize / chunkSize));
    const ctx = input.context;

    const plannedChunks: PlannedChunk[] = Array.from({ length: chunkCount }, (_, index) => {
        const start = index * chunkSize;
        const end = Math.min(input.totalSize, start + chunkSize);
        return { index, plaintext_size: end - start };
    });
    const manifestRoot = await computeManifestRoot({
        fileId: ctx.fileId,
        fileRevision,
        chunkSize,
        chunkCount,
        chunks: plannedChunks,
    });

    const fileKeyBytes = generateFileKeyBytes();
    const fileKey = await importFileKey(fileKeyBytes);
    const chunks: FileChunkManifest[] = [];
    try {
        const wrappedFileKey = await input.wrapFileKey(fileKeyBytes, fileKeyAad(ctx));
        for (let index = 0; index < chunkCount; index += 1) {
            const start = index * chunkSize;
            const end = Math.min(input.totalSize, start + chunkSize);
            const plaintext = await input.readChunk(start, end);
            const aad = chunkAad(ctx, fileRevision, manifestRoot, index, chunkCount);
            const ciphertext = await encryptChunk(plaintext, fileKey, aad);
            const ciphertextSize = await input.writeChunk(index, ciphertext);
            chunks.push({
                index,
                plaintext_size: plannedChunks[index]!.plaintext_size,
                ciphertext_size: ciphertextSize,
                ciphertext_sha256: await chunkCiphertextHash(ciphertext),
            });
        }

        const manifest: FileManifestV1 = {
            version: 1,
            algorithm: 'AES-256-GCM',
            file_id: ctx.fileId,
            file_revision: fileRevision,
            previous_manifest_hash: null,
            manifest_root: manifestRoot,
            owner_id: ctx.ownerId,
            vault_item_id: ctx.vaultItemId,
            original_name: input.metadata.original_name,
            mime_type: input.metadata.mime_type,
            original_size: input.totalSize,
            last_modified: input.metadata.last_modified,
            uploaded_at: new Date().toISOString(),
            chunk_size: chunkSize,
            chunk_count: chunkCount,
            wrapped_file_key: wrappedFileKey,
            chunks,
            preview: null,
            notes: null,
        };
        return { manifest, manifestRoot };
    } finally {
        fileKeyBytes.fill(0);
    }
}

export interface DecryptAttachmentInput {
    readonly context: AttachmentContext;
    readonly manifest: FileManifestV1;
    /** Reads a stored ciphertext chunk by index. */
    readonly readChunk: (index: number, storedSha256: string) => Promise<string>;
    /** Receives a decrypted plaintext chunk (caller may stream to disk). */
    readonly writeChunk: (index: number, plaintext: Uint8Array) => Promise<void>;
    /** Unwraps the per-file key using the outer vault key. */
    readonly unwrapFileKey: VaultDecryptBytes;
    /** If true (default), verify each chunk's stored ciphertext hash. */
    readonly verifyChunkHashes?: boolean;
}

/**
 * Decrypts an attachment by streaming chunks through `readChunk`/`writeChunk`.
 * Each chunk is authenticated by its AAD; when `verifyChunkHashes` is set the
 * stored ciphertext hash is additionally checked before decryption.
 */
export async function decryptAttachment(input: DecryptAttachmentInput): Promise<void> {
    const { manifest, context: ctx } = input;
    const verifyHashes = input.verifyChunkHashes ?? true;
    const fileKeyBytes = await input.unwrapFileKey(manifest.wrapped_file_key, fileKeyAad(ctx));
    const fileKey = await importFileKey(fileKeyBytes);
    try {
        fileKeyBytes.fill(0);
        for (const chunkMeta of manifest.chunks) {
            const ciphertext = await input.readChunk(chunkMeta.index, chunkMeta.ciphertext_sha256);
            if (verifyHashes) {
                const actual = await chunkCiphertextHash(ciphertext);
                if (actual !== chunkMeta.ciphertext_sha256) {
                    throw new DisInvalidArgumentError(
                        `Chunk ${chunkMeta.index} ciphertext hash mismatch`,
                    );
                }
            }
            const aad = chunkAad(
                ctx,
                manifest.file_revision,
                manifest.manifest_root,
                chunkMeta.index,
                manifest.chunk_count,
            );
            const plaintext = await decryptChunk(ciphertext, fileKey, aad);
            try {
                await input.writeChunk(chunkMeta.index, plaintext);
            } finally {
                plaintext.fill(0);
            }
        }
    } finally {
        fileKeyBytes.fill(0);
    }
}
