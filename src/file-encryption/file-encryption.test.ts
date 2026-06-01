import { describe, expect, it } from 'vitest';
import {
    decryptAttachment,
    encryptAttachment,
    type AttachmentContext,
    type FileManifestV1,
} from './index.js';
import { decryptBytes, encryptBytes } from '../aead/index.js';
import { importAesGcmKey } from '../kdf/index.js';
import { randomBytes } from '../random/index.js';

const ctx: AttachmentContext = { ownerId: 'owner-1', vaultItemId: 'item-1', fileId: 'file-1' };

async function makeVaultKey(): Promise<CryptoKey> {
    return importAesGcmKey(randomBytes(32));
}

/** In-memory chunk store used to exercise the storage-agnostic API. */
function makeStore() {
    const store = new Map<number, string>();
    return {
        store,
        writeChunk: async (index: number, ciphertext: string) => {
            store.set(index, ciphertext);
            return ciphertext.length;
        },
        readChunk: async (index: number) => {
            const v = store.get(index);
            if (!v) throw new Error(`missing chunk ${index}`);
            return v;
        },
    };
}

describe('attachment encryption (chunked)', () => {
    it('round-trips a multi-chunk file', async () => {
        const vaultKey = await makeVaultKey();
        const plaintext = randomBytes(10 * 1024); // > 1 chunk at small chunk size
        const store = makeStore();

        const { manifest } = await encryptAttachment({
            context: ctx,
            chunkSize: 4096,
            totalSize: plaintext.length,
            readChunk: async (start, end) => plaintext.slice(start, end),
            writeChunk: store.writeChunk,
            wrapFileKey: (bytes, aad) => encryptBytes(bytes, vaultKey, aad),
            metadata: { original_name: 'secret.bin', mime_type: null, last_modified: null },
        });

        expect(manifest.chunk_count).toBe(3);
        expect(manifest.original_size).toBe(plaintext.length);

        const out: number[] = [];
        await decryptAttachment({
            context: ctx,
            manifest,
            readChunk: async (index) => store.readChunk(index),
            writeChunk: async (_i, chunk) => {
                out.push(...chunk);
            },
            unwrapFileKey: (enc, aad) => decryptBytes(enc, vaultKey, aad),
        });
        expect(out).toEqual([...plaintext]);
    });

    it('detects a tampered ciphertext chunk', async () => {
        const vaultKey = await makeVaultKey();
        const plaintext = randomBytes(2048);
        const store = makeStore();
        const { manifest } = await encryptAttachment({
            context: ctx,
            chunkSize: 4096,
            totalSize: plaintext.length,
            readChunk: async (start, end) => plaintext.slice(start, end),
            writeChunk: store.writeChunk,
            wrapFileKey: (bytes, aad) => encryptBytes(bytes, vaultKey, aad),
            metadata: { original_name: 'a', mime_type: null, last_modified: null },
        });
        // Corrupt stored chunk 0.
        store.store.set(0, store.store.get(0)!.slice(0, -2) + 'AB');

        await expect(
            decryptAttachment({
                context: ctx,
                manifest,
                readChunk: async (index) => store.readChunk(index),
                writeChunk: async () => {},
                unwrapFileKey: (enc, aad) => decryptBytes(enc, vaultKey, aad),
            }),
        ).rejects.toBeTruthy();
    });

    it('rejects decryption under a different attachment context (AAD binding)', async () => {
        const vaultKey = await makeVaultKey();
        const plaintext = randomBytes(1024);
        const store = makeStore();
        const { manifest } = await encryptAttachment({
            context: ctx,
            chunkSize: 4096,
            totalSize: plaintext.length,
            readChunk: async (start, end) => plaintext.slice(start, end),
            writeChunk: store.writeChunk,
            wrapFileKey: (bytes, aad) => encryptBytes(bytes, vaultKey, aad),
            metadata: { original_name: 'a', mime_type: null, last_modified: null },
        });

        const wrongCtx: AttachmentContext = { ...ctx, vaultItemId: 'item-2' };
        const tampered: FileManifestV1 = { ...manifest };
        await expect(
            decryptAttachment({
                context: wrongCtx,
                manifest: tampered,
                readChunk: async (index) => store.readChunk(index),
                writeChunk: async () => {},
                unwrapFileKey: (enc, aad) => decryptBytes(enc, vaultKey, aad),
                verifyChunkHashes: false,
            }),
        ).rejects.toBeTruthy();
    });
});
