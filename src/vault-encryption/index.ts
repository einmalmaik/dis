/**
 * dis-vault-encryption — encryption of structured vault entries.
 *
 * A vault entry is an arbitrary JSON-serialisable record. It is sealed with
 * AES-256-GCM and wrapped in the versioned `sv-vault-v1:` envelope, byte
 * compatible with Singra Vault. The entry id is passed as AEAD associated data
 * so ciphertext is cryptographically bound to its row (defeats swap attacks).
 *
 * Legacy (pre-versioning, no-AAD) payloads fail closed on the runtime read
 * path and are only readable through the explicit migration helper.
 */

import { decryptString, encryptString } from '../aead/index.js';
import {
    formatEnvelope,
    isCurrentEnvelope,
    parseEnvelope,
    type VersionedCipherEnvelopeSpec,
} from '../format-versioning/index.js';
import { DisInvalidArgumentError, DisLegacyPayloadError } from '../core/errors.js';

export const VAULT_ITEM_ENVELOPE_V1_PREFIX = 'sv-vault-v1:';
const VAULT_ITEM_ENVELOPE_FAMILY_PREFIX = 'sv-vault-';

export const VAULT_ITEM_ENVELOPE_SPEC: VersionedCipherEnvelopeSpec = {
    currentPrefix: VAULT_ITEM_ENVELOPE_V1_PREFIX,
    familyPrefix: VAULT_ITEM_ENVELOPE_FAMILY_PREFIX,
    subject: 'vault item',
};

export type VaultEntryData = Record<string, unknown>;

/** Seals a vault entry, binding it to `entryId` via AEAD associated data. */
export async function encryptVaultEntry(
    data: VaultEntryData,
    key: CryptoKey,
    entryId: string,
): Promise<string> {
    if (!entryId) {
        throw new DisInvalidArgumentError('entryId is required to bind vault entry ciphertext');
    }
    const json = JSON.stringify(data);
    return formatEnvelope(VAULT_ITEM_ENVELOPE_SPEC, await encryptString(json, key, entryId));
}

/**
 * Opens a vault entry. Versioned payloads are read with `entryId` as AAD.
 * Legacy no-AAD payloads throw {@link DisLegacyPayloadError} on the runtime
 * path; use {@link decryptVaultEntryForMigration} to read and rewrite them.
 */
export async function decryptVaultEntry(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<VaultEntryData> {
    const envelope = parseEnvelope(VAULT_ITEM_ENVELOPE_SPEC, encryptedData);
    if (envelope.version === 1) {
        return JSON.parse(await decryptString(envelope.payload, key, entryId)) as VaultEntryData;
    }
    // Legacy payloads written after AAD rollout still authenticate with entryId.
    if (entryId) {
        try {
            return JSON.parse(
                await decryptString(envelope.payload, key, entryId),
            ) as VaultEntryData;
        } catch {
            throw new DisLegacyPayloadError('Legacy vault item without AAD requires migration.');
        }
    }
    throw new DisLegacyPayloadError('Legacy vault item without AAD requires migration.');
}

export interface VaultEntryMigrationResult {
    readonly data: VaultEntryData;
    readonly legacyEnvelopeUsed: boolean;
    readonly legacyNoAadFallbackUsed: boolean;
}

/**
 * Decrypts an entry on an explicit migration path, permitting the no-AAD
 * fallback for the oldest payloads so they can be rewritten as versioned,
 * AAD-bound items. Never use on the normal runtime read path.
 */
export async function decryptVaultEntryForMigration(
    encryptedData: string,
    key: CryptoKey,
    entryId: string,
): Promise<VaultEntryMigrationResult> {
    const envelope = parseEnvelope(VAULT_ITEM_ENVELOPE_SPEC, encryptedData);
    if (envelope.version === 1) {
        return {
            data: JSON.parse(await decryptString(envelope.payload, key, entryId)) as VaultEntryData,
            legacyEnvelopeUsed: false,
            legacyNoAadFallbackUsed: false,
        };
    }
    if (entryId) {
        try {
            return {
                data: JSON.parse(
                    await decryptString(envelope.payload, key, entryId),
                ) as VaultEntryData,
                legacyEnvelopeUsed: true,
                legacyNoAadFallbackUsed: false,
            };
        } catch {
            // Fall through to the no-AAD fallback below.
        }
    }
    const data = JSON.parse(await decryptString(envelope.payload, key)) as VaultEntryData;
    return { data, legacyEnvelopeUsed: true, legacyNoAadFallbackUsed: true };
}

/** True if `encryptedData` is a current versioned vault-item envelope. */
export function isCurrentVaultEntryEnvelope(encryptedData: string): boolean {
    return isCurrentEnvelope(VAULT_ITEM_ENVELOPE_SPEC, encryptedData);
}
