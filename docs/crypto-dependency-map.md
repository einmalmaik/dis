# Crypto Dependency Map

Inventory of cryptographic logic in the source applications, where it lives
today, and where it moves in DIS. Counts are from the repository at analysis
time and are a baseline, not a guarantee.

## Libraries (current)

| Library | Version | Use | Where |
| --- | --- | --- | --- |
| `hash-wasm` | 4.12.0 | Argon2id KDF | `singravault` |
| WebCrypto `SubtleCrypto` | platform | AES-GCM, HKDF, RSA-OAEP, SHA-256 | both |
| `@noble/post-quantum` | 0.5.4 | ML-KEM-768 (hybrid) | `singravault` |
| `otpauth` | ^9.5.0 | TOTP (out of DIS scope) | `singravault` |

## Singra Vault — core crypto modules

| File | Lines | Responsibility | DIS target |
| --- | --- | --- | --- |
| `src/services/cryptoService.ts` | 1741 | KDF, AES-GCM, vault-item envelope, verification hash, user-key wrap, RSA, shared-key | `kdf`, `aead`, `vault-encryption`, `key-management`, `format-versioning` |
| `src/services/keyMaterialService.ts` | 459 | Ensure/derive RSA + PQ key material | app orchestration over `key-management` (stays in app) |
| `src/services/secureBuffer.ts` | 301 | Memory-safe key handling | `secure-memory` |
| `src/services/pqCryptoService.ts` | 752 | ML-KEM-768 + RSA hybrid encrypt/wrap | `key-management` (PQ hybrid submodule — phase 2) |
| `src/services/deviceKeyService.ts` | — | Device-key gen + HKDF strengthening | `kdf` (HKDF strengthen) + app policy |
| `src/services/vaultIntegrityV2/*` | — | Item envelopes, manifests | `vault-encryption`, `integrity` |

## Public crypto surface extracted (Singra Vault `cryptoService.ts`)

`CURRENT_KDF_VERSION`, `KDF_PARAMS`, `VAULT_ITEM_ENVELOPE_V1_PREFIX`,
`generateSalt`, `deriveRawKey`, `deriveRawKeySecure`, `deriveKey`,
`importMasterKey`, `encrypt`/`decrypt`, `encryptBytes`/`decryptBytes`,
`encryptVaultItem`/`decryptVaultItem`, `decryptVaultItemForMigration`,
`isCurrentVaultItemEnvelope`, `createVerificationHash`, `verifyKey`,
`attemptKdfUpgrade`, `reEncryptString`, `reEncryptVault`, `createEncryptedUserKey`,
`migrateToUserKey`, `unwrapUserKey`, `unwrapUserKeyBytes`, `rewrapUserKey`,
`wrapPrivateKeyWithUserKey`/`unwrapPrivateKeyWithUserKey`, RSA helpers,
`generateSharedKey`/`encryptWithSharedKey`/`decryptWithSharedKey`.

PQ (`pqCryptoService.ts`): `HYBRID_VERSION`, `buildSharedKeyWrapAad`,
`generatePQKeyPair`, `generateHybridKeyPair`, `hybridEncrypt`/`hybridDecrypt`,
`hybridWrapKey`/`hybridUnwrapKey`, `isHybridEncrypted`, `migrateToHybrid`.

## Singra Premium — crypto usage

| File | Crypto role | DIS target |
| --- | --- | --- |
| `src/services/fileAttachmentService.ts` | Chunked file encryption, per-file key, manifest, AAD scheme | `file-encryption` (+ Supabase/Tauri transport stays in app) |
| `components/settings/EmergencyAccessSettings.tsx` | imports `cryptoService`, `pqCryptoService` | via DIS facade |
| `components/settings/SharedCollectionsSettings.tsx` | `keyMaterialService` | app orchestration |
| `pages/GrantorVaultPage.tsx`, `pages/AuthenticatorPage.tsx` | `cryptoService`, `VaultItemData` | via DIS facade |

**Current coupling:** Premium resolves core crypto by **filesystem path** —
`vitest.config.ts` aliases `@/services/*` to `../singravault/src`. There is no
package boundary today. Eliminating this path-alias coupling in favour of a
`@dis/shield` dependency is a primary objective.

## Call-site footprint (Singra Vault, non-test)

~35 non-test files import `@/services/{cryptoService,pqCryptoService,keyMaterialService,secureBuffer}`,
concentrated in `src/services`, `src/contexts/vault`, `src/components/vault`, and
`src/services/vaultIntegrityV2`. These become imports from `@dis/shield` (most
via a thin app-local `crypto` adapter — see `migration-plan.md`).

## Format constants (frozen — part of the contract)

| Constant | Value | Module |
| --- | --- | --- |
| Vault item envelope | `sv-vault-v1:` + `base64(IV‖CT‖tag)` | `vault-encryption` |
| User-key wrap | `usk-wrap-v2:` + `base64(IV‖CT‖tag)` | `key-management` |
| User-key wrap HKDF info | `singra-vault-wrap-v1` (zero salt) | `key-management` |
| Device-key HKDF info | `SINGRA_DEVICE_KEY_V1` | app-supplied to `kdf.strengthen` |
| File manifest envelope | `sv-file-manifest-v1:` | `file-encryption` |
| File-key AAD | `sv-file-key-v1:{owner}:{item}:{file}` | `file-encryption` |
| Chunk AAD | `sv-file-chunk-v1:{owner}:{item}:{file}:{rev}:{root}:{idx}:{count}` | `file-encryption` |
| KDF v1 / v2 | 64 MiB / 128 MiB Argon2id, t=3, p=4, 32B | `kdf` |
| AES-GCM | IV 12B, tag 128b, key 256b | `aead` |
| Verification constant | `SINGRA_VAULT_VERIFY_V3` | app (verification hash) |
| Hybrid (PQ) version byte | `VERSION_HYBRID_STANDARD_V2`; layout `ver‖pq_ct‖rsa_ct‖iv‖aes_ct` | `key-management` (phase 2) |
