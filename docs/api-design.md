# Public API Design

Stability contract: the symbols below are the supported surface. They follow
semantic versioning. Internal changes (KDF tuning within a version, provider
internals) must not change these signatures.

## Stability tiers

- **Stable** — covered by semver; breaking changes require a major bump and a
  migration note.
- **Format-frozen** — string constants that appear in persisted data. These are
  never edited; new behaviour means a new versioned constant.

## High-level SDK (`@dis/shield`)

```ts
// Vault entries (content-key in, opaque record out)
encryptVaultEntry(data, key, entryId): Promise<string>   // -> "sv-vault-v1:..."
decryptVaultEntry(sealed, key, entryId): Promise<Record<string, unknown>>
decryptVaultEntryForMigration(sealed, key, entryId): Promise<VaultEntryMigrationResult>
isCurrentVaultEntryEnvelope(sealed): boolean

// Attachments (storage-agnostic; caller supplies chunk IO + key wrap)
encryptAttachment(input: EncryptAttachmentInput): Promise<{ manifest; manifestRoot }>
decryptAttachment(input: DecryptAttachmentInput): Promise<void>

// KDF (see @dis/shield/kdf for low-level access; vault-crypto profile below)
deriveMasterKey(password, saltBase64, opts?): Promise<CryptoKey>  // == deriveAesGcmKey
deriveRawKey(password, saltBase64, opts?): Promise<Uint8Array>
generateSalt(): string

// Note: `KDF_PARAMS` is **not** exported from the SDK facade.
// The SDK re-exports `CURRENT_KDF_VERSION` and `DEFAULT_KDF_PARAMS` from
// @dis/shield/kdf. The plain-record `KDF_PARAMS` alias lives in
// @dis/shield/vault-crypto and is meant for Singra's call sites that look
// up params by version. For new applications, prefer `DEFAULT_KDF_PARAMS`
// from the SDK facade or @dis/shield/kdf.

// Two KDF paths exist — pick by what you need:
//
// (1) Generic: takes a typed `opts.strengthen` for HKDF-Expand second-factor binding
deriveAesGcmKey(password, saltBase64, {
  version?: number,                  // KDF version registry; defaults to CURRENT_KDF_VERSION
  params?: Readonly<Record<number, KdfParams>>,  // optional override
  strengthen?: {                     // optional HKDF second-factor binding
    hkdfSalt: Uint8Array,
    info: string,                    // caller-owned domain-separation label
  },
}): Promise<CryptoKey>

// (2) Singra Vault profile (vault-crypto): positional `deviceKey` is the common case
deriveRawKey(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<Uint8Array>
deriveKey(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<CryptoKey>
deriveRawKeySecure(masterPassword, saltBase64, kdfVersion?, deviceKey?): Promise<SecureBuffer>
//
// When `deviceKey` is supplied, DIS strengthens the Argon2id output via HKDF-Expand
// with HKDF info = 'SINGRA_DEVICE_KEY_V1' and salt = the device key bytes.
// (The `info` string is part of the wire-format contract; see crypto-dependency-map.md.)

// Key management
createWrappedUserKey(kdfOutputBytes, scheme?): Promise<UserKeyBundle>
unwrapUserKey(encryptedUserKey, kdfOutputBytes, scheme?): Promise<CryptoKey>
rotateEncryptionKeys(encryptedUserKey, oldKdf, newKdf, scheme?): Promise<string>

// Integrity & migrations
verifyPayloadIntegrity(bytes, expectedBase64): Promise<void>

// Migration framework — see docs/migrations.md for the full guide.
// DIS provides the framework; the application registers concrete steps.
new MigrationRegistry().register(migration: Migration).migrateToLatest(
  subject: string,
  payload: string,
  detect: VersionDetector,
  context: MigrationContext,
): Promise<string>

// ---- Two functions share a name across modules — read carefully. -----------
//
// (a) Storage-format migration for a wrapped private key.
//     Lives in @dis/shield/vault-crypto. Rewrites a stored
//     'salt:enc' / 'ver:salt:enc' private-key blob to the hybrid
//     'pq-v2:ver:salt:encRsa:encPq' form.
migrateToHybridKeyPair(encryptedPrivateKey: string, masterPassword: string):
  Promise<{ publicKey: string; encryptedPrivateKey: string; pqPublicKey: string } | null>

// (b) Cipher-version migration for an already-hybrid PQ+RSA ciphertext.
//     Lives in @dis/shield/post-quantum. Re-encodes a v1 (0x01 RSA-only),
//     legacy (0x02), or standard v1 (0x03) hybrid ciphertext into the
//     current standard v2 (0x04). Byte-layout preserved.
migrateToHybrid(
  legacyCiphertext: string,
  rsaPrivateKey: string,            // JWK string
  pqSecretKey: string | null,       // base64; required for 0x02 and 0x03
  pqPublicKey: string,              // base64
  rsaPublicKey: string,             // JWK string
  aad?: string,
): Promise<string>
//
// Use (a) when you are reading a legacy stored private key and want to
// upgrade its storage format. Use (b) when you already have a hybrid
// ciphertext at an old version and want to refresh it in place.
```

## Design rules

1. **Keys, not passwords, cross most APIs.** Only `kdf` accepts a password.
   Everything else takes a `CryptoKey` or raw bytes, enforcing key separation.
2. **AAD is mandatory and explicit** where context binding matters
   (`entryId`, attachment context). It is a required parameter, not optional.
3. **Caller owns secret lifetime.** Functions returning `Uint8Array` secrets
   document that the caller must wipe; DIS wipes everything it allocates
   internally.
4. **No app types leak in.** A vault entry is `Record<string, unknown>`; an
   attachment's storage is expressed as `readChunk`/`writeChunk` callbacks.
5. **Errors are typed and secret-free.** All decrypt failures collapse to
   `DisDecryptionError` (no oracle). Unknown versions →
   `DisUnsupportedFormatVersionError`. Legacy on runtime path →
   `DisLegacyPayloadError`.
6. **Providers are injectable** via `setCryptoProvider` for tests/hardware.

## Breaking-change policy

- Format-frozen constants are append-only (`sv-vault-v1` → add `sv-vault-v2`,
  never edit v1). Decryption keeps reading all supported versions.
- Removing a legacy read path is a **major** change and requires documented
  evidence that no data depends on it.
- New optional parameters are minor; new required parameters are major.

## Breaking-change risks for the apps (at cutover)

| Change | Risk | Handling |
| --- | --- | --- |
| Premium `../singravault/src` alias → `@dis/shield` | import paths change | codemod + adapter, single PR |
| App crypto modules deleted | dangling imports | app-local `crypto` adapter re-exports DIS |
| Raw `crypto.subtle` banned | lint failures | provide adapter; fix call sites |
| Legacy no-AAD runtime read removed | old data unreadable | only after migration + telemetry gate |
