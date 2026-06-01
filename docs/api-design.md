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

// KDF
deriveMasterKey(password, saltBase64, opts?): Promise<CryptoKey>  // == deriveAesGcmKey
deriveRawKey(password, saltBase64, opts?): Promise<Uint8Array>
generateSalt(): string

// Key management
createWrappedUserKey(kdfOutputBytes, scheme?): Promise<UserKeyBundle>
unwrapUserKey(encryptedUserKey, kdfOutputBytes, scheme?): Promise<CryptoKey>
rotateEncryptionKeys(encryptedUserKey, oldKdf, newKdf, scheme?): Promise<string>

// Integrity & migrations
verifyPayloadIntegrity(bytes, expectedBase64): Promise<void>
new MigrationRegistry().register(...).migrateToLatest(...)
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
