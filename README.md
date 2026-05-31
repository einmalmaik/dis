# DIS — Defensive Integration Shield

> **Powered by DIS — Defensive Integration Shield**

DIS is a central, framework-agnostic cryptographic security platform. It is the
single place where encryption, key management, secure data formats, KDFs,
versioning, and future migrations live — so that consuming applications
(Singra Vault, Singra Premium, and future projects) hold **no direct crypto
logic** and depend only on stable, versioned public APIs.

DIS **does not invent cryptography**. It composes audited, established
primitives:

| Concern | Primitive | Source |
| --- | --- | --- |
| Password KDF | Argon2id (versioned params) | [`hash-wasm`](https://github.com/Daninet/hash-wasm) |
| Authenticated encryption | AES-256-GCM (96-bit IV, 128-bit tag) | WebCrypto `SubtleCrypto` |
| Key separation / wrapping | HKDF-SHA-256 + AES-GCM | WebCrypto |
| Random | CSPRNG | WebCrypto `getRandomValues` |
| Post-quantum (optional) | ML-KEM-768 hybrid | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) |

## Status

This is the **foundation release** (`0.1.0`). The pure, portable primitives
(encoding, random, secure memory, KDF, AEAD, vault-entry encryption, key
wrapping/rotation, chunked file encryption, integrity, format versioning,
migration framework) are implemented and tested. The post-quantum hybrid
sharing layer and the application cutover are tracked in
[`docs/migration-plan.md`](docs/migration-plan.md).

## Install

```bash
npm install @dis/shield
# Optional, only if you use the post-quantum sharing module:
npm install @noble/post-quantum
```

Requires Node `>=20.19.0` or a browser with WebCrypto.

## Usage

```ts
import {
  deriveMasterKey,
  encryptVaultEntry,
  decryptVaultEntry,
  createWrappedUserKey,
  rotateEncryptionKeys,
} from '@dis/shield';

const salt = '...'; // base64, stored per account
const kek = await deriveMasterKey(masterPassword, salt); // Argon2id -> AES-GCM key

const sealed = await encryptVaultEntry({ password: 's3cret' }, kek, entryId);
const data = await decryptVaultEntry(sealed, kek, entryId);
```

Narrow imports are tree-shakeable:

```ts
import { encryptBytes } from '@dis/shield/aead';
import { deriveRawKey } from '@dis/shield/kdf';
```

## Modules

| Entry point | Responsibility |
| --- | --- |
| `@dis/shield/core` | Errors, encoding, constants, crypto-provider abstraction |
| `@dis/shield/random` | Secure random bytes / UUIDs |
| `@dis/shield/secure-memory` | `SecureBuffer` for key material |
| `@dis/shield/kdf` | Argon2id, versioned parameters, HKDF strengthening |
| `@dis/shield/aead` | AES-256-GCM encrypt/decrypt with AAD |
| `@dis/shield/format-versioning` | Versioned, prefix-tagged envelopes |
| `@dis/shield/vault-encryption` | Vault-entry sealing (entry-id AAD binding) |
| `@dis/shield/file-encryption` | Chunked attachment encryption + manifests |
| `@dis/shield/key-management` | Content-key wrap / unwrap / rotation |
| `@dis/shield/post-quantum` | ML-KEM-768 + RSA-4096 hybrid key wrapping (sharing / emergency access) |
| `@dis/shield/integrity` | SHA-256, constant-time compare, verification |
| `@dis/shield/migrations` | Ordered, explicit payload migrations |

## Security

See [`docs/`](docs/) for the architecture overview, threat model,
trust-boundary analysis, crypto review, and migration plan. Security
properties are only claimed where they are backed by code, tests, or
documentation. Anything unverified is labelled `not verified`.

## License

[PolyForm Noncommercial 1.0.0](LICENSE) — source-available, free for
noncommercial use. **Not free for commercial use.** See
[`docs/licensing.md`](docs/licensing.md) for the rationale, trademark/branding
rules, and commercial dual-licensing.
