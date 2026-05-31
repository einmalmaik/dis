# Trust-Boundary Analysis

## Assets

- Master password (never persisted, never leaves client).
- KDF output, KEK, content key (UserKey), file keys, device keys, recovery
  secrets, RSA/ML-KEM private keys.
- Plaintext vault entries and attachment contents.
- Metadata: file names, MIME types, sizes, timestamps, item ids, category
  structure.
- Verification hashes, wrapped keys, manifests (stored, but authenticated).

## Trust boundaries

1. **Client ↔ Server (zero-knowledge boundary).** The server stores only
   ciphertext, salts, wrapped keys, verification hashes, and manifests. It must
   never see the master password, KDF output, or any unwrapped key. DIS runs
   entirely client-side; it has no network code, which keeps this boundary
   structurally enforced.
2. **Application ↔ DIS.** Apps pass passwords/keys/plaintext in and receive
   ciphertext/keys out. DIS owns all primitive use. The app owns persistence,
   transport, and policy (e.g. when device-key is required).
3. **DIS ↔ crypto provider.** DIS depends on an audited `CryptoProvider`
   (WebCrypto by default) and `hash-wasm`/`@noble/post-quantum`. These are the
   trusted computing base for primitives.
4. **Browser/Tauri runtime ↔ OS.** Memory exposure, swap, and process dumps are
   outside DIS's control; `SecureBuffer` is best-effort mitigation only.
5. **Storage transport (object store / local FS).** Treated as untrusted:
   chunk AADs and the manifest root bind ciphertext to its place, so a storage
   operator cannot reorder, splice, or swap chunks/files undetected.

## Key lifecycle

```
master password ──Argon2id(salt, version)──▶ KDF output
        │                                        │
        │                              HKDF(info=wrap)──▶ KEK
        │                                        │
        │                          AES-GCM unwrap(usk-wrap-v2)──▶ content key (UserKey)
        │                                                              │
        │                       content key ──▶ vault entries (sv-vault-v1, AAD=entryId)
        │                       content key ──▶ wraps file keys (AAD=file-key-v1)
        └─ optional HKDF strengthen with device key (info=SINGRA_DEVICE_KEY_V1)

password change / rotation: re-wrap content key only (rotateEncryptionKeys);
no vault data is re-encrypted.
```

## Boundary rules enforced by DIS

- AEAD failures do not reveal cause (no oracle).
- Unknown format versions fail closed.
- Legacy no-AAD payloads are unreadable on the runtime path; only the explicit
  migration helper may read them.
- Key material is wiped after use; `CryptoKey`s are non-extractable.

## Out of DIS scope (app responsibility)

- Deciding device-key/passkey requirements and enforcing lock/logout state.
- Drift detection, quarantine, integrity-recovery orchestration.
- Where/whether to store salts, wrapped keys, manifests; access control.
- Clipboard, autofill, screenshot, and UI-level exposure.
