# Threat Model

Scope: the cryptographic layer (DIS) and the format/key decisions it owns.
Application-level threats are noted where DIS provides a control or where the
residual risk must be carried by the application.

Notation: **M** = mitigated by DIS, **A** = app responsibility, **R** =
accepted residual risk.

## Adversaries

Remote attacker, malicious/compromised server or DB, stolen device, malicious
browser extension/app, network attacker, insider/support, supply-chain
attacker, future quantum-capable attacker.

## Threats, controls, residual risk

| # | Threat | Control | Status |
| --- | --- | --- | --- |
| 1 | **Server/DB reads vault** | Zero-knowledge: only ciphertext + wrapped keys stored; AES-256-GCM under content key | M |
| 2 | **Ciphertext swap between rows** | Entry-id used as AEAD AAD binds ciphertext to its row | M |
| 3 | **Weak password brute force** | Argon2id 128 MiB (v2), versioned upgrade path | M (A: password policy) |
| 4 | **Nonce reuse** | Fresh CSPRNG 96-bit IV per encryption; never counter-based; negative test asserts IV uniqueness | M |
| 5 | **Downgrade / format manipulation** | Explicit version prefixes; unknown in-family versions fail closed; legacy no-AAD blocked on runtime path | M |
| 6 | **Migration attack** (force read of weaker legacy) | No-AAD read only via explicit migration API, never runtime | M |
| 7 | **Replay / rollback of chunks** | Chunk AAD binds owner/item/file/revision/manifest-root/index/count; manifest root over layout | M |
| 8 | **Cross-file chunk splice** | AAD includes file id + manifest root; per-file random key | M |
| 9 | **Tampered ciphertext** | GCM auth tag; optional per-chunk SHA-256 verification | M |
| 10 | **Key reuse across purposes** | HKDF domain separation (`info`), distinct KEK/content/file keys | M |
| 11 | **Password change forces re-encrypt** (availability/timing leak) | Content-key indirection: rotate re-wraps only | M |
| 12 | **Memory exposure / dumps** | `SecureBuffer`, wiped buffers, non-extractable keys | M (R: JS/GC cannot guarantee wiping) |
| 13 | **Secrets in logs** | Typed errors carry no secrets; no logging in crypto path | M (A: app logging) |
| 14 | **Metadata leaks** (file name, MIME, size) | Manifest is encrypted under vault key (AAD-bound); only ciphertext sizes/hashes are public | M (R: ciphertext size ≈ plaintext size) |
| 15 | **Quantum "harvest now, decrypt later"** on shared material | ML-KEM-768 + RSA hybrid wrapping for sharing | M (phase 2 in DIS) |
| 16 | **Supply-chain (malicious dep)** | No invented crypto; pinned audited deps; CI dependency + secret scanning; minimal surface | M (R: trust in `hash-wasm`/`noble`/WebCrypto) |
| 17 | **Provider substitution attack** | Single provider seam; default is platform WebCrypto; override is explicit | M |
| 18 | **Device-trust bypass** | DIS exposes HKDF strengthening; enforcement of `device_key_required` is app policy | A |
| 19 | **Recovery/export leaks** | DIS provides only authenticated formats; export packaging + recovery flows are app | A |
| 20 | **Multi-device sync conflicts / drift** | Authenticated, versioned formats; conflict/drift resolution is app | A |
| 21 | **Admin/support access** | No backdoor; no key escrow in DIS | M |
| 22 | **CI/build pipeline tampering** | CI runs lint/typecheck/test/build + dep & secret scan; no secrets needed at build | M (A: branch protection) |
| 23 | **Clipboard exposure** | Out of crypto scope | A |
| 24 | **AEAD/padding oracle** | Single opaque `DisDecryptionError` for all decrypt failures | M |

## Accepted residual risks

- **R-1 Memory wiping is best-effort.** JS GC is non-deterministic and strings
  are immutable; `SecureBuffer` reduces but cannot eliminate exposure.
- **R-2 Ciphertext length leaks approximate plaintext length** (no padding by
  default). Acceptable for password/attachment use; padding can be added as a
  future format version if a threat warrants it.
- **R-3 Primitive trust.** Soundness of Argon2id (`hash-wasm`), AES-GCM/HKDF
  (WebCrypto), and ML-KEM-768 (`@noble/post-quantum`) is assumed; DIS does not
  re-audit these.
- **R-4 Side channels in the host engine** (timing, cache) are out of scope for
  a portable JS library; constant-time compares are used where DIS controls the
  code.

## Not verified (require evidence before claims)

- Whether all current production payloads are already on `sv-vault-v1:` /
  `usk-wrap-v2:` (legacy no-AAD prevalence). Needs a production data audit.
- Whether browser, Tauri, and any mobile clients use identical crypto flows.
- Whether nonce management elsewhere in the apps (outside the extracted code)
  is correct.
