# Crypto Review

Review of the cryptographic choices DIS inherits from Singra and exposes. Each
item is rated and justified. Claims are backed by code/tests in this repo or
flagged `not verified`.

## Primitives

| Choice | Assessment | Notes |
| --- | --- | --- |
| **Argon2id** (memory-hard KDF) | Sound | Versioned params: v1 = 64 MiB, v2 = 128 MiB, t=3, p=4, 32-byte output. Memory-hard, resists GPU/ASIC. Upgrade path via version field. |
| **AES-256-GCM** AEAD | Sound | 96-bit random IV (correct length for GCM), 128-bit tag. Confidentiality + integrity + AAD. |
| **96-bit random IV** | Sound with caveat | Random IVs are safe for GCM up to ~2³² messages **per key**. Content-key is per-user; volumes are far below the birthday bound. Each call draws a fresh CSPRNG IV (tested). |
| **HKDF-SHA-256** for key separation | Sound | Domain-separated `info` per purpose (wrap-key, device-key). Zero salt acceptable because IKM (Argon2id output / device key) is already high-entropy. |
| **Content-key indirection** (UserKey) | Good design | Password change re-wraps the content key only; no bulk re-encryption; limits exposure of the password-derived key. |
| **Entry-id AAD on vault items** | Good | Binds ciphertext to its logical slot; defeats cross-row swap. |
| **Per-file random key + chunk AAD** | Good | File key wrapped under content key; chunk AAD binds owner/item/file/revision/manifest-root/index/count → resists reorder, splice, cross-file reuse, truncation. |
| **SHA-256 manifest root + per-chunk hash** | Good | Detects storage-level tampering independent of GCM tag. |
| **ML-KEM-768 + RSA-OAEP hybrid** (sharing) | Forward-looking | Hybrid protects against "harvest now, decrypt later"; classical RSA retained for defence in depth. Versioned blob layout. _Port to DIS in phase 2._ |
| **Non-extractable CryptoKeys** | Good | Imported keys cannot be exported from WebCrypto. |
| **SecureBuffer** wiping | Best-effort | `fill(0)` + FinalizationRegistry fallback; cannot defeat GC/string immutability (residual risk R-1). |

## Compliance with the mandated crypto rules

| Rule | Status |
| --- | --- |
| Audited libraries only, no invented crypto | ✔ `hash-wasm`, WebCrypto, `@noble/post-quantum` |
| AEAD | ✔ AES-256-GCM everywhere |
| Unique nonces | ✔ fresh random IV per call (tested) |
| Format versioning | ✔ prefixed envelopes, fail-closed |
| Associated data | ✔ entry id / attachment context / chunk index |
| Strong KDF | ✔ Argon2id, versioned params |
| Key separation | ✔ KEK ≠ content key ≠ file key (HKDF info) |
| Key wrapping | ✔ `usk-wrap-v2` content-key wrapping |
| Secure randomness | ✔ WebCrypto CSPRNG, never `Math.random` |
| Negative tests | ✔ wrong key, tampered, AAD mismatch, downgrade |
| Test vectors | ◐ base64/SHA-256/KDF determinism vectors present; **production golden vectors pending** (phase 1) |
| Documented migrations | ✔ this doc + migration-plan.md |
| No static salts | ✔ per-account random salt; HKDF zero-salt justified above |
| No password-as-key | ✔ always via Argon2id |
| No unauthenticated CBC | ✔ GCM only |
| No global mutable crypto state | ✔ single injectable provider seam |
| No secrets in logs / no debug bypass / no hidden fallback | ✔ typed secret-free errors; legacy read only via explicit migration API |

## Findings / recommendations

- **F-1 (must, phase 1):** capture byte-exact golden vectors from production and
  add cross-implementation decrypt tests before any app cutover (RK-1).
- **F-2 (should):** add property-based and fuzz tests for the envelope/manifest
  parsers; add large-file streaming benchmarks.
- **F-3 (consider):** optional length-hiding padding as a future format version
  if metadata-size leakage (R-2) becomes in-scope.
- **F-4 (verify):** confirm browser and Tauri use identical flows; no Tauri-only
  crypto in shared logic (per testing-runtime.md).

## Not verified

- Real-world zero-knowledge end-to-end (depends on app transport, not DIS).
- Prevalence of legacy no-AAD payloads in production.
- Correctness of nonce handling in app code outside the extracted modules.
