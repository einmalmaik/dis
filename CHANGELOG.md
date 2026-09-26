# Changelog

All notable changes to the `@msdis/shield` library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.0] - 2026-09-26

### Added
- **`@msdis/shield/altcha`**: Fully local, privacy-preserving Proof-of-Work (PoW) CAPTCHA alternative based on SHA-256 and HMAC-SHA-256.
  - `createAltchaChallenge({ hmacKey, maxNumber?, expiresAt? })`: Generates a tamper-evident PoW challenge with random salt and HMAC-SHA-256 signature.
  - `verifyAltchaSolution(solution, hmacKey, maxNumber?)`: Constant-time verification of client PoW payloads, expiration timestamps, and signature integrity.
  - Zero external tracking, zero cookies, zero third-party dependencies, and 100% GDPR/DSGVO compliant.
  - Seamlessly integrates with the official `<altcha-widget>` Web Component.
- Comprehensive test suite for `@msdis/shield/altcha` (`src/altcha/altcha.test.ts`).
- Documentation in `README.md`, `AGENTS.md`, `GEMINI.md`, and integration guides.

### Compatibility
- **Purely additive:** No existing module, signature, or wire format has been altered. Existing consumers on `0.2.x` upgrade with zero breaking changes.

---

## [0.2.2] - 2026-09-17

### Added
- **`@msdis/shield/messaging`**: Signal Double Ratchet protocol for stateful, secure end-to-end communication.
  - ECDH P-256 DH ratchet.
  - HKDF-SHA-256 symmetric ratchet.
  - AES-256-GCM message sealing with header bound as AAD.
  - Forward secrecy and post-compromise security with skipped-key support.

---

## [0.2.1] - 2026-07-09

### Added
- Vault crypto and multi-device key agreement refinements.

---

## [0.1.0] - 2026-06-13

### Added
- Initial core release of `@msdis/shield` (AEAD, KDF, SecureMemory, Asymmetric, Post-Quantum, Format-Versioning, File-Encryption).
