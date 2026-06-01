/**
 * Central, typed error hierarchy for DIS.
 *
 * Errors never include secret material (keys, plaintext, passwords) in their
 * message or properties. Callers may safely log `error.code` and `error.message`.
 */

export type DisErrorCode =
    | 'INVALID_ARGUMENT'
    | 'UNSUPPORTED_FORMAT_VERSION'
    | 'DECRYPTION_FAILED'
    | 'INTEGRITY_CHECK_FAILED'
    | 'KEY_DERIVATION_FAILED'
    | 'UNSUPPORTED_KDF_VERSION'
    | 'LEGACY_PAYLOAD_REQUIRES_MIGRATION'
    | 'PROVIDER_UNAVAILABLE'
    | 'USE_AFTER_DESTROY';

/** Base class for all errors thrown by DIS. */
export class DisError extends Error {
    readonly code: DisErrorCode;

    constructor(code: DisErrorCode, message: string) {
        super(message);
        this.name = 'DisError';
        this.code = code;
        // Maintain prototype chain when compiled to older targets.
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/** Thrown when an argument is missing or structurally invalid. */
export class DisInvalidArgumentError extends DisError {
    constructor(message: string) {
        super('INVALID_ARGUMENT', message);
        this.name = 'DisInvalidArgumentError';
    }
}

/**
 * Thrown when AEAD decryption or authentication fails. The cause (wrong key,
 * tampered ciphertext, or AAD mismatch) is intentionally not distinguished to
 * avoid leaking an oracle.
 */
export class DisDecryptionError extends DisError {
    constructor(message = 'Decryption failed') {
        super('DECRYPTION_FAILED', message);
        this.name = 'DisDecryptionError';
    }
}

/** Thrown when a versioned payload carries a version DIS cannot read. */
export class DisUnsupportedFormatVersionError extends DisError {
    constructor(message: string) {
        super('UNSUPPORTED_FORMAT_VERSION', message);
        this.name = 'DisUnsupportedFormatVersionError';
    }
}

/** Thrown when an integrity / hash verification fails. */
export class DisIntegrityError extends DisError {
    constructor(message = 'Integrity check failed') {
        super('INTEGRITY_CHECK_FAILED', message);
        this.name = 'DisIntegrityError';
    }
}

/** Thrown when a legacy, non-migratable payload is read on a runtime path. */
export class DisLegacyPayloadError extends DisError {
    constructor(message = 'Legacy payload requires explicit migration') {
        super('LEGACY_PAYLOAD_REQUIRES_MIGRATION', message);
        this.name = 'DisLegacyPayloadError';
    }
}
