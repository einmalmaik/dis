/**
 * dis-kdf — password-based key derivation.
 *
 * Primitive: Argon2id (via the audited `hash-wasm` implementation), with
 * versioned, immutable parameter sets so accounts can be transparently
 * upgraded to stronger parameters over time. Optional HKDF-Expand strengthening
 * binds the derived key to a second factor (e.g. a device key) without
 * weakening the password-derived material.
 *
 * DIS does not invent a KDF. Parameters follow OWASP Argon2id guidance.
 */

import { argon2id } from 'hash-wasm';
import { getCryptoProvider, subtle } from '../core/provider.js';
import { base64ToBytes, bytesToBase64 } from '../core/encoding.js';
import { KDF_SALT_LENGTH } from '../core/constants.js';
import {
    DisError,
    DisInvalidArgumentError,
} from '../core/errors.js';

/** Argon2id parameter set. Once released, a version's params are immutable. */
export interface KdfParams {
    /** Memory cost in KiB. */
    readonly memory: number;
    /** Iteration (time) cost. */
    readonly iterations: number;
    /** Degree of parallelism. */
    readonly parallelism: number;
    /** Output length in bytes. */
    readonly hashLength: number;
}

/**
 * Default versioned parameter registry. Byte-compatible with Singra Vault:
 *   v1: 64 MiB  (original baseline)
 *   v2: 128 MiB (current; exceeds OWASP Argon2id minimum)
 *
 * IMPORTANT: never change an existing version's parameters — only add versions.
 */
export const DEFAULT_KDF_PARAMS: Readonly<Record<number, KdfParams>> = Object.freeze({
    1: { memory: 65536, iterations: 3, parallelism: 4, hashLength: 32 },
    2: { memory: 131072, iterations: 3, parallelism: 4, hashLength: 32 },
});

/** The latest KDF version. New accounts derive with this version. */
export const CURRENT_KDF_VERSION = 2;

/** Optional second-factor strengthening via HKDF-Expand (SHA-256). */
export interface KdfStrengthenOptions {
    /** Salt for HKDF (e.g. a 256-bit device key). */
    readonly hkdfSalt: Uint8Array;
    /** Domain-separation `info` string for HKDF. Caller-owned (format contract). */
    readonly info: string;
}

export interface DeriveRawKeyOptions {
    /** KDF version to look up in `params`. Defaults to {@link CURRENT_KDF_VERSION}. */
    readonly version?: number;
    /** Parameter registry. Defaults to {@link DEFAULT_KDF_PARAMS}. */
    readonly params?: Readonly<Record<number, KdfParams>>;
    /** Optional HKDF strengthening (e.g. device-key binding). */
    readonly strengthen?: KdfStrengthenOptions;
}

/** Generates a cryptographically secure, base64-encoded salt. */
export function generateSalt(): string {
    const salt = new Uint8Array(KDF_SALT_LENGTH);
    getCryptoProvider().getRandomValues(salt);
    return bytesToBase64(salt);
}

async function hkdfStrengthen(
    argon2Output: Uint8Array,
    options: KdfStrengthenOptions,
): Promise<Uint8Array> {
    const baseKey = await subtle().importKey('raw', argon2Output as BufferSource, 'HKDF', false, [
        'deriveBits',
    ]);
    const info = new TextEncoder().encode(options.info);
    const derivedBits = await subtle().deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: options.hkdfSalt as BufferSource,
            info: info as BufferSource,
        },
        baseKey,
        argon2Output.length * 8,
    );
    return new Uint8Array(derivedBits);
}

/**
 * Derives raw key bytes from a password using Argon2id (+ optional HKDF).
 *
 * The caller owns the returned buffer and MUST wipe it (`.fill(0)`).
 */
export async function deriveRawKey(
    password: string,
    saltBase64: string,
    options: DeriveRawKeyOptions = {},
): Promise<Uint8Array> {
    const version = options.version ?? CURRENT_KDF_VERSION;
    const registry = options.params ?? DEFAULT_KDF_PARAMS;
    const params = registry[version];
    if (!params) {
        throw new DisError('UNSUPPORTED_KDF_VERSION', `Unknown KDF version: ${version}`);
    }
    if (typeof password !== 'string' || password.length === 0) {
        throw new DisInvalidArgumentError('password must be a non-empty string');
    }

    const salt = base64ToBytes(saltBase64);
    const result = (await argon2id({
        password,
        salt,
        parallelism: params.parallelism,
        iterations: params.iterations,
        memorySize: params.memory,
        hashLength: params.hashLength,
        outputType: 'binary',
    })) as unknown;

    let argon2Bytes: Uint8Array;
    if (result instanceof Uint8Array) {
        argon2Bytes = result;
    } else if (result instanceof ArrayBuffer) {
        argon2Bytes = new Uint8Array(result);
    } else {
        throw new DisError('KEY_DERIVATION_FAILED', 'Unexpected Argon2id output type');
    }

    if (!options.strengthen) {
        return argon2Bytes;
    }

    try {
        return await hkdfStrengthen(argon2Bytes, options.strengthen);
    } finally {
        argon2Bytes.fill(0);
    }
}

/** Imports raw 256-bit key bytes as a non-extractable AES-GCM CryptoKey. */
export async function importAesGcmKey(keyBytes: Uint8Array | BufferSource): Promise<CryptoKey> {
    return subtle().importKey(
        'raw',
        keyBytes as BufferSource,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
}

/**
 * Derives a non-extractable AES-GCM key from a password. Raw key bytes are
 * wiped as soon as the CryptoKey is imported.
 */
export async function deriveAesGcmKey(
    password: string,
    saltBase64: string,
    options: DeriveRawKeyOptions = {},
): Promise<CryptoKey> {
    const keyBytes = await deriveRawKey(password, saltBase64, options);
    try {
        return await importAesGcmKey(keyBytes);
    } finally {
        keyBytes.fill(0);
    }
}

/** Explicit Argon2id parameters for a single ad-hoc derivation. */
export interface Argon2idRawParams {
    readonly password: string;
    readonly salt: Uint8Array;
    /** Memory cost in KiB. */
    readonly memorySize: number;
    readonly iterations: number;
    readonly parallelism: number;
    readonly hashLength: number;
}

/**
 * Low-level Argon2id derivation returning raw key bytes. This is the audited
 * `hash-wasm` Argon2id with caller-chosen parameters and a raw byte salt — for
 * call sites that derive a key with a context-specific salt/param set (device
 * key transfer wrapping, integrity HMAC key) rather than the versioned account
 * KDF registry used by {@link deriveRawKey}.
 */
export async function argon2idRaw(params: Argon2idRawParams): Promise<Uint8Array> {
    if (typeof params.password !== 'string' || params.password.length === 0) {
        throw new DisInvalidArgumentError('password must be a non-empty string');
    }
    const result = await argon2id({
        password: params.password,
        salt: params.salt,
        parallelism: params.parallelism,
        iterations: params.iterations,
        memorySize: params.memorySize,
        hashLength: params.hashLength,
        outputType: 'binary',
    });
    return new Uint8Array(result);
}

/**
 * HKDF-SHA-256 expand/extract producing `lengthBits` of key material.
 *
 * `ikm` is the input keying material, `salt` defaults to the empty salt (the
 * op-log record/snapshot derivations use an empty salt and put all context in
 * `info`; the device-key derivation uses the device key as salt).
 */
export async function deriveHkdfSha256Bits(
    ikm: Uint8Array,
    options: { info: Uint8Array; salt?: Uint8Array; lengthBits?: number },
): Promise<Uint8Array> {
    const baseKey = await subtle().importKey(
        'raw',
        ikm as BufferSource,
        { name: 'HKDF' },
        false,
        ['deriveBits'],
    );
    const bits = await subtle().deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: (options.salt ?? new Uint8Array(0)) as BufferSource,
            info: options.info as BufferSource,
        },
        baseKey,
        options.lengthBits ?? 256,
    );
    return new Uint8Array(bits);
}

/**
 * HKDF-SHA-256 deriving directly into a non-extractable AES-256-GCM key,
 * mirroring `crypto.subtle.deriveKey` (used by passkey PRF wrapping and the
 * legacy device-key wrapping path).
 */
export async function deriveHkdfAesGcmKey(
    ikm: Uint8Array,
    options: { info: Uint8Array; salt?: Uint8Array; usages?: KeyUsage[] },
): Promise<CryptoKey> {
    const baseKey = await subtle().importKey(
        'raw',
        ikm as BufferSource,
        'HKDF',
        false,
        ['deriveKey'],
    );
    return subtle().deriveKey(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: (options.salt ?? new Uint8Array(0)) as BufferSource,
            info: options.info as BufferSource,
        },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        options.usages ?? ['encrypt', 'decrypt'],
    );
}
