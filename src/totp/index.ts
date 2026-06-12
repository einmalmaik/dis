/**
 * dis-totp — time-based one-time passwords (RFC 6238).
 *
 * Thin wrapper over the audited `otpauth` library so applications never embed
 * the OTP primitive directly. Parameters are pinned to the values Singra Vault
 * uses (SHA-1, 6 digits, 30-second period, 160-bit secrets) so existing
 * enrolled authenticators keep working unchanged.
 *
 * SHA-1 here is the standardised HMAC inside the TOTP construction (RFC 6238),
 * which every authenticator app implements; it is not used as a hash for any
 * security decision elsewhere.
 */

import * as OTPAuth from 'otpauth';
import { DisInvalidArgumentError } from '../core/errors.js';

/** TOTP parameters, fixed to remain compatible with enrolled authenticators. */
export const TOTP_ALGORITHM = 'SHA1' as const;
export const TOTP_DIGITS = 6;
export const TOTP_PERIOD_SECONDS = 30;
/** Secret size in bytes (160-bit) as produced by {@link generateTotpSecret}. */
export const TOTP_SECRET_SIZE = 20;

/** HMAC algorithms RFC 6238 permits and authenticator apps implement. */
export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

/**
 * Parameters for third-party TOTP entries (password-manager authenticator
 * storage). Unlike Singra's own 2FA enrolment — which is pinned to
 * SHA-1 / 6 digits / 30 s — imported entries carry whatever parameters the
 * issuing service chose, so each knob is explicit here.
 */
export interface TotpCodeOptions {
    /** HMAC algorithm. Defaults to {@link TOTP_ALGORITHM}. */
    readonly algorithm?: TotpAlgorithm;
    /** Code length. Defaults to {@link TOTP_DIGITS}. */
    readonly digits?: number;
    /** Time step in seconds. Defaults to {@link TOTP_PERIOD_SECONDS}. */
    readonly period?: number;
    /** Epoch milliseconds to generate for. Defaults to the current time. */
    readonly timestamp?: number;
}

export interface TotpParams {
    /** Issuer label shown in the authenticator app. */
    readonly issuer: string;
    /** Account label (typically the user's email). */
    readonly label: string;
    /** Base32-encoded shared secret. */
    readonly secret: string;
}

/** Generates a new base32-encoded 160-bit TOTP secret. */
export function generateTotpSecret(): string {
    return new OTPAuth.Secret({ size: TOTP_SECRET_SIZE }).base32;
}

function buildTotp(params: TotpParams): OTPAuth.TOTP {
    return new OTPAuth.TOTP({
        issuer: params.issuer,
        label: params.label,
        algorithm: TOTP_ALGORITHM,
        digits: TOTP_DIGITS,
        period: TOTP_PERIOD_SECONDS,
        secret: OTPAuth.Secret.fromBase32(params.secret.replace(/\s/g, '')),
    });
}

/** Builds the `otpauth://` provisioning URI for a QR code. */
export function buildTotpUri(params: TotpParams): string {
    if (!params.secret) {
        throw new DisInvalidArgumentError('TOTP secret is required');
    }
    return buildTotp(params).toString();
}

/**
 * Generates the TOTP code for a base32 `secret` with explicit parameters —
 * the primitive behind a password manager's authenticator view. Throws
 * {@link DisInvalidArgumentError} on a malformed secret so callers can decide
 * how to surface the error.
 */
export function generateTotpCode(secret: string, options: TotpCodeOptions = {}): string {
    let parsedSecret: OTPAuth.Secret;
    try {
        parsedSecret = OTPAuth.Secret.fromBase32(secret.replace(/\s/g, ''));
    } catch {
        throw new DisInvalidArgumentError('TOTP secret is not valid base32');
    }
    const totp = new OTPAuth.TOTP({
        algorithm: options.algorithm ?? TOTP_ALGORITHM,
        digits: options.digits ?? TOTP_DIGITS,
        period: options.period ?? TOTP_PERIOD_SECONDS,
        secret: parsedSecret,
    });
    return totp.generate(
        options.timestamp !== undefined ? { timestamp: options.timestamp } : undefined,
    );
}

/**
 * Builds the `otpauth://` provisioning URI for an entry with explicit
 * parameters (third-party authenticator entries). Singra's own 2FA enrolment
 * should keep using {@link buildTotpUri}, which pins the Singra parameter set.
 */
export function buildTotpUriWithOptions(
    params: TotpParams,
    options: Omit<TotpCodeOptions, 'timestamp'> = {},
): string {
    if (!params.secret) {
        throw new DisInvalidArgumentError('TOTP secret is required');
    }
    return new OTPAuth.TOTP({
        issuer: params.issuer,
        label: params.label,
        algorithm: options.algorithm ?? TOTP_ALGORITHM,
        digits: options.digits ?? TOTP_DIGITS,
        period: options.period ?? TOTP_PERIOD_SECONDS,
        secret: OTPAuth.Secret.fromBase32(params.secret.replace(/\s/g, '')),
    }).toString();
}

/**
 * Verifies a TOTP `code` against a base32 `secret`, allowing `window` periods
 * of clock drift on either side (default 1 = ±30s). Returns `true` on a match.
 * Malformed secrets/codes return `false` rather than throwing.
 */
export function verifyTotpCode(
    secret: string,
    code: string,
    window = 1,
): boolean {
    try {
        const totp = new OTPAuth.TOTP({
            algorithm: TOTP_ALGORITHM,
            digits: TOTP_DIGITS,
            period: TOTP_PERIOD_SECONDS,
            secret: OTPAuth.Secret.fromBase32(secret.replace(/\s/g, '')),
        });
        return totp.validate({ token: code.replace(/\s/g, ''), window }) !== null;
    } catch {
        return false;
    }
}
