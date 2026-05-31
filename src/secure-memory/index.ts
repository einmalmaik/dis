/**
 * dis-secure-storage / secure-memory — memory-safe handling of key material.
 *
 * Ported from Singra Vault's SecureBuffer. Provides controlled, callback-scoped
 * access to sensitive bytes with explicit zeroing on destroy and a
 * FinalizationRegistry fallback. This is defense-in-depth: JavaScript cannot
 * guarantee memory wiping (GC is non-deterministic, strings are immutable), but
 * controlled access plus best-effort zeroing materially reduces exposure
 * (cf. KeePass CVE-2023-32784).
 */

import { getCryptoProvider } from '../core/provider.js';
import { DisError, DisInvalidArgumentError } from '../core/errors.js';

const cleanupRegistry = new FinalizationRegistry<Uint8Array>((buffer) => {
    try {
        buffer.fill(0);
    } catch {
        // Buffer may already be detached or GC'd.
    }
});

function assertLive(destroyed: boolean): void {
    if (destroyed) {
        throw new DisError('USE_AFTER_DESTROY', 'SecureBuffer has been destroyed');
    }
}

/** A wrapper for sensitive binary data with controlled access and zeroing. */
export class SecureBuffer {
    private buffer: Uint8Array;
    private destroyed = false;

    constructor(size: number) {
        if (size <= 0 || !Number.isInteger(size)) {
            throw new DisInvalidArgumentError('SecureBuffer size must be a positive integer');
        }
        this.buffer = new Uint8Array(size);
        cleanupRegistry.register(this, this.buffer, this);
    }

    /** Copies `bytes` into a new SecureBuffer. The source is NOT auto-zeroed. */
    static fromBytes(bytes: Uint8Array): SecureBuffer {
        const secure = new SecureBuffer(bytes.length || 1);
        if (bytes.length === 0) {
            secure.destroy();
            throw new DisInvalidArgumentError('Cannot create SecureBuffer from empty bytes');
        }
        secure.buffer.set(bytes);
        return secure;
    }

    /** Builds a SecureBuffer from a hex string (spaces/dashes allowed). */
    static fromHex(hex: string): SecureBuffer {
        const cleanHex = hex.replace(/[\s-]/g, '');
        if (cleanHex.length === 0 || cleanHex.length % 2 !== 0) {
            throw new DisInvalidArgumentError('Hex string must have a positive even length');
        }
        const secure = new SecureBuffer(cleanHex.length / 2);
        for (let i = 0; i < secure.buffer.length; i++) {
            const value = parseInt(cleanHex.substr(i * 2, 2), 16);
            if (Number.isNaN(value)) {
                secure.destroy();
                throw new DisInvalidArgumentError(`Invalid hex byte at position ${i * 2}`);
            }
            secure.buffer[i] = value;
        }
        return secure;
    }

    /** Allocates a SecureBuffer filled with CSPRNG bytes. */
    static random(size: number): SecureBuffer {
        const secure = new SecureBuffer(size);
        getCryptoProvider().getRandomValues(secure.buffer);
        return secure;
    }

    /** Synchronous controlled access. Do not retain the buffer past `fn`. */
    use<T>(fn: (data: Uint8Array) => T): T {
        assertLive(this.destroyed);
        return fn(this.buffer);
    }

    /** Asynchronous controlled access. */
    async useAsync<T>(fn: (data: Uint8Array) => Promise<T>): Promise<T> {
        assertLive(this.destroyed);
        return fn(this.buffer);
    }

    get size(): number {
        assertLive(this.destroyed);
        return this.buffer.length;
    }

    get isDestroyed(): boolean {
        return this.destroyed;
    }

    /** Zeros the buffer and marks it destroyed. Idempotent. */
    destroy(): void {
        if (this.destroyed) return;
        this.buffer.fill(0);
        cleanupRegistry.unregister(this);
        this.destroyed = true;
    }

    /** Returns a mutable copy of the contents (caller must zero it). */
    toBytes(): Uint8Array {
        assertLive(this.destroyed);
        return new Uint8Array(this.buffer);
    }

    /** Constant-time equality comparison against another buffer. */
    equals(other: SecureBuffer | Uint8Array): boolean {
        assertLive(this.destroyed);
        const otherBytes = other instanceof SecureBuffer ? other.buffer : other;
        if (this.buffer.length !== otherBytes.length) return false;
        let result = 0;
        for (let i = 0; i < this.buffer.length; i++) {
            result |= this.buffer[i]! ^ otherBytes[i]!;
        }
        return result === 0;
    }
}

/** Runs `fn` with a temporary SecureBuffer that is always destroyed afterwards. */
export async function withSecureBuffer<T>(
    bytes: Uint8Array,
    fn: (secure: SecureBuffer) => Promise<T>,
): Promise<T> {
    const secure = SecureBuffer.fromBytes(bytes);
    try {
        return await fn(secure);
    } finally {
        secure.destroy();
    }
}

/** Zeros multiple buffers. Convenience for `finally` cleanup blocks. */
export function zeroBuffers(...buffers: (Uint8Array | null | undefined)[]): void {
    for (const buffer of buffers) {
        buffer?.fill(0);
    }
}
