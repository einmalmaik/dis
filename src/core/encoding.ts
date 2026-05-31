/**
 * Byte/string/base64 encoding helpers.
 *
 * These intentionally reproduce the exact base64 encoding used by Singra Vault
 * and Singra Premium so that DIS is byte-compatible with already-stored
 * ciphertext. Do not "optimise" the algorithm in a way that changes output.
 */

/**
 * Encodes bytes to a standard (RFC 4648) base64 string.
 *
 * Uses a chunked loop over `String.fromCharCode` + `btoa` to stay identical to
 * the legacy `uint8ArrayToBase64` implementation while avoiding call-stack
 * overflows on large inputs.
 */
export function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        const chunk = bytes.subarray(i, i + chunkSize);
        binary += String.fromCharCode(...chunk);
    }
    return btoa(binary);
}

/** Decodes a standard base64 string to bytes. */
export function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

/** UTF-8 encodes a string to bytes. */
export function utf8ToBytes(text: string): Uint8Array {
    return textEncoder.encode(text);
}

/** UTF-8 decodes bytes to a string. */
export function bytesToUtf8(bytes: Uint8Array): string {
    return textDecoder.decode(bytes);
}

/** Concatenates byte arrays into a single new buffer. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    let total = 0;
    for (const part of parts) total += part.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
}
