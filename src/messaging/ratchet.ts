/**
 * dis-messaging — the Signal Double Ratchet as a pure state machine.
 *
 * Model:
 *   - A **symmetric ratchet** advances a chain key with HKDF-SHA-256 for every
 *     message, yielding a single-use message key that is destroyed after use.
 *     This gives forward secrecy: a key recovered today opens nothing sent
 *     before it.
 *   - A **DH ratchet** mixes a fresh ECDH P-256 agreement into the root key
 *     whenever the conversation changes direction. This gives post-compromise
 *     security: one uncompromised round trip heals the session.
 *   - Each message is sealed with AES-256-GCM under a key and nonce derived
 *     from its message key, with the header bound in as associated data.
 *
 * DIS does not invent any of this — it is RFC 5869 HKDF, NIST P-256 ECDH and
 * AES-256-GCM, composed as specified by the Double Ratchet algorithm.
 *
 * Purity contract: `encryptMessage` and `decryptMessage` never mutate, wipe or
 * retain their input state. They return a fresh `nextState`; the caller
 * persists it and then calls {@link destroyRatchetState} on the state it
 * replaced. Decryption in particular works on a private clone and commits only
 * after the AEAD tag verifies, so a forged message can never advance — or
 * wedge — a live session.
 *
 * Key exchange (X3DH or any other handshake) is explicitly out of scope: the
 * initial `sharedSecret` is supplied by the caller.
 */

import { aesGcmDecrypt, aesGcmEncrypt } from '../aead/index.js';
import { deriveHkdfSha256Bits } from '../kdf/index.js';
import { SecureBuffer, zeroBuffers } from '../secure-memory/index.js';
import { formatEnvelope, parseEnvelope } from '../format-versioning/index.js';
import type { VersionedCipherEnvelopeSpec } from '../format-versioning/index.js';
import { subtle } from '../core/provider.js';
import {
    base64ToBytes,
    bytesToBase64,
    concatBytes,
    utf8ToBytes,
} from '../core/encoding.js';
import { DisDecryptionError, DisInvalidArgumentError } from '../core/errors.js';
import {
    DEFAULT_MAX_SKIPPED_KEYS,
    DH_PRIVATE_KEY_LENGTH,
    DH_PUBLIC_KEY_LENGTH,
    RATCHET_KEY_LENGTH,
    RATCHET_MESSAGE_V1_PREFIX,
    RATCHET_MESSAGE_V1_TAG,
    RATCHET_STATE_V1_PREFIX,
} from './types.js';
import type {
    DecryptMessageResult,
    EncryptMessageResult,
    InitReceiverStateInput,
    InitSenderStateInput,
    RatchetDhKeyPair,
    RatchetHeader,
    RatchetMessage,
    RatchetState,
    SkippedMessageKey,
} from './types.js';

// ---------------------------------------------------------------------------
// Format contract — frozen constants
//
// Changing any value below is a breaking format change and must be expressed
// as a new version (`sv-dr-msg-v2:` / `sv-dr-state-v2:`), never an in-place
// edit. See CLAUDE.md principle 3 (zero breakage).
// ---------------------------------------------------------------------------

/** HKDF `info` for the DH ratchet: root key + chain key. */
const ROOT_KDF_INFO = utf8ToBytes('sv-dr-root-v1');

/** HKDF `info` for the symmetric ratchet: next chain key + message key. */
const CHAIN_KDF_INFO = utf8ToBytes('sv-dr-chain-v1');

/** HKDF `info` expanding a message key into an AES-GCM key + nonce. */
const MESSAGE_KDF_INFO = utf8ToBytes('sv-dr-msg-v1');

/**
 * Explicit all-zero HKDF salt. RFC 5869 substitutes HashLen zero bytes for an
 * absent salt, so this is spelled out rather than omitted to keep the contract
 * unambiguous for any reimplementation.
 */
const ZERO_SALT = new Uint8Array(32);

/** Domain separator between the AAD segments. */
const AAD_SEPARATOR = new Uint8Array([0x00]);

const EMPTY_BYTES = new Uint8Array(0);

/** Bytes of AES key + GCM nonce expanded from one message key. */
const AES_KEY_BYTES = 32;
const GCM_NONCE_BYTES = 12;
const MESSAGE_MATERIAL_BYTES = AES_KEY_BYTES + GCM_NONCE_BYTES;

const ECDH_P256_ALGORITHM = { name: 'ECDH', namedCurve: 'P-256' } as const;

const MESSAGE_ENVELOPE_SPEC: VersionedCipherEnvelopeSpec = {
    currentPrefix: RATCHET_MESSAGE_V1_PREFIX,
    familyPrefix: 'sv-dr-msg-',
    subject: 'ratchet message',
};

const STATE_ENVELOPE_SPEC: VersionedCipherEnvelopeSpec = {
    currentPrefix: RATCHET_STATE_V1_PREFIX,
    familyPrefix: 'sv-dr-state-',
    subject: 'ratchet state',
};

export {
    DEFAULT_MAX_SKIPPED_KEYS,
    RATCHET_MESSAGE_V1_PREFIX,
    RATCHET_STATE_V1_PREFIX,
} from './types.js';

// ---------------------------------------------------------------------------
// Internal mutable working state
//
// `RatchetState` is deeply readonly for callers. Decryption needs a scratch
// copy it can advance step by step, so it clones into this shape and only ever
// hands the clone back after the AEAD tag has verified.
// ---------------------------------------------------------------------------

interface MutableRatchetState {
    version: 1;
    dhSelf: RatchetDhKeyPair;
    dhRemote: Uint8Array | null;
    rootKey: Uint8Array;
    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;
    sendCount: number;
    receiveCount: number;
    previousSendCount: number;
    skippedMessageKeys: SkippedMessageKey[];
    maxSkippedKeys: number;
    associatedData: Uint8Array | null;
}

function cloneKeyPair(pair: RatchetDhKeyPair): RatchetDhKeyPair {
    return {
        algorithm: pair.algorithm,
        publicKey: new Uint8Array(pair.publicKey),
        privateKey: new Uint8Array(pair.privateKey),
    };
}

function cloneState(state: RatchetState): MutableRatchetState {
    return {
        version: 1,
        dhSelf: cloneKeyPair(state.dhSelf),
        dhRemote: state.dhRemote === null ? null : new Uint8Array(state.dhRemote),
        rootKey: new Uint8Array(state.rootKey),
        sendingChainKey:
            state.sendingChainKey === null ? null : new Uint8Array(state.sendingChainKey),
        receivingChainKey:
            state.receivingChainKey === null ? null : new Uint8Array(state.receivingChainKey),
        sendCount: state.sendCount,
        receiveCount: state.receiveCount,
        previousSendCount: state.previousSendCount,
        skippedMessageKeys: state.skippedMessageKeys.map((entry) => ({
            dh: entry.dh,
            n: entry.n,
            messageKey: new Uint8Array(entry.messageKey),
        })),
        maxSkippedKeys: state.maxSkippedKeys,
        associatedData:
            state.associatedData === null ? null : new Uint8Array(state.associatedData),
    };
}

// ---------------------------------------------------------------------------
// ECDH P-256
// ---------------------------------------------------------------------------

/**
 * Generates a fresh ratchet key pair, exported to the byte form the state
 * stores. The private key is generated extractable because a Double Ratchet
 * state must be persistable across restarts — it is exported once here and
 * from then on only ever held as bytes the caller can wipe.
 */
export async function generateRatchetKeyPair(): Promise<RatchetDhKeyPair> {
    const pair = await subtle().generateKey(ECDH_P256_ALGORITHM, true, ['deriveBits']);
    const publicKey = new Uint8Array(await subtle().exportKey('raw', pair.publicKey));
    const privateKey = new Uint8Array(await subtle().exportKey('pkcs8', pair.privateKey));
    return { algorithm: 'ECDH-P-256', publicKey, privateKey };
}

/**
 * ECDH agreement, returning the 32-byte shared secret in a SecureBuffer.
 *
 * WebCrypto rejects a public key that is not a valid curve point with a
 * `DataError`. Callers on an attacker-controlled path must translate that into
 * {@link DisDecryptionError} so a tampered header is indistinguishable from a
 * tampered ciphertext.
 */
async function ecdhShared(
    privateKeyBytes: Uint8Array,
    publicKeyBytes: Uint8Array,
): Promise<SecureBuffer> {
    const privateKey = await subtle().importKey(
        'pkcs8',
        privateKeyBytes as BufferSource,
        ECDH_P256_ALGORITHM,
        false,
        ['deriveBits'],
    );
    const publicKey = await subtle().importKey(
        'raw',
        publicKeyBytes as BufferSource,
        ECDH_P256_ALGORITHM,
        false,
        [],
    );
    const bits = await subtle().deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256);
    const shared = new Uint8Array(bits);
    try {
        return SecureBuffer.fromBytes(shared);
    } finally {
        shared.fill(0);
    }
}

// ---------------------------------------------------------------------------
// KDF stages
// ---------------------------------------------------------------------------

/** Splits HKDF output into two halves, wiping the source. */
function split(derived: Uint8Array, at: number): [Uint8Array, Uint8Array] {
    try {
        return [derived.slice(0, at), derived.slice(at)];
    } finally {
        derived.fill(0);
    }
}

/**
 * Rejects a peer public key that is not a valid P-256 point.
 *
 * WebCrypto signals this with a `DataError`, which would otherwise escape
 * `decryptMessage` as a distinguishable failure — telling an attacker that
 * their forged header failed point validation rather than tag verification.
 * Checking here, before any ratchet work, collapses it into the single
 * {@link DisDecryptionError} every other failure produces.
 */
async function assertValidRemotePublicKey(publicKeyBytes: Uint8Array): Promise<void> {
    try {
        await subtle().importKey(
            'raw',
            publicKeyBytes as BufferSource,
            ECDH_P256_ALGORITHM,
            false,
            [],
        );
    } catch {
        throw new DisDecryptionError();
    }
}

/**
 * DH ratchet step: `HKDF(salt = rootKey, ikm = ecdhShared)` → new root key and
 * a fresh chain key.
 */
async function rootKdf(
    rootKey: Uint8Array,
    shared: SecureBuffer,
): Promise<{ rootKey: Uint8Array; chainKey: Uint8Array }> {
    const derived = await shared.useAsync((bytes) =>
        deriveHkdfSha256Bits(bytes, {
            info: ROOT_KDF_INFO,
            salt: rootKey,
            lengthBits: RATCHET_KEY_LENGTH * 2 * 8,
        }),
    );
    const [nextRootKey, chainKey] = split(derived, RATCHET_KEY_LENGTH);
    return { rootKey: nextRootKey, chainKey };
}

/**
 * Symmetric ratchet step: `HKDF(ikm = chainKey)` → next chain key and the
 * single-use message key for the current position.
 */
async function chainKdf(
    chainKey: Uint8Array,
): Promise<{ chainKey: Uint8Array; messageKey: Uint8Array }> {
    const derived = await deriveHkdfSha256Bits(chainKey, {
        info: CHAIN_KDF_INFO,
        salt: ZERO_SALT,
        lengthBits: RATCHET_KEY_LENGTH * 2 * 8,
    });
    const [nextChainKey, messageKey] = split(derived, RATCHET_KEY_LENGTH);
    return { chainKey: nextChainKey, messageKey };
}

/**
 * Expands a message key into `aesKey(32) || nonce(12)`.
 *
 * The nonce is derived, not random: every message key is used exactly once by
 * construction, so a deterministic nonce is strictly safer than a random one
 * here (no birthday collision) and needs no room on the wire.
 */
async function expandMessageKey(messageKeyBytes: Uint8Array): Promise<SecureBuffer> {
    const messageKey = SecureBuffer.fromBytes(messageKeyBytes);
    try {
        const derived = await messageKey.useAsync((bytes) =>
            deriveHkdfSha256Bits(bytes, {
                info: MESSAGE_KDF_INFO,
                salt: ZERO_SALT,
                lengthBits: MESSAGE_MATERIAL_BYTES * 8,
            }),
        );
        try {
            return SecureBuffer.fromBytes(derived);
        } finally {
            derived.fill(0);
        }
    } finally {
        messageKey.destroy();
    }
}

// ---------------------------------------------------------------------------
// Header canonicalisation & AAD
// ---------------------------------------------------------------------------

/**
 * Canonical header bytes for the AAD.
 *
 * The object literal is rebuilt field by field so the key order is fixed by
 * this source file, never by the order in which a peer happened to serialise
 * its JSON. Otherwise a reordered — but semantically identical — header would
 * produce a different AAD and break interop, and an attacker could probe which
 * orderings verify.
 */
function canonicalHeaderBytes(header: RatchetHeader): Uint8Array {
    return utf8ToBytes(
        JSON.stringify({ v: header.v, dh: header.dh, pn: header.pn, n: header.n }),
    );
}

/**
 * `"sv-dr-msg-v1" || 0x00 || associatedData || 0x00 || canonicalHeader`.
 *
 * Binding the full header means any change to the ratchet public key or to
 * either counter fails the GCM tag check.
 */
function buildAad(header: RatchetHeader, associatedData: Uint8Array | null): Uint8Array {
    return concatBytes(
        MESSAGE_KDF_INFO,
        AAD_SEPARATOR,
        associatedData ?? EMPTY_BYTES,
        AAD_SEPARATOR,
        canonicalHeaderBytes(header),
    );
}

// ---------------------------------------------------------------------------
// Message sealing / opening
// ---------------------------------------------------------------------------

/** Seals `plaintext` under a single-use message key. Caller wipes `messageKeyBytes`. */
async function sealMessage(
    messageKeyBytes: Uint8Array,
    plaintext: Uint8Array,
    header: RatchetHeader,
    associatedData: Uint8Array | null,
): Promise<string> {
    const material = await expandMessageKey(messageKeyBytes);
    const aad = buildAad(header, associatedData);
    try {
        const ciphertext = await material.useAsync((bytes) =>
            aesGcmEncrypt(
                bytes.subarray(0, AES_KEY_BYTES),
                bytes.subarray(AES_KEY_BYTES, MESSAGE_MATERIAL_BYTES),
                plaintext,
                aad,
            ),
        );
        return bytesToBase64(ciphertext);
    } finally {
        material.destroy();
        aad.fill(0);
    }
}

/**
 * Opens a message under a candidate message key. Any failure — wrong key,
 * tampered header, tampered ciphertext, malformed base64 — collapses to
 * {@link DisDecryptionError}, so no decryption oracle exists.
 */
async function openMessage(
    messageKeyBytes: Uint8Array,
    message: RatchetMessage,
    associatedData: Uint8Array | null,
): Promise<Uint8Array> {
    let ciphertext: Uint8Array;
    try {
        ciphertext = base64ToBytes(message.ciphertext);
    } catch {
        throw new DisDecryptionError();
    }
    const material = await expandMessageKey(messageKeyBytes);
    const aad = buildAad(message.header, associatedData);
    try {
        return await material.useAsync((bytes) =>
            aesGcmDecrypt(
                bytes.subarray(0, AES_KEY_BYTES),
                bytes.subarray(AES_KEY_BYTES, MESSAGE_MATERIAL_BYTES),
                ciphertext,
                aad,
            ),
        );
    } finally {
        material.destroy();
        aad.fill(0);
        ciphertext.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

function isNonNegativeInt(value: unknown): value is number {
    return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function requireBytes(value: unknown, expectedLength: number, field: string): Uint8Array {
    if (!(value instanceof Uint8Array) || value.length !== expectedLength) {
        throw new DisInvalidArgumentError(`${field} must be ${expectedLength} bytes`);
    }
    return new Uint8Array(value);
}

function normaliseMaxSkippedKeys(value: number | undefined): number {
    if (value === undefined) return DEFAULT_MAX_SKIPPED_KEYS;
    if (!Number.isSafeInteger(value) || value < 1) {
        throw new DisInvalidArgumentError('maxSkippedKeys must be a positive integer');
    }
    return value;
}

function requireKeyPair(pair: RatchetDhKeyPair | undefined, field: string): RatchetDhKeyPair {
    if (!pair || typeof pair !== 'object') {
        throw new DisInvalidArgumentError(`${field} is required`);
    }
    if (pair.algorithm !== 'ECDH-P-256') {
        throw new DisInvalidArgumentError(`${field}.algorithm must be ECDH-P-256`);
    }
    return {
        algorithm: 'ECDH-P-256',
        publicKey: requireBytes(pair.publicKey, DH_PUBLIC_KEY_LENGTH, `${field}.publicKey`),
        privateKey: requireBytes(pair.privateKey, DH_PRIVATE_KEY_LENGTH, `${field}.privateKey`),
    };
}

/** Cheap structural guard so callers get a clear error instead of a crypto failure. */
function assertRatchetState(state: RatchetState): void {
    if (!state || typeof state !== 'object' || state.version !== 1) {
        throw new DisInvalidArgumentError('Invalid ratchet state');
    }
    if (!(state.rootKey instanceof Uint8Array) || state.rootKey.length !== RATCHET_KEY_LENGTH) {
        throw new DisInvalidArgumentError('Invalid ratchet state');
    }
    if (!state.dhSelf || state.dhSelf.algorithm !== 'ECDH-P-256') {
        throw new DisInvalidArgumentError('Invalid ratchet state');
    }
}

interface ValidatedHeader {
    readonly dh: string;
    readonly dhBytes: Uint8Array;
    readonly pn: number;
    readonly n: number;
}

/**
 * Structurally validates an inbound message. Everything here is
 * attacker-controlled, so every rejection is a {@link DisDecryptionError} —
 * indistinguishable from a failed tag check.
 */
function validateMessage(message: RatchetMessage): ValidatedHeader {
    if (!message || typeof message !== 'object' || typeof message.ciphertext !== 'string') {
        throw new DisDecryptionError();
    }
    const header = message.header;
    if (!header || typeof header !== 'object' || header.v !== RATCHET_MESSAGE_V1_TAG) {
        throw new DisDecryptionError();
    }
    if (typeof header.dh !== 'string' || !isNonNegativeInt(header.pn) || !isNonNegativeInt(header.n)) {
        throw new DisDecryptionError();
    }
    let dhBytes: Uint8Array;
    try {
        dhBytes = base64ToBytes(header.dh);
    } catch {
        throw new DisDecryptionError();
    }
    if (dhBytes.length !== DH_PUBLIC_KEY_LENGTH) {
        throw new DisDecryptionError();
    }
    return { dh: header.dh, dhBytes, pn: header.pn, n: header.n };
}

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------

/**
 * Initialises the party that sends first (Alice).
 *
 * She already holds the peer's published ratchet public key, so she generates
 * her own pair and performs the first DH ratchet immediately — her sending
 * chain is ready before the peer has said anything.
 */
export async function initSenderState(input: InitSenderStateInput): Promise<RatchetState> {
    if (!input || typeof input !== 'object') {
        throw new DisInvalidArgumentError('initSenderState input is required');
    }
    const sharedSecret = requireBytes(input.sharedSecret, RATCHET_KEY_LENGTH, 'sharedSecret');
    const remotePublicKey = requireBytes(
        input.remotePublicKey,
        DH_PUBLIC_KEY_LENGTH,
        'remotePublicKey',
    );
    const maxSkippedKeys = normaliseMaxSkippedKeys(input.maxSkippedKeys);
    const dhSelf = await generateRatchetKeyPair();

    let shared: SecureBuffer | null = null;
    try {
        try {
            shared = await ecdhShared(dhSelf.privateKey, remotePublicKey);
        } catch {
            throw new DisInvalidArgumentError('remotePublicKey is not a valid P-256 public key');
        }
        const derived = await rootKdf(sharedSecret, shared);
        return {
            version: 1,
            dhSelf,
            dhRemote: remotePublicKey,
            rootKey: derived.rootKey,
            sendingChainKey: derived.chainKey,
            receivingChainKey: null,
            sendCount: 0,
            receiveCount: 0,
            previousSendCount: 0,
            skippedMessageKeys: [],
            maxSkippedKeys,
            associatedData:
                input.associatedData === undefined ? null : new Uint8Array(input.associatedData),
        };
    } finally {
        shared?.destroy();
        sharedSecret.fill(0);
    }
}

/**
 * Initialises the party whose ratchet key was published (Bob).
 *
 * He has no chains yet: the shared secret is his root key, and his first DH
 * ratchet happens when the first message arrives. He therefore cannot send
 * until he has received.
 */
export async function initReceiverState(input: InitReceiverStateInput): Promise<RatchetState> {
    if (!input || typeof input !== 'object') {
        throw new DisInvalidArgumentError('initReceiverState input is required');
    }
    const rootKey = requireBytes(input.sharedSecret, RATCHET_KEY_LENGTH, 'sharedSecret');
    const dhSelf = requireKeyPair(input.dhKeyPair, 'dhKeyPair');
    const maxSkippedKeys = normaliseMaxSkippedKeys(input.maxSkippedKeys);
    return {
        version: 1,
        dhSelf,
        dhRemote: null,
        rootKey,
        sendingChainKey: null,
        receivingChainKey: null,
        sendCount: 0,
        receiveCount: 0,
        previousSendCount: 0,
        skippedMessageKeys: [],
        maxSkippedKeys,
        associatedData:
            input.associatedData === undefined ? null : new Uint8Array(input.associatedData),
    };
}

// ---------------------------------------------------------------------------
// Skipped-key bookkeeping
// ---------------------------------------------------------------------------

/**
 * Stores a skipped message key, evicting the oldest entry once the budget is
 * exhausted (FIFO). Bounding the store means a peer that announces messages it
 * never delivers cannot exhaust memory; the cost is that very old late
 * messages eventually become undecryptable, which the Double Ratchet spec
 * explicitly allows.
 */
function retainSkippedKey(working: MutableRatchetState, entry: SkippedMessageKey): void {
    while (
        working.skippedMessageKeys.length >= working.maxSkippedKeys &&
        working.skippedMessageKeys.length > 0
    ) {
        const evicted = working.skippedMessageKeys.shift();
        evicted?.messageKey.fill(0);
    }
    working.skippedMessageKeys.push(entry);
}

/**
 * Advances the receiving chain to `until`, retaining a message key for every
 * position passed over.
 *
 * The number of steps is capped at `maxSkippedKeys`. That cap is the CPU half
 * of the DoS defence: FIFO eviction bounds how many keys are *stored*, but
 * without this a header claiming `n = 2^31` would still force two billion HKDF
 * invocations. The refusal is a {@link DisDecryptionError} rather than a
 * distinct error type so that "counter nudged by one" and "counter absurd" are
 * not distinguishable from the outside.
 */
async function skipMessageKeys(
    working: MutableRatchetState,
    chainDh: string,
    until: number,
): Promise<void> {
    if (until <= working.receiveCount) {
        return;
    }
    if (working.receivingChainKey === null) {
        // Nothing has ever been received on this chain, so there is no key
        // material to skip forward with.
        throw new DisDecryptionError();
    }
    if (until - working.receiveCount > working.maxSkippedKeys) {
        throw new DisDecryptionError();
    }

    let chainKey = working.receivingChainKey;
    while (working.receiveCount < until) {
        const stepped = await chainKdf(chainKey);
        chainKey.fill(0);
        chainKey = stepped.chainKey;
        retainSkippedKey(working, {
            dh: chainDh,
            n: working.receiveCount,
            messageKey: stepped.messageKey,
        });
        working.receiveCount += 1;
    }
    working.receivingChainKey = chainKey;
}

/**
 * Performs a DH ratchet step against the peer's new public key: derives the
 * receiving chain from the current key pair, then generates a fresh pair and
 * derives the new sending chain from it.
 */
async function dhRatchet(
    working: MutableRatchetState,
    remotePublicKey: Uint8Array,
): Promise<void> {
    working.previousSendCount = working.sendCount;
    working.sendCount = 0;
    working.receiveCount = 0;
    working.dhRemote = new Uint8Array(remotePublicKey);

    const receivingShared = await ecdhShared(working.dhSelf.privateKey, remotePublicKey);
    try {
        const derived = await rootKdf(working.rootKey, receivingShared);
        working.rootKey.fill(0);
        working.rootKey = derived.rootKey;
        working.receivingChainKey?.fill(0);
        working.receivingChainKey = derived.chainKey;
    } finally {
        receivingShared.destroy();
    }

    const nextPair = await generateRatchetKeyPair();
    zeroBuffers(working.dhSelf.privateKey, working.dhSelf.publicKey);
    working.dhSelf = nextPair;

    const sendingShared = await ecdhShared(nextPair.privateKey, remotePublicKey);
    try {
        const derived = await rootKdf(working.rootKey, sendingShared);
        working.rootKey.fill(0);
        working.rootKey = derived.rootKey;
        working.sendingChainKey?.fill(0);
        working.sendingChainKey = derived.chainKey;
    } finally {
        sendingShared.destroy();
    }
}

// ---------------------------------------------------------------------------
// Public ratchet operations
// ---------------------------------------------------------------------------

/**
 * Encrypts one message, advancing the sending chain.
 *
 * Returns a fresh state; `state` itself is left untouched. Throws
 * {@link DisInvalidArgumentError} if this party has no sending chain yet — the
 * receiving side must decrypt its first inbound message before it can reply.
 */
export async function encryptMessage(
    state: RatchetState,
    plaintext: Uint8Array,
): Promise<EncryptMessageResult> {
    assertRatchetState(state);
    if (!(plaintext instanceof Uint8Array)) {
        throw new DisInvalidArgumentError('plaintext must be a Uint8Array');
    }
    if (state.sendingChainKey === null) {
        throw new DisInvalidArgumentError(
            'Ratchet has no sending chain yet; decrypt an inbound message first',
        );
    }

    const stepped = await chainKdf(state.sendingChainKey);
    try {
        const header: RatchetHeader = {
            v: RATCHET_MESSAGE_V1_TAG,
            dh: bytesToBase64(state.dhSelf.publicKey),
            pn: state.previousSendCount,
            n: state.sendCount,
        };
        const ciphertext = await sealMessage(
            stepped.messageKey,
            plaintext,
            header,
            state.associatedData,
        );

        const nextState = cloneState(state);
        nextState.sendingChainKey?.fill(0);
        nextState.sendingChainKey = stepped.chainKey;
        nextState.sendCount = state.sendCount + 1;
        return { nextState, message: { header, ciphertext } };
    } catch (error) {
        stepped.chainKey.fill(0);
        throw error;
    } finally {
        stepped.messageKey.fill(0);
    }
}

/**
 * Decrypts one message, advancing (or ratcheting) the receiving side.
 *
 * All work happens on a private clone which is only returned once the GCM tag
 * has verified — a forged or replayed message leaves `state` byte-for-byte
 * unchanged, so it can neither advance the ratchet nor wedge the session.
 * Every failure mode collapses to {@link DisDecryptionError}.
 */
export async function decryptMessage(
    state: RatchetState,
    message: RatchetMessage,
): Promise<DecryptMessageResult> {
    assertRatchetState(state);
    const header = validateMessage(message);

    // (a) A message key retained earlier for this exact position.
    const skippedIndex = state.skippedMessageKeys.findIndex(
        (entry) => entry.n === header.n && entry.dh === header.dh,
    );
    if (skippedIndex >= 0) {
        const entry = state.skippedMessageKeys[skippedIndex]!;
        const plaintext = await openMessage(entry.messageKey, message, state.associatedData);
        const nextState = cloneState(state);
        const [consumed] = nextState.skippedMessageKeys.splice(skippedIndex, 1);
        // Consumed irrevocably: the key exists in neither the returned state
        // nor any future one, so a replay finds nothing to open it with.
        consumed?.messageKey.fill(0);
        return { nextState, plaintext };
    }

    const currentRemote = state.dhRemote === null ? null : bytesToBase64(state.dhRemote);

    // (b) Replay of a position already consumed on the live receiving chain.
    if (currentRemote === header.dh && header.n < state.receiveCount) {
        throw new DisDecryptionError();
    }

    const working = cloneState(state);
    let committed = false;
    try {
        if (currentRemote !== header.dh) {
            await assertValidRemotePublicKey(header.dhBytes);
            if (currentRemote !== null) {
                await skipMessageKeys(working, currentRemote, header.pn);
            } else if (header.pn !== 0) {
                // First ever inbound message cannot claim a previous chain.
                throw new DisDecryptionError();
            }
            await dhRatchet(working, header.dhBytes);
        }
        await skipMessageKeys(working, header.dh, header.n);

        const receivingChainKey = working.receivingChainKey;
        if (receivingChainKey === null) {
            throw new DisDecryptionError();
        }
        const stepped = await chainKdf(receivingChainKey);
        try {
            const plaintext = await openMessage(
                stepped.messageKey,
                message,
                working.associatedData,
            );
            receivingChainKey.fill(0);
            working.receivingChainKey = stepped.chainKey;
            working.receiveCount += 1;
            committed = true;
            return { nextState: working, plaintext };
        } catch (error) {
            stepped.chainKey.fill(0);
            throw error;
        } finally {
            stepped.messageKey.fill(0);
        }
    } finally {
        if (!committed) {
            destroyRatchetState(working);
        }
    }
}

/**
 * Zeroes every secret a state holds. Call this on a state that has been
 * replaced by a `nextState`, once the replacement is safely persisted —
 * keeping the old one alive keeps its chain keys alive, which is exactly the
 * forward secrecy the ratchet exists to provide.
 *
 * Idempotent and safe on an already-destroyed state.
 */
export function destroyRatchetState(state: RatchetState): void {
    if (!state || typeof state !== 'object') {
        return;
    }
    zeroBuffers(
        state.rootKey,
        state.sendingChainKey,
        state.receivingChainKey,
        state.dhSelf?.privateKey,
        state.dhSelf?.publicKey,
        state.dhRemote,
        state.associatedData,
    );
    for (const entry of state.skippedMessageKeys ?? []) {
        entry.messageKey?.fill(0);
    }
}

// ---------------------------------------------------------------------------
// Serialisation
//
// State and message both carry an explicit version prefix. Binary fields are
// base64; the surrounding JSON is left readable so a persisted session can be
// inspected without a decoder.
// ---------------------------------------------------------------------------

interface SerializedSkippedKey {
    readonly dh: string;
    readonly n: number;
    readonly messageKey: string;
}

interface SerializedState {
    readonly version: 1;
    readonly dhSelf: {
        readonly algorithm: string;
        readonly publicKey: string;
        readonly privateKey: string;
    };
    readonly dhRemote: string | null;
    readonly rootKey: string;
    readonly sendingChainKey: string | null;
    readonly receivingChainKey: string | null;
    readonly sendCount: number;
    readonly receiveCount: number;
    readonly previousSendCount: number;
    readonly skippedMessageKeys: readonly SerializedSkippedKey[];
    readonly maxSkippedKeys: number;
    readonly associatedData: string | null;
}

function encodeOptional(bytes: Uint8Array | null): string | null {
    return bytes === null ? null : bytesToBase64(bytes);
}

/** Serialises a state to `sv-dr-state-v1:` + JSON with base64 binary fields. */
export function serializeRatchetState(state: RatchetState): string {
    assertRatchetState(state);
    const body: SerializedState = {
        version: 1,
        dhSelf: {
            algorithm: state.dhSelf.algorithm,
            publicKey: bytesToBase64(state.dhSelf.publicKey),
            privateKey: bytesToBase64(state.dhSelf.privateKey),
        },
        dhRemote: encodeOptional(state.dhRemote),
        rootKey: bytesToBase64(state.rootKey),
        sendingChainKey: encodeOptional(state.sendingChainKey),
        receivingChainKey: encodeOptional(state.receivingChainKey),
        sendCount: state.sendCount,
        receiveCount: state.receiveCount,
        previousSendCount: state.previousSendCount,
        skippedMessageKeys: state.skippedMessageKeys.map((entry) => ({
            dh: entry.dh,
            n: entry.n,
            messageKey: bytesToBase64(entry.messageKey),
        })),
        maxSkippedKeys: state.maxSkippedKeys,
        associatedData: encodeOptional(state.associatedData),
    };
    return formatEnvelope(STATE_ENVELOPE_SPEC, JSON.stringify(body));
}

function decodeBase64(value: unknown, field: string): Uint8Array {
    if (typeof value !== 'string') {
        throw new DisInvalidArgumentError(`${field} must be a base64 string`);
    }
    try {
        return base64ToBytes(value);
    } catch {
        throw new DisInvalidArgumentError(`${field} is not valid base64`);
    }
}

function decodeFixed(value: unknown, expectedLength: number, field: string): Uint8Array {
    const bytes = decodeBase64(value, field);
    if (bytes.length !== expectedLength) {
        bytes.fill(0);
        throw new DisInvalidArgumentError(`${field} must decode to ${expectedLength} bytes`);
    }
    return bytes;
}

function decodeOptionalFixed(
    value: unknown,
    expectedLength: number,
    field: string,
): Uint8Array | null {
    return value === null || value === undefined ? null : decodeFixed(value, expectedLength, field);
}

function decodeCount(value: unknown, field: string): number {
    if (!isNonNegativeInt(value)) {
        throw new DisInvalidArgumentError(`${field} must be a non-negative integer`);
    }
    return value;
}

/**
 * Parses a serialised state.
 *
 * Fails closed on anything unexpected: a future in-family version raises
 * {@link DisUnsupportedFormatVersionError} via `parseEnvelope`, a foreign
 * payload or any structurally invalid field raises
 * {@link DisInvalidArgumentError}. Byte lengths are checked so a malformed
 * state can never reach a crypto primitive.
 */
export function deserializeRatchetState(json: string): RatchetState {
    if (typeof json !== 'string' || json.length === 0) {
        throw new DisInvalidArgumentError('Ratchet state must be a non-empty string');
    }
    const envelope = parseEnvelope(STATE_ENVELOPE_SPEC, json);
    if (envelope.version !== 1) {
        throw new DisInvalidArgumentError('Unrecognised ratchet state envelope');
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(envelope.payload);
    } catch {
        throw new DisInvalidArgumentError('Malformed ratchet state JSON');
    }
    if (!parsed || typeof parsed !== 'object') {
        throw new DisInvalidArgumentError('Malformed ratchet state JSON');
    }

    const body = parsed as Partial<SerializedState>;
    if (body.version !== 1) {
        throw new DisInvalidArgumentError('Unsupported ratchet state version');
    }
    const dhSelf = body.dhSelf;
    if (!dhSelf || typeof dhSelf !== 'object' || dhSelf.algorithm !== 'ECDH-P-256') {
        throw new DisInvalidArgumentError('Unsupported ratchet DH algorithm');
    }
    if (!Array.isArray(body.skippedMessageKeys)) {
        throw new DisInvalidArgumentError('skippedMessageKeys must be an array');
    }
    const maxSkippedKeys = normaliseMaxSkippedKeys(body.maxSkippedKeys);
    if (body.skippedMessageKeys.length > maxSkippedKeys) {
        throw new DisInvalidArgumentError('skippedMessageKeys exceeds maxSkippedKeys');
    }

    const skippedMessageKeys: SkippedMessageKey[] = body.skippedMessageKeys.map((entry, index) => {
        if (!entry || typeof entry !== 'object' || typeof entry.dh !== 'string') {
            throw new DisInvalidArgumentError(`skippedMessageKeys[${index}] is malformed`);
        }
        return {
            dh: entry.dh,
            n: decodeCount(entry.n, `skippedMessageKeys[${index}].n`),
            messageKey: decodeFixed(
                entry.messageKey,
                RATCHET_KEY_LENGTH,
                `skippedMessageKeys[${index}].messageKey`,
            ),
        };
    });

    return {
        version: 1,
        dhSelf: {
            algorithm: 'ECDH-P-256',
            publicKey: decodeFixed(dhSelf.publicKey, DH_PUBLIC_KEY_LENGTH, 'dhSelf.publicKey'),
            privateKey: decodeFixed(dhSelf.privateKey, DH_PRIVATE_KEY_LENGTH, 'dhSelf.privateKey'),
        },
        dhRemote: decodeOptionalFixed(body.dhRemote, DH_PUBLIC_KEY_LENGTH, 'dhRemote'),
        rootKey: decodeFixed(body.rootKey, RATCHET_KEY_LENGTH, 'rootKey'),
        sendingChainKey: decodeOptionalFixed(
            body.sendingChainKey,
            RATCHET_KEY_LENGTH,
            'sendingChainKey',
        ),
        receivingChainKey: decodeOptionalFixed(
            body.receivingChainKey,
            RATCHET_KEY_LENGTH,
            'receivingChainKey',
        ),
        sendCount: decodeCount(body.sendCount, 'sendCount'),
        receiveCount: decodeCount(body.receiveCount, 'receiveCount'),
        previousSendCount: decodeCount(body.previousSendCount, 'previousSendCount'),
        skippedMessageKeys,
        maxSkippedKeys,
        associatedData:
            body.associatedData === null || body.associatedData === undefined
                ? null
                : decodeBase64(body.associatedData, 'associatedData'),
    };
}

/** Serialises a message to `sv-dr-msg-v1:` + JSON for transport. */
export function serializeRatchetMessage(message: RatchetMessage): string {
    if (!message || typeof message !== 'object' || typeof message.ciphertext !== 'string') {
        throw new DisInvalidArgumentError('Invalid ratchet message');
    }
    const header = message.header;
    if (
        !header ||
        header.v !== RATCHET_MESSAGE_V1_TAG ||
        typeof header.dh !== 'string' ||
        !isNonNegativeInt(header.pn) ||
        !isNonNegativeInt(header.n)
    ) {
        throw new DisInvalidArgumentError('Invalid ratchet message header');
    }
    return formatEnvelope(
        MESSAGE_ENVELOPE_SPEC,
        JSON.stringify({
            header: { v: header.v, dh: header.dh, pn: header.pn, n: header.n },
            ciphertext: message.ciphertext,
        }),
    );
}

/**
 * Parses a transported message. This only restores structure — authenticity is
 * decided by {@link decryptMessage}, which is the single place that can tell a
 * genuine message from a forged one.
 */
export function deserializeRatchetMessage(wire: string): RatchetMessage {
    if (typeof wire !== 'string' || wire.length === 0) {
        throw new DisInvalidArgumentError('Ratchet message must be a non-empty string');
    }
    const envelope = parseEnvelope(MESSAGE_ENVELOPE_SPEC, wire);
    if (envelope.version !== 1) {
        throw new DisInvalidArgumentError('Unrecognised ratchet message envelope');
    }
    let parsed: unknown;
    try {
        parsed = JSON.parse(envelope.payload);
    } catch {
        throw new DisInvalidArgumentError('Malformed ratchet message JSON');
    }
    if (!parsed || typeof parsed !== 'object') {
        throw new DisInvalidArgumentError('Malformed ratchet message JSON');
    }
    const body = parsed as Partial<RatchetMessage>;
    const header = body.header;
    if (
        !header ||
        typeof header !== 'object' ||
        header.v !== RATCHET_MESSAGE_V1_TAG ||
        typeof header.dh !== 'string' ||
        !isNonNegativeInt(header.pn) ||
        !isNonNegativeInt(header.n) ||
        typeof body.ciphertext !== 'string'
    ) {
        throw new DisInvalidArgumentError('Malformed ratchet message');
    }
    return {
        header: { v: RATCHET_MESSAGE_V1_TAG, dh: header.dh, pn: header.pn, n: header.n },
        ciphertext: body.ciphertext,
    };
}
