/**
 * dis-messaging — Signal Double Ratchet (ECDH P-256 + HKDF-SHA-256 + AES-256-GCM).
 *
 * Forward secrecy and post-compromise security for a message stream, exposed
 * as a pure, fully serialisable state machine. DIS performs no storage or
 * transport: the caller owns the state, persists it, and destroys the version
 * it replaces.
 *
 * The initial shared secret comes from a handshake (e.g. X3DH) that is
 * deliberately outside this module's scope.
 */

export {
    generateRatchetKeyPair,
    initSenderState,
    initReceiverState,
    encryptMessage,
    decryptMessage,
    destroyRatchetState,
    serializeRatchetState,
    deserializeRatchetState,
    serializeRatchetMessage,
    deserializeRatchetMessage,
    RATCHET_MESSAGE_V1_PREFIX,
    RATCHET_STATE_V1_PREFIX,
    DEFAULT_MAX_SKIPPED_KEYS,
} from './ratchet.js';

export type {
    RatchetState,
    RatchetMessage,
    RatchetHeader,
    RatchetDhKeyPair,
    RatchetDhAlgorithm,
    SkippedMessageKey,
    EncryptMessageResult,
    DecryptMessageResult,
    InitSenderStateInput,
    InitReceiverStateInput,
} from './types.js';
