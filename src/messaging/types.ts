/**
 * dis-messaging — types for the Signal Double Ratchet state machine.
 *
 * Every type here is a plain, JSON-representable data holder. The ratchet is a
 * pure state transition: the caller owns the state, persists it, and decides
 * when to destroy it. Nothing in this module reads or writes storage.
 *
 * Binary fields are `Uint8Array` in memory and base64 on the wire (see
 * `serializeRatchetState`). Key material held here is long-lived and therefore
 * caller-owned — the same convention as `deriveRawKey`, which documents that
 * the caller must wipe the buffer it receives. Use `destroyRatchetState()` on
 * a state that has been superseded.
 */

/** Wire prefix of a serialised {@link RatchetMessage}. Format-frozen. */
export const RATCHET_MESSAGE_V1_PREFIX = 'sv-dr-msg-v1:';

/** Wire prefix of a serialised {@link RatchetState}. Format-frozen. */
export const RATCHET_STATE_V1_PREFIX = 'sv-dr-state-v1:';

/** Version tag carried inside every message header. Format-frozen. */
export const RATCHET_MESSAGE_V1_TAG = 'sv-dr-msg-v1';

/**
 * Default cap on retained skipped message keys. Bounds memory against a peer
 * that never delivers the messages it announces, and (reused as a per-step
 * bound) bounds CPU against a header claiming an absurd message number.
 */
export const DEFAULT_MAX_SKIPPED_KEYS = 1000;

/** Raw byte length of an uncompressed ECDH P-256 public key. */
export const DH_PUBLIC_KEY_LENGTH = 65;

/** Raw byte length of a PKCS#8-encoded ECDH P-256 private key. */
export const DH_PRIVATE_KEY_LENGTH = 138;

/** Byte length of every chain/root/message key in the ratchet. */
export const RATCHET_KEY_LENGTH = 32;

/**
 * The DH algorithm a state was created with.
 *
 * Only `ECDH-P-256` exists in v1. It is recorded in the state so a future
 * `sv-dr-state-v2` can introduce X25519 without ambiguity, and so a v1 state
 * can never be silently reinterpreted under a different curve.
 */
export type RatchetDhAlgorithm = 'ECDH-P-256';

/** A ratchet DH key pair, serialised in the exact form the state stores. */
export interface RatchetDhKeyPair {
    readonly algorithm: RatchetDhAlgorithm;
    /** Raw (uncompressed point) public key — {@link DH_PUBLIC_KEY_LENGTH} bytes. */
    readonly publicKey: Uint8Array;
    /** PKCS#8 private key — {@link DH_PRIVATE_KEY_LENGTH} bytes. Secret. */
    readonly privateKey: Uint8Array;
}

/**
 * Public, authenticated message header.
 *
 * Every field is bound into the AEAD's associated data, so tampering with any
 * of them makes decryption fail with {@link DisDecryptionError}.
 */
export interface RatchetHeader {
    readonly v: typeof RATCHET_MESSAGE_V1_TAG;
    /** base64 of the sender's current ratchet public key (raw, 65 bytes). */
    readonly dh: string;
    /** Number of messages in the sender's previous sending chain. */
    readonly pn: number;
    /** Message number within the sender's current sending chain. */
    readonly n: number;
}

/** One sealed message: authenticated header plus base64 `ciphertext || tag`. */
export interface RatchetMessage {
    readonly header: RatchetHeader;
    /**
     * base64 of `ciphertext || authTag`. There is no IV prefix — the nonce is
     * derived deterministically from the single-use message key.
     */
    readonly ciphertext: string;
}

/**
 * A message key retained for a message that was announced but not yet
 * delivered. Consuming it removes it from the state irrevocably.
 */
export interface SkippedMessageKey {
    /** base64 public key identifying the chain this key belongs to. */
    readonly dh: string;
    /** Message number within that chain. */
    readonly n: number;
    /** The message key — {@link RATCHET_KEY_LENGTH} bytes. Secret. */
    readonly messageKey: Uint8Array;
}

/**
 * The complete Double Ratchet session state.
 *
 * Fully serialisable and never mutated by `encryptMessage`/`decryptMessage` —
 * both return a fresh `nextState` and leave their input untouched. Persist the
 * returned state, then call `destroyRatchetState()` on the one it replaced.
 */
export interface RatchetState {
    readonly version: 1;
    /** This party's current ratchet key pair (DHs). */
    readonly dhSelf: RatchetDhKeyPair;
    /** The peer's current ratchet public key (DHr); `null` until first receive. */
    readonly dhRemote: Uint8Array | null;
    /** Root key (RK) — {@link RATCHET_KEY_LENGTH} bytes. Secret. */
    readonly rootKey: Uint8Array;
    /** Sending chain key (CKs); `null` before the first DH ratchet. Secret. */
    readonly sendingChainKey: Uint8Array | null;
    /** Receiving chain key (CKr); `null` before the first DH ratchet. Secret. */
    readonly receivingChainKey: Uint8Array | null;
    /** Messages sent in the current sending chain (Ns). */
    readonly sendCount: number;
    /** Messages received in the current receiving chain (Nr). */
    readonly receiveCount: number;
    /** Length of the previous sending chain (PN). */
    readonly previousSendCount: number;
    /** Retained out-of-order message keys, oldest first (FIFO eviction). */
    readonly skippedMessageKeys: readonly SkippedMessageKey[];
    /** Cap on retained skipped keys, and on skips performed per step. */
    readonly maxSkippedKeys: number;
    /**
     * Optional session binding mixed into every message's AAD — e.g. the
     * identity material from an X3DH handshake. Establishing it is out of
     * scope for DIS; it is treated here as opaque bytes.
     */
    readonly associatedData: Uint8Array | null;
}

/** Result of {@link encryptMessage}. */
export interface EncryptMessageResult {
    readonly nextState: RatchetState;
    readonly message: RatchetMessage;
}

/** Result of {@link decryptMessage}. The plaintext is secret — wipe it. */
export interface DecryptMessageResult {
    readonly nextState: RatchetState;
    readonly plaintext: Uint8Array;
}

/** Input for {@link initSenderState} (the party that speaks first). */
export interface InitSenderStateInput {
    /** Shared secret from the handshake — {@link RATCHET_KEY_LENGTH} bytes. */
    readonly sharedSecret: Uint8Array;
    /** The peer's published ratchet public key (raw, 65 bytes). */
    readonly remotePublicKey: Uint8Array;
    readonly associatedData?: Uint8Array;
    readonly maxSkippedKeys?: number;
}

/** Input for {@link initReceiverState} (the party that published a key pair). */
export interface InitReceiverStateInput {
    /** Shared secret from the handshake — {@link RATCHET_KEY_LENGTH} bytes. */
    readonly sharedSecret: Uint8Array;
    /** The key pair whose public half the sender used. */
    readonly dhKeyPair: RatchetDhKeyPair;
    readonly associatedData?: Uint8Array;
    readonly maxSkippedKeys?: number;
}
