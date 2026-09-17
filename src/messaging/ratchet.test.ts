import { describe, expect, it } from 'vitest';
import {
    decryptMessage,
    deserializeRatchetMessage,
    deserializeRatchetState,
    destroyRatchetState,
    encryptMessage,
    generateRatchetKeyPair,
    initReceiverState,
    initSenderState,
    serializeRatchetMessage,
    serializeRatchetState,
} from './index.js';
import type { RatchetMessage, RatchetState } from './index.js';
import {
    base64ToBytes,
    bytesToBase64,
    bytesToUtf8,
    utf8ToBytes,
} from '../core/encoding.js';
import {
    DisDecryptionError,
    DisInvalidArgumentError,
    DisUnsupportedFormatVersionError,
} from '../core/errors.js';

const text = (value: string): Uint8Array => utf8ToBytes(value);
const read = (bytes: Uint8Array): string => bytesToUtf8(bytes);

/**
 * Stands in for an X3DH handshake, which is deliberately outside this module.
 * The only thing the ratchet needs from a handshake is 32 agreed bytes.
 */
function handshakeSecret(fill = 0x2a): Uint8Array {
    return new Uint8Array(32).fill(fill);
}

async function establishSession(
    maxSkippedKeys?: number,
): Promise<{ alice: RatchetState; bob: RatchetState }> {
    const sharedSecret = handshakeSecret();
    const bobPair = await generateRatchetKeyPair();
    const alice = await initSenderState({
        sharedSecret,
        remotePublicKey: bobPair.publicKey,
        ...(maxSkippedKeys === undefined ? {} : { maxSkippedKeys }),
    });
    const bob = await initReceiverState({
        sharedSecret,
        dhKeyPair: bobPair,
        ...(maxSkippedKeys === undefined ? {} : { maxSkippedKeys }),
    });
    return { alice, bob };
}

/** Flips a byte inside a base64 payload, keeping it structurally valid base64. */
function tamperBase64(value: string): string {
    const bytes = base64ToBytes(value);
    bytes[0] = bytes[0]! ^ 0xff;
    return bytesToBase64(bytes);
}

describe('messaging — Double Ratchet', () => {
    it('round-trips a synchronous ping-pong exchange', async () => {
        let { alice, bob } = await establishSession();

        const a1 = await encryptMessage(alice, text('hallo bob'));
        alice = a1.nextState;
        const b1 = await decryptMessage(bob, a1.message);
        bob = b1.nextState;
        expect(read(b1.plaintext)).toBe('hallo bob');

        // Bob only has a sending chain after his first receive.
        const b2 = await encryptMessage(bob, text('hallo alice'));
        bob = b2.nextState;
        const a2 = await decryptMessage(alice, b2.message);
        alice = a2.nextState;
        expect(read(a2.plaintext)).toBe('hallo alice');

        const a3 = await encryptMessage(alice, text('wie geht es dir'));
        alice = a3.nextState;
        const b3 = await decryptMessage(bob, a3.message);
        bob = b3.nextState;
        expect(read(b3.plaintext)).toBe('wie geht es dir');

        const b4 = await encryptMessage(bob, text('gut, danke'));
        const a4 = await decryptMessage(alice, b4.message);
        expect(read(a4.plaintext)).toBe('gut, danke');

        // Each change of direction really did ratchet the DH key.
        expect(a3.message.header.dh).not.toBe(a1.message.header.dh);
        expect(b4.message.header.dh).not.toBe(b2.message.header.dh);
    });

    it('cannot send before it has received', async () => {
        const { bob } = await establishSession();
        await expect(encryptMessage(bob, text('zu früh'))).rejects.toBeInstanceOf(
            DisInvalidArgumentError,
        );
    });

    it('handles out-of-order delivery (2, 0, 1)', async () => {
        let { alice, bob } = await establishSession();

        const sent: RatchetMessage[] = [];
        for (const body of ['eins', 'zwei', 'drei']) {
            const result = await encryptMessage(alice, text(body));
            alice = result.nextState;
            sent.push(result.message);
        }
        expect(sent.map((m) => m.header.n)).toEqual([0, 1, 2]);

        let received = await decryptMessage(bob, sent[2]!);
        bob = received.nextState;
        expect(read(received.plaintext)).toBe('drei');
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([0, 1]);

        received = await decryptMessage(bob, sent[0]!);
        bob = received.nextState;
        expect(read(received.plaintext)).toBe('eins');
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([1]);

        received = await decryptMessage(bob, sent[1]!);
        bob = received.nextState;
        expect(read(received.plaintext)).toBe('zwei');
        expect(bob.skippedMessageKeys).toHaveLength(0);
    });

    it('carries skipped keys across a change of direction', async () => {
        let { alice, bob } = await establishSession();

        // Alice sends three, only the last arrives.
        const sent: RatchetMessage[] = [];
        for (const body of ['a0', 'a1', 'a2']) {
            const result = await encryptMessage(alice, text(body));
            alice = result.nextState;
            sent.push(result.message);
        }
        let received = await decryptMessage(bob, sent[2]!);
        bob = received.nextState;

        // Bob replies, Alice replies — the ratchet moves on.
        const reply = await encryptMessage(bob, text('b0'));
        bob = reply.nextState;
        alice = (await decryptMessage(alice, reply.message)).nextState;
        const after = await encryptMessage(alice, text('a3'));
        alice = after.nextState;
        bob = (await decryptMessage(bob, after.message)).nextState;

        // The stragglers from the very first chain still open.
        received = await decryptMessage(bob, sent[0]!);
        bob = received.nextState;
        expect(read(received.plaintext)).toBe('a0');
        received = await decryptMessage(bob, sent[1]!);
        expect(read(received.plaintext)).toBe('a1');
    });

    it('rejects a tampered ciphertext', async () => {
        let { alice, bob } = await establishSession();
        const sealed = await encryptMessage(alice, text('vertraulich'));
        alice = sealed.nextState;

        const forged: RatchetMessage = {
            header: sealed.message.header,
            ciphertext: tamperBase64(sealed.message.ciphertext),
        };
        await expect(decryptMessage(bob, forged)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('rejects a tampered header counter', async () => {
        let { alice, bob } = await establishSession();

        // Two messages so that n = 1 is a position the receiver would accept.
        const first = await encryptMessage(alice, text('eins'));
        alice = first.nextState;
        const second = await encryptMessage(alice, text('zwei'));
        alice = second.nextState;

        const bumpedN: RatchetMessage = {
            header: { ...second.message.header, n: 0 },
            ciphertext: second.message.ciphertext,
        };
        await expect(decryptMessage(bob, bumpedN)).rejects.toBeInstanceOf(DisDecryptionError);

        const bumpedPn: RatchetMessage = {
            header: { ...first.message.header, pn: 7 },
            ciphertext: first.message.ciphertext,
        };
        await expect(decryptMessage(bob, bumpedPn)).rejects.toBeInstanceOf(DisDecryptionError);

        const negativeN = {
            header: { ...first.message.header, n: -1 },
            ciphertext: first.message.ciphertext,
        } as unknown as RatchetMessage;
        await expect(decryptMessage(bob, negativeN)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('rejects a tampered ratchet public key', async () => {
        let { alice, bob } = await establishSession();
        const sealed = await encryptMessage(alice, text('geheim'));
        alice = sealed.nextState;

        // A different but perfectly valid curve point.
        const stranger = await generateRatchetKeyPair();
        const swapped: RatchetMessage = {
            header: { ...sealed.message.header, dh: bytesToBase64(stranger.publicKey) },
            ciphertext: sealed.message.ciphertext,
        };
        await expect(decryptMessage(bob, swapped)).rejects.toBeInstanceOf(DisDecryptionError);

        // A point that is not on the curve at all — WebCrypto raises DataError,
        // which must not surface as anything other than DisDecryptionError.
        const offCurve: RatchetMessage = {
            header: { ...sealed.message.header, dh: tamperBase64(sealed.message.header.dh) },
            ciphertext: sealed.message.ciphertext,
        };
        await expect(decryptMessage(bob, offCurve)).rejects.toBeInstanceOf(DisDecryptionError);

        // A structurally wrong key length.
        const truncated: RatchetMessage = {
            header: { ...sealed.message.header, dh: bytesToBase64(new Uint8Array(32)) },
            ciphertext: sealed.message.ciphertext,
        };
        await expect(decryptMessage(bob, truncated)).rejects.toBeInstanceOf(DisDecryptionError);
    });

    it('leaves the receiver state byte-for-byte intact after a forged message', async () => {
        let { alice, bob } = await establishSession();
        const genuine = await encryptMessage(alice, text('echt'));
        alice = genuine.nextState;

        const forged: RatchetMessage = {
            header: genuine.message.header,
            ciphertext: tamperBase64(genuine.message.ciphertext),
        };

        const before = serializeRatchetState(bob);
        await expect(decryptMessage(bob, forged)).rejects.toBeInstanceOf(DisDecryptionError);
        expect(serializeRatchetState(bob)).toBe(before);

        // No ratchet-DoS: the genuine message still opens afterwards.
        const received = await decryptMessage(bob, genuine.message);
        expect(read(received.plaintext)).toBe('echt');
    });

    it('rejects a replayed message and consumes skipped keys irrevocably', async () => {
        let { alice, bob } = await establishSession();

        const first = await encryptMessage(alice, text('eins'));
        alice = first.nextState;
        const second = await encryptMessage(alice, text('zwei'));
        alice = second.nextState;

        // In-order delivery, then replay of the same message.
        const received = await decryptMessage(bob, first.message);
        bob = received.nextState;
        await expect(decryptMessage(bob, first.message)).rejects.toBeInstanceOf(
            DisDecryptionError,
        );

        // Out-of-order delivery leaves a retained key; using it removes it.
        const outOfOrder = await encryptMessage(alice, text('drei'));
        alice = outOfOrder.nextState;
        const jumped = await decryptMessage(bob, outOfOrder.message);
        bob = jumped.nextState;
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([1]);

        const late = await decryptMessage(bob, second.message);
        bob = late.nextState;
        expect(read(late.plaintext)).toBe('zwei');
        expect(bob.skippedMessageKeys).toHaveLength(0);
        await expect(decryptMessage(bob, second.message)).rejects.toBeInstanceOf(
            DisDecryptionError,
        );
    });

    it('evicts the oldest skipped key once the budget is exhausted (FIFO)', async () => {
        let { alice, bob } = await establishSession(3);

        const sent: RatchetMessage[] = [];
        for (let i = 0; i < 6; i += 1) {
            const result = await encryptMessage(alice, text(`m${i}`));
            alice = result.nextState;
            sent.push(result.message);
        }

        // Delivering m3 retains keys for m0..m2 — exactly the budget.
        let received = await decryptMessage(bob, sent[3]!);
        bob = received.nextState;
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([0, 1, 2]);

        // Delivering m5 needs a slot for m4, so m0's key is evicted.
        received = await decryptMessage(bob, sent[5]!);
        bob = received.nextState;
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([1, 2, 4]);

        await expect(decryptMessage(bob, sent[0]!)).rejects.toBeInstanceOf(DisDecryptionError);

        received = await decryptMessage(bob, sent[1]!);
        expect(read(received.plaintext)).toBe('m1');
    });

    it('refuses an absurd message counter without doing the work', async () => {
        let { alice, bob } = await establishSession();
        const sealed = await encryptMessage(alice, text('x'));
        alice = sealed.nextState;

        const flood: RatchetMessage = {
            header: { ...sealed.message.header, n: 2_000_000_000 },
            ciphertext: sealed.message.ciphertext,
        };

        const startedAt = Date.now();
        await expect(decryptMessage(bob, flood)).rejects.toBeInstanceOf(DisDecryptionError);
        // Bounded by maxSkippedKeys, not by the attacker's counter.
        expect(Date.now() - startedAt).toBeLessThan(1000);
    });

    it('binds the session associated data', async () => {
        const sharedSecret = handshakeSecret();
        const bobPair = await generateRatchetKeyPair();
        const alice = await initSenderState({
            sharedSecret,
            remotePublicKey: bobPair.publicKey,
            associatedData: text('session-A'),
        });
        const sealed = await encryptMessage(alice, text('geheim'));

        const wrongSession = await initReceiverState({
            sharedSecret,
            dhKeyPair: bobPair,
            associatedData: text('session-B'),
        });
        await expect(decryptMessage(wrongSession, sealed.message)).rejects.toBeInstanceOf(
            DisDecryptionError,
        );

        const rightSession = await initReceiverState({
            sharedSecret,
            dhKeyPair: bobPair,
            associatedData: text('session-A'),
        });
        const received = await decryptMessage(rightSession, sealed.message);
        expect(read(received.plaintext)).toBe('geheim');
    });

    it('does not wipe the caller-owned handshake secret or public key', async () => {
        const sharedSecret = handshakeSecret();
        const bobPair = await generateRatchetKeyPair();
        await initSenderState({ sharedSecret, remotePublicKey: bobPair.publicKey });
        expect(sharedSecret.every((b) => b === 0x2a)).toBe(true);
        expect(bobPair.publicKey.some((b) => b !== 0)).toBe(true);
    });
});

describe('messaging — serialisation', () => {
    it('survives persistence in the middle of a session', async () => {
        let { alice, bob } = await establishSession();

        const outbound = await encryptMessage(alice, text('vor dem neustart'));
        alice = outbound.nextState;
        bob = (await decryptMessage(bob, outbound.message)).nextState;

        const aliceWire = serializeRatchetState(alice);
        const bobWire = serializeRatchetState(bob);
        expect(aliceWire.startsWith('sv-dr-state-v1:')).toBe(true);
        alice = deserializeRatchetState(aliceWire);
        bob = deserializeRatchetState(bobWire);

        const reply = await encryptMessage(bob, text('nach dem neustart'));
        const received = await decryptMessage(alice, reply.message);
        expect(read(received.plaintext)).toBe('nach dem neustart');
    });

    it('preserves retained skipped keys across persistence', async () => {
        let { alice, bob } = await establishSession();
        const sent: RatchetMessage[] = [];
        for (const body of ['s0', 's1', 's2']) {
            const result = await encryptMessage(alice, text(body));
            alice = result.nextState;
            sent.push(result.message);
        }
        bob = (await decryptMessage(bob, sent[2]!)).nextState;
        expect(bob.skippedMessageKeys).toHaveLength(2);

        bob = deserializeRatchetState(serializeRatchetState(bob));
        expect(bob.skippedMessageKeys.map((e) => e.n)).toEqual([0, 1]);

        const received = await decryptMessage(bob, sent[0]!);
        expect(read(received.plaintext)).toBe('s0');
    });

    it('round-trips a message over the wire format', async () => {
        let { alice, bob } = await establishSession();
        const sealed = await encryptMessage(alice, text('über die leitung'));
        alice = sealed.nextState;

        const wire = serializeRatchetMessage(sealed.message);
        expect(wire.startsWith('sv-dr-msg-v1:')).toBe(true);

        const received = await decryptMessage(bob, deserializeRatchetMessage(wire));
        expect(read(received.plaintext)).toBe('über die leitung');
    });

    it('fails closed on unknown or malformed envelopes', async () => {
        const { alice } = await establishSession();
        const wire = serializeRatchetState(alice);

        expect(() =>
            deserializeRatchetState(wire.replace('sv-dr-state-v1:', 'sv-dr-state-v2:')),
        ).toThrow(DisUnsupportedFormatVersionError);
        expect(() => deserializeRatchetState('sv-vault-v1:fremdes-format')).toThrow(
            DisInvalidArgumentError,
        );
        expect(() => deserializeRatchetState('sv-dr-state-v1:{nicht-json')).toThrow(
            DisInvalidArgumentError,
        );
        // rootKey padded out to the wrong byte length.
        expect(() => deserializeRatchetState(wire.replace('"rootKey":"', '"rootKey":"AAAA'))).toThrow(
            DisInvalidArgumentError,
        );

        const messageWire = serializeRatchetMessage(
            (await encryptMessage(alice, text('x'))).message,
        );
        expect(() =>
            deserializeRatchetMessage(messageWire.replace('sv-dr-msg-v1:', 'sv-dr-msg-v9:')),
        ).toThrow(DisUnsupportedFormatVersionError);
    });
});

describe('messaging — memory hygiene', () => {
    it('destroyRatchetState zeroes every secret it holds', async () => {
        let { alice, bob } = await establishSession();
        const sent: RatchetMessage[] = [];
        for (const body of ['h0', 'h1']) {
            const result = await encryptMessage(alice, text(body));
            alice = result.nextState;
            sent.push(result.message);
        }
        bob = (await decryptMessage(bob, sent[1]!)).nextState;

        const rootKey = bob.rootKey;
        const sendingChainKey = bob.sendingChainKey!;
        const receivingChainKey = bob.receivingChainKey!;
        const privateKey = bob.dhSelf.privateKey;
        const skipped = bob.skippedMessageKeys[0]!.messageKey;

        expect(rootKey.some((b) => b !== 0)).toBe(true);
        expect(skipped.some((b) => b !== 0)).toBe(true);

        destroyRatchetState(bob);

        expect(rootKey.every((b) => b === 0)).toBe(true);
        expect(sendingChainKey.every((b) => b === 0)).toBe(true);
        expect(receivingChainKey.every((b) => b === 0)).toBe(true);
        expect(privateKey.every((b) => b === 0)).toBe(true);
        expect(skipped.every((b) => b === 0)).toBe(true);

        // Idempotent.
        expect(() => destroyRatchetState(bob)).not.toThrow();
    });

    it('does not let a superseded state share buffers with its successor', async () => {
        let { alice, bob } = await establishSession();
        const previous = alice;
        const sealed = await encryptMessage(alice, text('unabhängig'));
        alice = sealed.nextState;

        // Destroying the old state must not damage the new one.
        destroyRatchetState(previous);
        expect(alice.rootKey.some((b) => b !== 0)).toBe(true);

        const received = await decryptMessage(bob, sealed.message);
        expect(read(received.plaintext)).toBe('unabhängig');
    });
});
