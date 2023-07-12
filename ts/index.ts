// Taken from https://github.com/iden3/circomlib/blob/master/src/poseidon.js
import * as assert from 'assert'
const ff = require('ffjavascript')
const Scalar = ff.Scalar
const ZqField = ff.ZqField
const { unstringifyBigInts, leBuff2int } = ff.utils
import { poseidon } from 'circomlib'
const circomlibjs = require('circomlibjs')
const babyJub = circomlibjs.babyJub
const eddsa = circomlibjs.eddsa
const buildPoseidon = circomlibjs.buildPoseidon
import * as crypto from 'crypto'

type PrivKey = BigInt
type PubKey = BigInt[]
type EcdhSharedKey = BigInt[]

const SNARK_FIELD_SIZE = BigInt(
    '0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001'
)

const F = new ZqField(Scalar.fromString(SNARK_FIELD_SIZE.toString()))

const two128 = F.e('340282366920938463463374607431768211456')

const genRandomNonce = (): BigInt => {

    const max = two128
    // Prevent modulo bias
    const lim = F.e('0x10000000000000000000000000000000000000000000000000000000000000000')
    const min = F.mod(F.sub(lim, max), max)

    let rand
    while (true) {
        rand = BigInt('0x' + crypto.randomBytes(32).toString('hex'))

        if (rand >= min) {
            break
        }
    }

    const privKey: PrivKey = F.mod(F.e(rand), max)
    assert(privKey < max)

    return privKey
}

const poseidonEncrypt = async (
    msg: any[],
    sharedKey: EcdhSharedKey,
    nonce: BigInt,
) => {
    msg = msg.map((x) => F.e(x))

    // The nonce must be less than 2 ^ 128
    assert(nonce < two128)

    const message: any[] = [...msg]

    // Pad the message if needed
    while (message.length % 3 > 0) {
        message.push(F.zero)
    }

    let cipherLength = message.length

    // Create the initial state
    let state = [
        F.zero,
        F.e(sharedKey[0]),
        F.e(sharedKey[1]),
        F.add(
            F.e(nonce), 
            F.mul(F.e(msg.length), two128),
        ),
    ]

    const ciphertext: BigInt[] = []
    const poseidonEx = await buildPoseidon()

    for (let i = 0; i < cipherLength / 3; i ++) {
        // Iterate Poseidon on the state
        state = poseidonEx(state.slice(1), state[0], 4).map((x) => poseidonEx.F.toObject(x))
        // Absorb three elements of message
        state[1] = F.add(state[1], BigInt(message[i * 3]))
        state[2] = F.add(state[2], BigInt(message[i * 3 + 1]))
        state[3] = F.add(state[3], BigInt(message[i * 3 + 2]))
        
        // Release three elements of the ciphertext
        ciphertext.push(state[1])
        ciphertext.push(state[2])
        ciphertext.push(state[3])
    }

    // Iterate Poseidon on the state one last time
    state = poseidonEx(state.slice(1), state[0], 4).map((x) => poseidonEx.F.toObject(x))
    // Release the last ciphertext element
    ciphertext.push(state[1])

    return ciphertext
}

const poseidonDecrypt = async (
    ciphertext: BigInt[],
    sharedKey: EcdhSharedKey,
    nonce: BigInt,
    length: number,
) => {
    assert(nonce < two128)

    // Create the initial state
    let state = [
        F.zero,
        F.e(sharedKey[0]),
        F.e(sharedKey[1]),
        F.add(
            F.e(nonce), 
            F.mul(F.e(length), two128),
        ),
    ]

    const message: any[] = []
    const poseidonEx = await buildPoseidon()

    let n = Math.floor(ciphertext.length / 3)

    for (let i = 0; i < n; i ++) {
        // Iterate Poseidon on the state
        state = poseidonEx(state.slice(1), state[0], 4).map((x) => poseidonEx.F.toObject(x))
        
        // Release three elements of the message
        message.push(F.sub(ciphertext[i * 3], state[1]))
        message.push(F.sub(ciphertext[i * 3 + 1], state[2]))
        message.push(F.sub(ciphertext[i * 3 + 2], state[3]))

        // Modify the state
        state[1] = ciphertext[i * 3]
        state[2] = ciphertext[i * 3 + 1]
        state[3] = ciphertext[i * 3 + 2]
    }

    // If length > 3, check if the last (3 - (l mod 3)) elements of the message
    // are 0
    if (length > 3) {
        if (length % 3 === 2) {
            assert(F.eq(message[message.length - 1], F.zero))
        } else if (length % 3 === 1) {
            assert(F.eq(message[message.length - 1], F.zero))
            assert(F.eq(message[message.length - 2], F.zero))
        }
    }

    // Iterate Poseidon on the state one last time
    state = poseidonEx(state.slice(1), state[0], 4).map((x) => poseidonEx.F.toObject(x))
    
    // Check the last ciphertext element
    assert(F.eq(ciphertext[ciphertext.length - 1], state[1]))

    return message.slice(0, length)
}

// Hash up to 2 elements
const poseidonT3 = (inputs: BigInt[]) => {
    assert(inputs.length === 2)
    return poseidon(inputs)
}

/*
 * Hash a single BigInt with the Poseidon hash function
 */
const hashOne = (preImage: BigInt): BigInt => {

    return poseidonT3([preImage, BigInt(0)])
}

/*
 * Convert a BigInt to a Buffer
 */
const bigInt2Buffer = (i: BigInt): Buffer => {
    return Buffer.from(i.toString(16), 'hex')
}

/*
 * An internal function which formats a random private key to be compatible
 * with the BabyJub curve. This is the format which should be passed into the
 * PublicKey and other circuits.
 */
const formatPrivKeyForBabyJub = (privKey: PrivKey) => {

    // TODO: clarify this explanation
    // https://tools.ietf.org/html/rfc8032
    // Because of the "buff[0] & 0xF8" part which makes sure you have a point
    // with order that 8 divides (^ pruneBuffer)
    // Every point in babyjubjub is of the form: aP + bH, where H has order 8
    // and P has a big large prime order
    // Guaranteeing that any low order points in babyjubjub get deleted
    const sBuff = eddsa.pruneBuffer(
        bigInt2Buffer(
            hashOne(privKey)
        ).slice(0, 32)
    )

    const s = leBuff2int(sBuff)
    return ff.Scalar.shr(s, 3)
}

/*
 * Generates an Elliptic-curve Diffie–Hellman shared key given a private key
 * and a public key.
 * @return The ECDH shared key.
 */
const genEcdhSharedKey = (
    privKey: PrivKey,
    pubKey: PubKey,
): EcdhSharedKey => {

    return babyJub.mulPointEscalar(pubKey, formatPrivKeyForBabyJub(privKey))
}

/**
 * - Returns a signal value similar to the "callGetSignalByName" function from the "circom-helper" package.
 * - This function depends on the "circom_tester" package.
 * 
 * Example usage:
 * 
 * ```typescript
 * const wasm_tester = require('circom_tester').wasm;
 * 
 * const circuit = await wasm_tester(path.resolve("./circuit/path"));
 * const witness = await circuit.calculateWitness(inputsObject);
 * await circuit.checkConstraints(witness);
 * await circuit.loadSymbols();
 * 
 * /// You can check signal names by printing "circuit.symbols".
 * /// You will mostly need circuit inputs and outputs.
 * const singalName = 'main.out'
 * const signalValue = getSignalByName(circuit, witness, SignalName)
 * ```
 */

const getSignalByName = (circuit: any, witness: any, signalName: string) => {
    return witness[circuit.symbols[signalName].varIdx].toString()
}

export {
    poseidonEncrypt,
    poseidonDecrypt,
    genEcdhSharedKey,
    genRandomNonce,
    getSignalByName,
}
