import { poseidonEncrypt, poseidonDecrypt, genRandomNonce, getSignalByName } from '..'
import { Keypair, PrivKey, genRandomSalt } from 'maci-crypto'

const path = require("path");
const wasm_tester = require('circom_tester').wasm
const ff = require('ffjavascript')
const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts

describe('Decryption in a circuit', () => {
    it('should fail if the nonce >= 2 ^ 128', async () => {
        const circuit = await wasm_tester(path.resolve('./circom/test/poseidonDecrypt4_test.circom'))
        const message = [0, 1, 2, 3].map((x) => BigInt(x))
        const key = [BigInt(123), BigInt(456)]
        const nonce = BigInt('340282366920938463463374607431768211456')
        const ciphertext = await poseidonEncrypt(message, key, BigInt(1))

        const circuitInputs = stringifyBigInts({
            ciphertext,
            nonce,
            key,
        })

        expect.assertions(1)
        try {
            const witness = await circuit.calculateWitness(circuitInputs);
            await circuit.checkConstraints(witness);
        } catch (e) {
            expect(true).toBeTruthy()
        }
    })

    it('l = 1', async () => {
        await test('poseidonDecrypt1_test', 1)
    })

    it('l = 2', async () => {
        await test('poseidonDecrypt2_test', 2)
    })

    it('l = 3', async () => {
        await test('poseidonDecrypt3_test', 3)
    })

    it('l = 4', async () => {
        await test('poseidonDecrypt4_test', 4)
    })


    it('l = 5', async () => {
        await test('poseidonDecrypt5_test', 5)
    })


    it('l = 6', async () => {
        await test('poseidonDecrypt6_test', 6)
    })


    it('l = 7', async () => {
        await test('poseidonDecrypt7_test', 7)
    })


    it('l = 8', async () => {
        await test('poseidonDecrypt8_test', 8)
    })

})

const test = async (circuitName: string, messageLength: number) => {
    const message: BigInt[] = []
    for (let i = 0; i < messageLength; i ++) {
        message.push(genRandomSalt())
    }
    const key = [BigInt(123), BigInt(456)]
    const nonce = genRandomNonce()
    const ciphertext = await poseidonEncrypt(message, key, nonce)
    const decrypted = await poseidonDecrypt(ciphertext, key, nonce, message.length)

    let decryptedLength = message.length
    while (decryptedLength % 3 != 0) {
        decryptedLength ++
    }

    const circuit = await wasm_tester(path.resolve(`./circom/test/${circuitName}.circom`));
    const circuitInputs = stringifyBigInts({
        ciphertext,
        nonce,
        key,
    })

    const witness = await circuit.calculateWitness(circuitInputs);
    await circuit.checkConstraints(witness);
    await circuit.loadSymbols()
    const output: string[] = []
    for (let i = 0; i < ciphertext.length - 1; i++) {
        const out = getSignalByName(circuit, witness, 'main.decrypted[' + i + ']')
        output.push(out)
    }

    expect.assertions(decryptedLength)

    for (let i = 0; i < decryptedLength; i ++) {
        if (i < message.length) {
            expect(output[i].toString()).toEqual(message[i].toString())
        } else {
            expect(output[i].toString()).toEqual('0')
        }
    }
}
