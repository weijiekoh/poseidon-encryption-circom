import { poseidonEncrypt, poseidonDecrypt, genRandomNonce } from '..'
import { Keypair, PrivKey, genRandomSalt } from 'maci-crypto'
import {
    callGenWitness as genWitness,
    callGetSignalByName as getSignalByName,
} from 'circom-helper'
const ff = require('ffjavascript')
const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts

describe('Decryption in a circuit', () => {
    it('should fail if the nonce >= 2 ^ 128', async () => {
        const circuit = 'poseidonDecrypt4_test'
        const message = [0, 1, 2, 3].map((x) => BigInt(x))
        const key = [BigInt(123), BigInt(456)]
        const nonce = BigInt('340282366920938463463374607431768211456')
        const ciphertext = poseidonEncrypt(message, key, BigInt(1))

        const circuitInputs = stringifyBigInts({
            ciphertext,
            nonce,
            key,
        })

        expect.assertions(1)
        try {
            await genWitness(circuit, circuitInputs)
        } catch (e) {
            expect(true).toBeTruthy()
        }
    })

    it('l = 2', async () => {
        test('poseidonDecrypt2_test', 2)
    })

    it('l = 3', async () => {
        test('poseidonDecrypt3_test', 3)
    })

    it('l = 4', async () => {
        test('poseidonDecrypt4_test', 4)
    })

})

const test = async (circuit: string, messageLength: number) => {
    const message: BigInt[] = []
    for (let i = 0; i < messageLength; i ++) {
        message.push(genRandomSalt())
    }
    const key = [BigInt(123), BigInt(456)]
    const nonce = BigInt(789)
    const ciphertext = poseidonEncrypt(message, key, nonce)
    const decrypted = poseidonDecrypt(ciphertext, key, nonce, message.length)

    let decryptedLength = message.length
    while (decryptedLength % 3 != 0) {
        decryptedLength ++
    }

    const circuitInputs = stringifyBigInts({
        ciphertext,
        nonce,
        key,
    })

    const witness = await genWitness(circuit, circuitInputs)
    const output: string[] = []
    for (let i = 0; i < ciphertext.length - 1; i++) {
        const out = await getSignalByName(circuit, witness, 'main.decrypted[' + i + ']')
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
