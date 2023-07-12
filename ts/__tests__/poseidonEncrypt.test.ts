import { poseidonEncrypt, poseidonDecrypt, genRandomNonce } from '..'
import { genKeypair } from 'maci-crypto'

const test = async (message: BigInt[]) => {
    const keypair = genKeypair()
    const nonce = genRandomNonce()
    const ciphertext = await poseidonEncrypt(message, keypair.pubKey, nonce)
    const decrypted = await poseidonDecrypt(ciphertext, keypair.pubKey, nonce, message.length)

    for (let i = 0; i < message.length; i ++) {
        if (message[i] !== decrypted[i]) {
            console.log(keypair, nonce, message, ciphertext)
        }
        expect(message[i]).toEqual(decrypted[i])
    }
    expect(message.length).toEqual(decrypted.length)
}

describe('Encryption and decryption', () => {

    it('Encryption and decryption', async () => {
        await test([0].map((x) => BigInt(x)))
        await test([0, 1].map((x) => BigInt(x)))
        await test([0, 1, 2].map((x) => BigInt(x)))
        await test([0, 1, 2, 3].map((x) => BigInt(x)))
        await test([0, 1, 2, 3, 4].map((x) => BigInt(x)))
        await test([0, 1, 2, 3, 4, 5].map((x) => BigInt(x)))
        await test([0, 1, 2, 3, 4, 5, 6].map((x) => BigInt(x)))
    })
})

