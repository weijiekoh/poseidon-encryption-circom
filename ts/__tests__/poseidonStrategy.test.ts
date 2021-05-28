import {
    poseidonStrategy,
} from '..'

import {
    callGenWitness as genWitness,
    callGetSignalByName as getSignalByName,
} from 'circom-helper'
const ff = require('ffjavascript')
const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts

const expected = [
    '115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a',
    'fca49b798923ab0239de1c9e7a4a9a2210312b6a2f616d18b5a87f9b628ae29',
    'e7ae82e40091e63cbd4f16a6d16310b3729d4b6e138fcf54110e2867045a30c',
]

const inputs = [1, 2]
const circuit = 'poseidonStrategy_test'

describe('poseidonStrategy function and circuit', () => {
    it('JS function', () => {
        const state = poseidonStrategy([0, ...inputs])

        // The Poseidon hash function outputs the 0th value of the final state.
        // The Poseidon encryption function, however, uses the other values as
        // well.
        expect(state[0].toString(16)).toEqual(expected[0])
        expect(state[1].toString(16)).toEqual(expected[1])
        expect(state[2].toString(16)).toEqual(expected[2])
    })

    it('Circuit', async () => {
        const circuitInputs = stringifyBigInts({
            inputs
        })

        const witness = await genWitness(circuit, circuitInputs)

        const output: string[] = []
        for (let i = 0; i < 3; i++) {
            const out = await getSignalByName(circuit, witness, 'main.out[' + i + ']')
            output.push(out)
        }
        expect(BigInt(output[0]).toString(16)).toEqual(expected[0])
        expect(BigInt(output[1]).toString(16)).toEqual(expected[1])
        expect(BigInt(output[2]).toString(16)).toEqual(expected[2])
    })
})
