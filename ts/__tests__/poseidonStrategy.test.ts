const buildPoseidon = require('circomlibjs').buildPoseidon
import { getSignalByName } from '..'

const wasm_tester = require("circom_tester").wasm
const path = require("path")
const ff = require('ffjavascript')
const stringifyBigInts: (obj: object) => any = ff.utils.stringifyBigInts

const expected = [
    '13031e1fb1688551f3ddb0a0245485e8f589c4beaee98a54a73afce6c22fd016',
    '2262fd3e561b5a66e420ebc065290bdb05ba6e666e1a7e22c58af1d541137cb2',
    '29ba1e2f0b875cc8bd1c85199d415a553297a12bb135c4b51a2b38b89f64371d',
    '140d8dfdd343a73f651226dd8c127bd4926f3628e037e6f0cd2e6341f9ac0240',
]

const inputs = [0, 1, 2]

describe('poseidonStrategy function and circuit', () => {
    it('JS function', async () => {
        const poseidonEx = await buildPoseidon()
        const state = poseidonEx(inputs, 0, 4).map((x) => poseidonEx.F.toString(x, 16))

        // The Poseidon hash function outputs the 0th value of the final state.
        // The Poseidon encryption function, however, uses the other values as
        // well.
        expect(state[0]).toEqual(expected[0])
        expect(state[1]).toEqual(expected[1])
        expect(state[2]).toEqual(expected[2])
        expect(state[3]).toEqual(expected[3])
    })

    it('Circuit', async () => {

        const circuit = await wasm_tester(path.resolve("./circom/test/poseidonStrategy_test.circom"));
        const witness = await circuit.calculateWitness({initialState: 0, inputs: [0, 1, 2]})
        await circuit.checkConstraints(witness)
        await circuit.loadSymbols()

        const output: string[] = []
        for (let i=0; i<4; i++) {
            const out = getSignalByName(circuit, witness, `main.out[${i}]`)
            output.push(out)
        }
        expect(BigInt(output[0]).toString(16)).toEqual(expected[0])
        expect(BigInt(output[1]).toString(16)).toEqual(expected[1])
        expect(BigInt(output[2]).toString(16)).toEqual(expected[2])
        expect(BigInt(output[3]).toString(16)).toEqual(expected[3])
    })
})
