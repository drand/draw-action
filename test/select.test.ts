import {describe, it} from "@jest/globals"
import {expect} from "chai"
import {RandomnessBeacon} from "drand-client"

import {select} from "../src/select"

describe("select", () => {
    const beacon: RandomnessBeacon = {
        round: 4332469,
        randomness: "34b9bc1f9afda7a472c5bff6785d272aa49f0c3a46a02b1896040b44fb759ac3",
        signature: "b945c808e129f88105e27a1709653170680c797c8fb7a606d292b0582564cde1a43de8bdf4f523410e20db22129d54cc18718273dd9e4596b6ed80427f3cd15f6a2a87799c1a7346b5b18adaa1760f027f78d33de8dc713c34d0842df64d63dd",
        previous_signature: "a480ee1575d3cbc71258948e099b433fc0a5e8c9c6c12ba2dc77cfad6d92f97fa454a89353739a1c96b097b73673845d1289b435671cc7b65d75e06e779cb8e64d604f77c3abd4a9107a6f7629993d5c5642c88adf7a2948f9a73226e1393fd3"
    }

    it("returns the whole list if it's less than count, without randomness", async () => {
        const values = ["a", "b", "c", "d"]
        const result = await select(20, values, beacon)

        expect(result.winners).equals(values)
        expect(result.randomness).equals("")
    })

    it("returns nothing if count is 0, without randomness", async () => {
        const values = ["a", "b", "c", "d"]
        const result = await select(0, values, beacon)

        expect(result.winners).deep.equals([])
        expect(result.randomness).equals("")
    })

    it("returns selected values from the list", async () => {
        const values = ["a", "b", "c", "d"]
        const count = 2
        const result = await select(count, values, beacon)

        expect(result.winners.length).equals(count)

        // they should have existed in the first place
        result.winners.forEach(w => values.includes(w))

        // winners should be unique!
        expect(new Set(result.winners).size == result.winners.length)
    })

    it("draws are deterministic", async () => {
        const values = ["a", "b", "c", "d"]
        const count = 2
        const result = await select(count, values, beacon)
        const result2 = await select(count, values, beacon)

        expect(result).deep.equals(result2)
    })
})
