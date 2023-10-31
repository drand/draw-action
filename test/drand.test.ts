import {test, expect} from "@jest/globals"
import {HttpCachingChain, HttpChainClient} from "drand-client"
import {drawWithDrand} from "../src"
import fetch from "node-fetch"

test("things should run smoothly with real drand", async () => {
    const chain = new HttpCachingChain("https://pl-eu.testnet.drand.sh")
    const client = new HttpChainClient(chain)

    const count = 2
    const list = ["alice", "bob", "carol", "dave", "esther", "fred"]
    const result = await drawWithDrand(client, count, list)

    // ensure the correct number are drawn
    expect(result.winners.length).toEqual(2)
    // ensure they're unique
    expect(new Set(result.winners).size).toEqual(result.winners.length)
    // ensure they exist in the original list
    result.winners.forEach(winner => {
        expect(list.includes(winner))
    })

    // basic sanity check on the randomness
    expect(result.round).toBeGreaterThan(1)
    expect(result.randomness.length).toBeGreaterThan(1)

    // this test can take a while until the next round is emitted
}, 40000)
