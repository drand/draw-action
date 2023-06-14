import * as fs from "fs/promises"
import * as path from "path"
import * as core from "@actions/core"
import fetch from "node-fetch"
import {readFile} from "fs/promises"
import {HttpCachingChain, HttpChainClient} from "drand-client"
import {select} from "./select"
// @ts-ignore
global.fetch = fetch

main().catch(err => {
    console.error(err);
    console.error(err.stack);
    process.exit(err.code || -1);
})

async function main(): Promise<void> {
    const inputDir = core.getInput("inputDir") ?? "."
    const outputDir = core.getInput("outputDir") ?? "."
    const drawPrefix = core.getInput("drawPrefix") ?? "draw-"
    const drandURL = core.getInput("drandURL") ?? "https://api.drand.sh"
    const gitRepo = process.env.GITHUB_WORKSPACE
    const drandClient = new HttpChainClient(new HttpCachingChain(drandURL))

    const inputFiles = await fs.readdir(path.join(gitRepo, inputDir))
    const outputFiles = await fs.readdir(path.join(gitRepo, outputDir))

    for (let inputFile of inputFiles) {
        // we don't want to redo draws that have already been done
        const outputFilename = `${drawPrefix}${inputFile}`
        if (outputFiles.includes(outputFilename)) {
            console.log(`skipping ${outputFilename}`)
            continue
        }

        console.log(`processing ${inputFile}`)
        const contents = await readFile(path.join(gitRepo, inputDir, inputFile))

        // we trim any empty entries in case of trailing newlines
        const lines = contents.toString()
            .split("\n")
            .filter(it => it.trim() !== "")

        const selectionOutput = await select({
            count: 1,
            values: lines,
            drandClient: drandClient
        })
        await fs.writeFile(path.join(gitRepo, outputDir, outputFilename), JSON.stringify(selectionOutput))
        console.log(`created ${outputFilename}`)
    }
}