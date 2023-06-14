import * as fs from "fs/promises"
import * as path from "path"
import {readFile} from "fs/promises"
import {HttpCachingChain, HttpChainClient} from "drand-client"
import {select} from "./select"

main().catch(err => {
    console.error(err);
    console.error(err.stack);
    process.exit(err.code || -1);
})

async function main(): Promise<void> {
    const inputDir = process.env.INPUT_DIR || "."
    const outputDir = process.env.OUTPUT_DIR || "."
    const drawPrefix = process.env.OUTPUT_PREFIX || "draw-"
    const drandURL = process.env.DRAND_URL || "https://api.drand.sh"
    const drandClient = new HttpChainClient(new HttpCachingChain(drandURL))

    const inputFiles = await fs.readdir(path.join(__dirname, inputDir))
    const outputFiles = await fs.readdir(path.join(__dirname, outputDir))

    for (let inputFile of inputFiles) {
        // we don't want to redo draws that have already been done
        const outputFilename = `${drawPrefix}${inputFile}`
        if (outputFiles.includes(outputFilename)) {
            console.log(`skipping ${outputFilename}`)
            continue
        }

        console.log(`processing ${inputFile}`)
        const contents = await readFile(path.join(inputDir, inputFile))
        const lines = contents.toString().split("\n")
        const selectionOutput = await select({
            count: 1,
            values: lines,
            drandClient: drandClient
        })
        await fs.writeFile(path.join(outputDir, outputFilename), JSON.stringify(selectionOutput))
        console.log(`created ${outputFilename}`)
    }
}