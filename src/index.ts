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
    const prefix = core.getInput("drawPrefix") ?? "draw-"
    const name = core.getInput("name") ?? ""
    const drandURL = core.getInput("drandURL") ?? "https://api.drand.sh"
    const count = Number.parseInt(core.getInput("count") ?? "1")
    const gitRepo = process.env.GITHUB_WORKSPACE
    const drandClient = new HttpChainClient(new HttpCachingChain(drandURL))

    const inputFiles = await fs.readdir(path.join(gitRepo, inputDir))
    const outputFiles = await fs.readdir(path.join(gitRepo, outputDir))

    for (let inputFile of inputFiles) {
        await writeDraw({prefix, inputFile, outputFiles, gitRepo, inputDir, count, drandClient, name, outputDir})
    }
}

type DrawOptions = {
    name: string
    prefix: string,
    inputFile: string,
    outputDir: string
    outputFiles: string[],
    gitRepo: string,
    inputDir: string,
    count: number
    drandClient: HttpChainClient
}

async function writeDraw(options: DrawOptions) {
    const {prefix, inputFile, outputFiles, gitRepo, inputDir, count, drandClient, name, outputDir} = options
    // we don't want to redo draws that have already been done
    const outputFilename = `${prefix}${inputFile}`
    if (outputFiles.includes(outputFilename)) {
        console.log(`skipping ${outputFilename}`)
        return
    }

    console.log(`processing ${inputFile}`)
    const contents = await readFile(path.join(gitRepo, inputDir, inputFile))

    // we trim any empty entries in case of trailing newlines
    const lines = contents.toString()
        .split("\n")
        .filter(it => it.trim() !== "")

    const selectionOutput = await select({
        count,
        values: lines,
        drandClient: drandClient
    })

    const fileOutput: FileOutput = {
        time: Date.now(),
        name,
        total: lines.length,
        ...selectionOutput
    }
    await fs.writeFile(path.join(gitRepo, outputDir, outputFilename), JSON.stringify(fileOutput))
    console.log(`created ${outputFilename}`)
}

export type FileOutput = {
    time: number
    name: string
    total: number
    hashedInput: string
    winners: Array<string>
    randomness: string
    round: number
}