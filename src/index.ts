import * as fs from "fs/promises"
import * as path from "path"
import {readFile} from "fs/promises"
import {fetchBeacon, HttpChainClient, roundAt} from "drand-client"
import {select, SelectionOutput} from "./select"
import {retry} from "./util"
import {parseGithubOptions} from "./options"

main().catch(err => {
    console.error(err);
    console.error(err.stack);
    process.exit(err.code || -1);
})

async function main(): Promise<void> {
    const draws = await parseGithubOptions()

    for (let draw of draws) {
        const {prefix, inputFile, outputFiles, gitRepo, inputDir, count, drandClient, name, outputDir} = draw
        // we don't want to redo draws that have already been done
        const outputFilename = `${prefix}${inputFile}`
        if (outputFiles.includes(outputFilename)) {
            console.log(`skipping ${outputFilename}`)
            return
        }
        const drawItems = await readDrawItems(inputFile, gitRepo, inputDir)
        const selectionOutput = await drawWithDrand(drandClient, count, drawItems)
        await writeSuccessfulDraw(name, drawItems, selectionOutput, gitRepo, outputDir, outputFilename)
    }
}

async function readDrawItems(inputFile: string, gitRepo: string, inputDir: string) {
    console.log(`processing ${inputFile}`)
    const contents = await readFile(path.join(gitRepo, inputDir, inputFile))

    // we trim any empty entries in case of trailing newlines
    return contents.toString()
        .split("\n")
        .filter(it => it.trim() !== "")
}

export async function drawWithDrand(drandClient: HttpChainClient, count: number, values: Array<string>) {
    const chainInfo = await drandClient.chain().info()
    const nextRound = roundAt(Date.now(), chainInfo) + 1

    // let's get the chosen random number from drand; try up to 35 times as it's more than the `default` network period
    const beacon = await retry(35, () => fetchBeacon(drandClient, nextRound))

    return select(count, values, beacon)
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

async function writeSuccessfulDraw(name: string, drawItems: string[], selectionOutput: SelectionOutput, gitRepo: string, outputDir: string, outputFilename: string) {
    const fileOutput: FileOutput = {
        time: Date.now(),
        name,
        total: drawItems.length,
        ...selectionOutput
    }
    await fs.writeFile(path.join(gitRepo, outputDir, outputFilename), JSON.stringify(fileOutput))
    console.log(`created ${outputFilename}`)
}
