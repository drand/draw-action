import * as core from "@actions/core"
import {HttpCachingChain, HttpChainClient} from "drand-client"
import fs from "fs/promises"
import path from "path"

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
export async function parseGithubOptions(): Promise<Array<DrawOptions>> {
    const inputDir = core.getInput("inputDir") ?? "."
    const outputDir = core.getInput("outputDir") ?? "."
    const prefix = core.getInput("drawPrefix") ?? "draw-"
    const name = core.getInput("name") ?? ""
    const drandURL = core.getInput("drandURL") ?? "https://api.drand.sh"
    const count = Number.parseInt(core.getInput("count") ?? "1")
    const gitRepo = process.env.GITHUB_WORKSPACE ?? ""
    const drandClient = new HttpChainClient(new HttpCachingChain(drandURL))

    const inputFiles = await fs.readdir(path.join(gitRepo, inputDir))
    const outputFiles = await fs.readdir(path.join(gitRepo, outputDir))

    return inputFiles.map(inputFile => ({
        prefix,
        inputFile,
        outputFiles,
        gitRepo,
        inputDir,
        count,
        drandClient,
        name,
        outputDir
    }))
}