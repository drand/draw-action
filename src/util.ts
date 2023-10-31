export async function retry<T>(times: number, fn: () => Promise<T>) {
    try {
        return await fn()
    } catch (err) {
        if (times == 1) {
            return Promise.reject(err)
        }

        await sleep(1000)
        return retry(times - 1, fn)
    }
}

export function sleep(timeMs: number): Promise<void> {
    return new Promise(resolve => setTimeout(() => resolve(), timeMs))
}