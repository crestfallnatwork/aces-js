import { crypto } from './crypto'

export function randomBytes(n: number): Uint8Array {
    return randomBytesIn(new Uint8Array(n))
}

export function randomBytesIn(to: Uint8Array): Uint8Array {
    return crypto.getRandomValues(to)
}
