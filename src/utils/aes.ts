import { randomBytes } from "./random"
import * as crypto from 'node:crypto'

export async function encrypt(raw: Uint8Array, sharedKey: CryptoKey): Promise<Uint8Array> {
    const res = new Uint8Array(12 + raw.length + 16)
    const iv = randomBytes(12)
    res.set(iv)
    res.set(new Uint8Array(await crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            tagLength: 128
        },
        sharedKey,
        raw
    )), 12)
    return res
}
export async function decrypt(ciphertext: Uint8Array, sharedSecret: CryptoKey): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: ciphertext.slice(0, 12)
        },
        sharedSecret, ciphertext.slice(12)));
}
