import { hkdf, encrypt, decrypt, x25519, generateKeys } from "../utils/index"
import { ECDHInterface } from "./echd_provider"
import { Ed25519PublicKey } from "@aptos-labs/ts-sdk"

export interface ECIESLike {
    encrypt(raw: Uint8Array, to: Ed25519PublicKey): Promise<Uint8Array>
    decrypt(ciphertext: Uint8Array, from: Ed25519PublicKey): Promise<Uint8Array>
}
export interface ECIESEphemeralLike {
    encryptEphemeral(raw: Uint8Array): Promise<Uint8Array>
    decryptEphemeral(ciphertext: Uint8Array): Promise<Uint8Array>
}

export class ECIES {
    private ecdher: ECDHInterface
    constructor(ecdhProvider: ECDHInterface) {
        this.ecdher = ecdhProvider
    }
    async encrypt(raw: Uint8Array, to: Uint8Array) {
        const ephemeralKeys = generateKeys()
        const secret = new Uint8Array(64)
        secret.set((await this.ecdher.ecdh(to)))
        secret.set(x25519(ephemeralKeys.sk, to), 32)
        const key = await hkdf(secret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.pk)
        res.set(ciphertext, 32)
        return res
    }
    async decrypt(ciphertext: Uint8Array, from: Uint8Array) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const secret = new Uint8Array(64)
        secret.set((await this.ecdher.ecdh(from)).slice(0, 32))
        secret.set((await this.ecdher.ecdh(ephemeralPublicKey)), 32)
        const key = await hkdf(secret)
        return decrypt(ciphertext.slice(32), key)
    }
    async encryptEphemeral(raw: Uint8Array) {
        const ephemeralKeys = generateKeys()
        const ephemeralSecret = x25519(ephemeralKeys.sk, (await this.ecdher.publicEncryptionKey()))
        const key = await hkdf(ephemeralSecret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.pk)
        res.set(ciphertext, 32)
        return res
    }
    async decryptEphemeral(ciphertext: Uint8Array) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const ephemeralSecret = (await this.ecdher.ecdh(ephemeralPublicKey))
        const key = await hkdf(ephemeralSecret)
        return decrypt(ciphertext.slice(32), key)
    }
}
