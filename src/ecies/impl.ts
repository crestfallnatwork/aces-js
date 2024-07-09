import nacl from "tweetnacl"
import { hkdf, encrypt, decrypt, x25519 } from "../utils/index"
import { ECDHInterface, generateC25519keys } from "./echd_provider"

export class ECIES {
    private ecdher: ECDHInterface
    constructor(ecdhProvider: ECDHInterface) {
        this.ecdher = ecdhProvider
    }
    async encrypt(raw: Uint8Array, to: Uint8Array) {
        const ephemeralKeys = generateC25519keys()
        const actualSecret = (await this.ecdher.ecdh(to))
        const ephemeralSecret = x25519(ephemeralKeys.secretKey, to)
        const secret = nacl.scalarMult(actualSecret, ephemeralSecret)
        const key = await hkdf(secret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.publicKey)
        res.set(ciphertext, 32)
        return res
    }
    async decrypt(ciphertext: Uint8Array, from: Uint8Array) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const actualSecret = (await this.ecdher.ecdh(from)).slice(0, 32)
        const ephemeralSecret = (await this.ecdher.ecdh(ephemeralPublicKey)).slice(0, 32)
        const secret = nacl.scalarMult(actualSecret, ephemeralSecret)
        const key = await hkdf(secret)
        return decrypt(ciphertext.slice(32), key)
    }
}

export class ECIESEphemeral {
    private ecdher: ECDHInterface
    constructor(ecdhProvider: ECDHInterface) {
        this.ecdher = ecdhProvider
    }
    async encrypt(raw: Uint8Array) {
        const ephemeralKeys = generateC25519keys()
        const ephemeralSecret = x25519(ephemeralKeys.secretKey, await this.ecdher.publicEncryptionKey())
        const key = await hkdf(ephemeralSecret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.publicKey)
        res.set(ciphertext, 32)
        return res
    }
    async decrypt(ciphertext: Uint8Array) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const ephemeralSecret = (await this.ecdher.ecdh(ephemeralPublicKey))
        const key = await hkdf(ephemeralSecret)
        return decrypt(ciphertext.slice(32), key)
    }

}
