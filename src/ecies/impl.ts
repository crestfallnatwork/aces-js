import { hkdf, encrypt, decrypt, x25519 } from "../utils/index"
import { ECDHInterface, generateC25519keys } from "./echd_provider"
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
    async encrypt(raw: Uint8Array, to: Ed25519PublicKey) {
        const ephemeralKeys = generateC25519keys()
        const actualSecret = (await this.ecdher.ecdh(to))
        const ephemeralSecret = x25519(ephemeralKeys.secretKey, to.toUint8Array())
        const secret = x25519(actualSecret, ephemeralSecret)
        const key = await hkdf(secret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.publicKey)
        res.set(ciphertext, 32)
        return res
    }
    async decrypt(ciphertext: Uint8Array, from: Ed25519PublicKey) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const actualSecret = (await this.ecdher.ecdh(from)).slice(0, 32)
        const ephemeralSecret = (await this.ecdher.ecdh(new Ed25519PublicKey(ephemeralPublicKey)))
        const secret = x25519(actualSecret, ephemeralSecret)
        const key = await hkdf(secret)
        return decrypt(ciphertext.slice(32), key)
    }
    async encryptEphemeral(raw: Uint8Array) {
        const ephemeralKeys = generateC25519keys()
        const ephemeralSecret = x25519(ephemeralKeys.secretKey, (await this.ecdher.publicEncryptionKey()).toUint8Array())
        const key = await hkdf(ephemeralSecret)
        const ciphertext = await encrypt(raw, key)
        const res = new Uint8Array(ciphertext.length + 32)
        res.set(ephemeralKeys.publicKey)
        res.set(ciphertext, 32)
        return res
    }
    async decryptEphemeral(ciphertext: Uint8Array) {
        const ephemeralPublicKey = ciphertext.slice(0, 32)
        const ephemeralSecret = (await this.ecdher.ecdh(new Ed25519PublicKey(ephemeralPublicKey)))
        const key = await hkdf(ephemeralSecret)
        return decrypt(ciphertext.slice(32), key)
    }
}
