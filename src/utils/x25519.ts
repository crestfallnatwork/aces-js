import { Ed25519PrivateKey, Ed25519PublicKey } from "@aptos-labs/ts-sdk"
import {edwardsToMontgomeryPub, edwardsToMontgomeryPriv, x25519 as x255} from "@noble/curves/ed25519"

export function x25519(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {

    return x255.getSharedSecret(ourPrivateKey, theirPublicKey)
}

export function x25519Base(ourPrivateKey: Uint8Array): Uint8Array {
    return x255.getPublicKey(ourPrivateKey)
}

export function generateKeys(): {pk: Uint8Array, sk: Uint8Array} {
    const sk = x255.utils.randomPrivateKey()
    const pk = x255.getPublicKey(sk)
    return {sk, pk}
}

export function toX25519PubKey(pk: Ed25519PublicKey): Uint8Array {
    return edwardsToMontgomeryPub(pk.toUint8Array())
}

export function toX25519PrivKey(sk: Ed25519PrivateKey): Uint8Array {
    return edwardsToMontgomeryPriv(sk.toUint8Array())
}
