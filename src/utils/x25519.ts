import {x25519 as x255} from "@noble/curves/ed25519"

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
