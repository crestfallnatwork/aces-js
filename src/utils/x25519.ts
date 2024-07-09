import nacl from "tweetnacl";

export function x25519(ourPrivateKey: Uint8Array, theirPublicKey: Uint8Array): Uint8Array {
    return nacl.scalarMult(ourPrivateKey, theirPublicKey)
}

export function x25519Base(ourPrivateKey: Uint8Array): Uint8Array {
    return nacl.scalarMult.base(ourPrivateKey)
}