import nacl from "tweetnacl"

export interface ECDHInterface {
    ecdh(theirPublicKey: Uint8Array): Promise<Uint8Array>
}

export function generateC25519keys(): { publicKey: Uint8Array, secretKey: Uint8Array }{
    const keys = nacl.box.keyPair()
    return {publicKey: keys.publicKey, secretKey: keys.secretKey}
}

export function X25519ECDH(ecdh: (theirPublicKey: Uint8Array) => Promise<Uint8Array>): ECDHInterface {
   return {
       ecdh: ecdh,
   }
}
