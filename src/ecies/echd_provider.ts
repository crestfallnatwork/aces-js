import { Ed25519PublicKey } from "@aptos-labs/ts-sdk"
import nacl from "tweetnacl"

export interface ECDHInterface {
    ecdh(theirPublicKey: Ed25519PublicKey): Promise<Uint8Array>
    publicEncryptionKey(): Promise<Ed25519PublicKey>
}

export function generateC25519keys(): { publicKey: Uint8Array, secretKey: Uint8Array }{
    const keys = nacl.box.keyPair()
    return {publicKey: keys.publicKey, secretKey: keys.secretKey}
}
