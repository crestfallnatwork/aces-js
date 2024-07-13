import { Ed25519PublicKey } from "@aptos-labs/ts-sdk"

export interface ECDHInterface {
    ecdh(theirPublicKey: Uint8Array): Promise<Uint8Array>
    publicEncryptionKey(): Promise<Uint8Array>
}
