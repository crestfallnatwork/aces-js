import { x25519, x25519Base } from "../utils/index";
import { edwardsToMontgomeryPriv } from "@noble/curves/ed25519";

export class ECDHWalletExtension {
    private key: Uint8Array
    get features() {
        return {
            'aptos:echd': {
                version: '0.1.0',
                ecdh: this.ecdh
            },
            'aptos:publicEncryptionKey': {
                version: '0.1.0',
                publicEncryptionKey: this.publicEncryptionKey
            }
        }
    }
    public async ecdh(theirPublicKey: Uint8Array): Promise<Uint8Array> {
        const sk = edwardsToMontgomeryPriv(this.key.slice(0, 32))
        return x25519(sk, theirPublicKey)
    }
    public async publicEncryptionKey(): Promise<Uint8Array> {
        const sk = edwardsToMontgomeryPriv(this.key.slice(0, 32))
        return x25519Base(sk)
    }
    constructor(privateKey: Uint8Array) {
        this.key = privateKey
    }
}

export class ECDH {
    private key: Uint8Array
    constructor(privateKey: Uint8Array) {
        this.key = privateKey
    }
    public async ecdh(theirPublicKey: Uint8Array): Promise<Uint8Array> {
        return x25519(this.key, theirPublicKey)
    }
    public async publicEncryptionKey(): Promise<Uint8Array> {
        return x25519Base(this.key)
    }
}
