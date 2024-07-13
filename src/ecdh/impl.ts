import { Ed25519PrivateKey } from "@aptos-labs/ts-sdk";
import { toX25519PrivKey, x25519, x25519Base } from "../utils/index";

export class ECDHWalletExtension {
    private key: Ed25519PrivateKey
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
        const sk = toX25519PrivKey(this.key)
        return x25519(sk, theirPublicKey)
    }
    public async publicEncryptionKey(): Promise<Uint8Array> {
        const sk = toX25519PrivKey(this.key)
        return x25519Base(sk)
    }
    constructor(privateKey: Uint8Array) {
        this.key = new Ed25519PrivateKey(privateKey)
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
