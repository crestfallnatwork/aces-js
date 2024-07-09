import { Ed25519PublicKey} from "@aptos-labs/ts-sdk";
import { x25519, x25519Base } from "../utils/index";

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
    public async ecdh(theirPublicKey: Ed25519PublicKey): Promise<Uint8Array> {
        return x25519(this.key.slice(0,32), theirPublicKey.toUint8Array())
    }
    public async publicEncryptionKey(): Promise<Ed25519PublicKey> {
        return new Ed25519PublicKey(x25519Base(this.key.slice(0, 32)))
    }
    constructor(privateKey: Uint8Array) {
        this.key = privateKey
    }
}
