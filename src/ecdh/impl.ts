import { Account, AccountAddress, AccountPublicKey, Aptos, Ed25519PrivateKey, Secp256k1PrivateKey, SigningScheme, SigningSchemeInput } from "@aptos-labs/ts-sdk";
import { x25519 } from "../utils/index";
import nacl from "tweetnacl";

type AccountWithKey = { account: Account, sk: Uint8Array, scheme: number }
type AccountInfo = { address: AccountAddress, publicKey: AccountPublicKey }
export class ECDHWalletExtension {
    private signer: AccountWithKey
    get features() {
        return {
            'aptos:echd': {
                version: '0.1.0',
                ecdh: this.ecdh
            },
            'aptos:account': {
                version: '0.1.0',
                account: this.signer
            },
            'aptos:publicEncryptionKey': {
                version: '0.1.0',
                publicEncryptionKey: this.publicEncryptionKey
            }
        }
    }
    public async ecdh(theirPublicKey: Uint8Array): Promise<Uint8Array> {
        return x25519(this.signer.sk, theirPublicKey)
    }
    public async publicEncryptionKey(): Promise<Uint8Array> {
        return nacl.scalarMult.base(this.signer.sk)
    }
    public async account(): Promise<AccountInfo> {
        return {
            publicKey: this.signer.account.publicKey,
            address: this.signer.account.accountAddress
        }
    }
    constructor(privateKey: Uint8Array, signingScheme: SigningSchemeInput = SigningSchemeInput.Ed25519) {
        if (privateKey.length !== 32) {
            throw new Error("private key must be 32 bytes")
        }

        let key: Ed25519PrivateKey | Secp256k1PrivateKey
        let scheme = 0
        switch (signingScheme) {
            case SigningSchemeInput.Ed25519: {
                key = new Ed25519PrivateKey(privateKey)
                scheme = 1
                break
            }
            case SigningSchemeInput.Secp256k1Ecdsa: {
                key = new Secp256k1PrivateKey(privateKey)
                scheme = 2
                break
            }
        }
        const account = Account.fromPrivateKey({ privateKey: key, legacy: false })
        this.signer = { account: account, sk: privateKey, scheme: scheme }
    }
}
