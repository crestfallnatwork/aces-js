import { generateAddress } from '@ethereumjs/util'
import {ECDHWalletExtension, ECIES, ECIESEphemeral, generateC25519keys} from './index'

async function main() {
    console.log(await userEncryptionEphemeralTest())
    console.log(await e2eMessage())
}

async function userEncryptionEphemeralTest() {
    const msg = "Hello Apotos! How are you?"
    const {publicKey, secretKey} = generateC25519keys()
    const wallet = new ECDHWalletExtension(secretKey)
    const eciesEph = new ECIESEphemeral(wallet)
    const ciphertext = await eciesEph.encrypt(Buffer.from(msg))
    const plaintext = Buffer.from(await eciesEph.decrypt(ciphertext)).toString('utf-8')
    console.log(plaintext)
    return msg === plaintext
}

async function e2eMessage() {
    const msg = "Hello Apotos! How are you?"
    const alice = generateC25519keys()
    const bob = generateC25519keys()
    const aWallet = new ECDHWalletExtension(alice.secretKey)
    const bWallet = new ECDHWalletExtension(bob.secretKey)
    const aEcies = new ECIES(aWallet)
    const bEcies = new ECIES(bWallet)
    const ciphertext = await aEcies.encrypt(Buffer.from(msg), await bWallet.publicEncryptionKey())
    const plaintext = Buffer.from(await bEcies.decrypt(ciphertext, await aWallet.publicEncryptionKey())).toString('utf-8')
    console.log(plaintext)
    return msg === plaintext
}

main()
