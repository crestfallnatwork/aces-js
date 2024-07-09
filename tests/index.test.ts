import test, { describe, it } from 'node:test'
import {ECDHWalletExtension, ECIES, ECIESEphemeral, generateC25519keys} from '../index'
import assert from 'node:assert'

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
    return msg === plaintext
}

test("userEncryption", async () => {
        assert.equal(true, await userEncryptionEphemeralTest())
})
test("e2eMessage", async () => {
        assert.equal(true, await e2eMessage())
})
