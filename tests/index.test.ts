import test from 'node:test'
import {ECDHWalletExtension, ECIES} from '../index'
import assert from 'node:assert'
import { Account } from '@aptos-labs/ts-sdk'

async function userEncryptionEphemeralTest() {
    const msg = "Hello Apotos! How are you?"
    const acc = Account.generate()
    const wallet = new ECDHWalletExtension(acc.privateKey.toUint8Array())
    const eciesEph = new ECIES(wallet)
    const ciphertext = await eciesEph.encryptEphemeral(Buffer.from(msg))
    const plaintext = Buffer.from(await eciesEph.decryptEphemeral(ciphertext)).toString('utf-8')
    return msg === plaintext
}

async function e2eMessage() {
    const msg = "Hello Apotos! How are you?"
    const alice = Account.generate()
    const bob = Account.generate()
    const aWallet = new ECDHWalletExtension(alice.privateKey.toUint8Array())
    const bWallet = new ECDHWalletExtension(bob.privateKey.toUint8Array())
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
