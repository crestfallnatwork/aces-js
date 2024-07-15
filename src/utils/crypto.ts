export let crypto: Crypto

if ((typeof process !== 'undefined') &&
    (typeof process.versions.node !== 'undefined')) {
    crypto = require('node:crypto')
} else {
    crypto = window.crypto
}
