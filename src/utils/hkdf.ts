import { crypto } from './crypto'
export async function hkdf(secret: Uint8Array) {
    return crypto.subtle.deriveKey(
        {
            name: "HKDF",
            hash: "SHA-256",
            info: new Uint8Array(),
            salt: new Uint8Array(),
        },
        await crypto.subtle.importKey(
            "raw",
            secret,
            { name: "HKDF" },
            false,
            ["deriveKey"]
        ),
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
    );
}
