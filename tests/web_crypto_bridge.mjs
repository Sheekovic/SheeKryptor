import fs from "node:fs/promises";
import { webcrypto } from "node:crypto";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
await import("../docs/crypto.js");

const [operation, inputPath, outputPath, password] = process.argv.slice(2);
if (!["encrypt", "decrypt"].includes(operation)
    || !inputPath || !outputPath || !password) {
  throw new Error("Usage: web_crypto_bridge.mjs encrypt|decrypt input output password");
}

const input = new Uint8Array(await fs.readFile(inputPath));
const output = operation === "encrypt"
  ? await globalThis.SheeKryptorCrypto.encryptBytes(input, password)
  : await globalThis.SheeKryptorCrypto.decryptBytes(input, password);
await fs.writeFile(outputPath, output);
