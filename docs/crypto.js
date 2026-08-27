(function exposeSheeKryptorCrypto(globalScope) {
  "use strict";

  const MAGIC = new TextEncoder().encode("SKRYPTOR");
  const FORMAT_VERSION = 1;
  const KDF_PBKDF2_SHA256 = 1;
  const PBKDF2_ITERATIONS = 600000;
  const HEADER_SIZE = 42;
  const SALT_OFFSET = 14;
  const NONCE_OFFSET = 30;
  const SALT_SIZE = 16;
  const NONCE_SIZE = 12;
  const TAG_SIZE = 16;

  function createHeader(salt, nonce) {
    const header = new Uint8Array(HEADER_SIZE);
    header.set(MAGIC, 0);
    header[8] = FORMAT_VERSION;
    header[9] = KDF_PBKDF2_SHA256;
    new DataView(header.buffer).setUint32(10, PBKDF2_ITERATIONS, false);
    header.set(salt, SALT_OFFSET);
    header.set(nonce, NONCE_OFFSET);
    return header;
  }

  function parseHeader(data) {
    if (data.byteLength < HEADER_SIZE + TAG_SIZE) {
      throw new Error("This encrypted file is incomplete.");
    }
    const header = data.slice(0, HEADER_SIZE);
    const magicMatches = MAGIC.every((byte, index) => header[index] === byte);
    const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
    if (!magicMatches || header[8] !== FORMAT_VERSION) {
      throw new Error("This is not a supported SheeKryptor web file.");
    }
    if (header[9] !== KDF_PBKDF2_SHA256 || view.getUint32(10, false) !== PBKDF2_ITERATIONS) {
      throw new Error("This file uses unsupported password-hardening settings.");
    }
    return {
      header,
      salt: header.slice(SALT_OFFSET, SALT_OFFSET + SALT_SIZE),
      nonce: header.slice(NONCE_OFFSET, NONCE_OFFSET + NONCE_SIZE),
    };
  }

  async function deriveKey(password, salt, usage) {
    if (!password) throw new Error("Password must not be empty.");
    const passwordMaterial = await globalScope.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return globalScope.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt,
        iterations: PBKDF2_ITERATIONS,
      },
      passwordMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      [usage],
    );
  }

  function combine(first, second) {
    const result = new Uint8Array(first.byteLength + second.byteLength);
    result.set(new Uint8Array(first), 0);
    result.set(new Uint8Array(second), first.byteLength);
    return result;
  }

  async function encryptBytes(plaintext, password) {
    if (password.length < 12) {
      throw new Error("Use a password of at least 12 characters.");
    }
    const salt = globalScope.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
    const nonce = globalScope.crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
    const header = createHeader(salt, nonce);
    const key = await deriveKey(password, salt, "encrypt");
    const ciphertext = await globalScope.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: header,
        tagLength: 128,
      },
      key,
      plaintext,
    );
    return combine(header, ciphertext);
  }

  async function decryptBytes(encrypted, password) {
    const data = encrypted instanceof Uint8Array ? encrypted : new Uint8Array(encrypted);
    const { header, salt, nonce } = parseHeader(data);
    const key = await deriveKey(password, salt, "decrypt");
    try {
      const plaintext = await globalScope.crypto.subtle.decrypt(
        {
          name: "AES-GCM",
          iv: nonce,
          additionalData: header,
          tagLength: 128,
        },
        key,
        data.slice(HEADER_SIZE),
      );
      return new Uint8Array(plaintext);
    } catch (error) {
      throw new Error(
        "The password is incorrect or the encrypted file was modified.",
        { cause: error },
      );
    }
  }

  globalScope.SheeKryptorCrypto = Object.freeze({
    encryptBytes,
    decryptBytes,
    HEADER_SIZE,
    PBKDF2_ITERATIONS,
  });
}(globalThis));
