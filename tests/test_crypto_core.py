import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from crypto_core import (
    CryptoError,
    HEADER_STRUCT,
    InvalidEncryptedFile,
    decrypt_file,
    encrypt_file,
)


class CryptoCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def round_trip(self, payload: bytes) -> None:
        source = self.root / "source.bin"
        encrypted = self.root / "source.bin.skrypt"
        recovered = self.root / "recovered.bin"
        source.write_bytes(payload)

        encrypt_file(source, encrypted, "correct horse battery staple")
        used_legacy = decrypt_file(
            encrypted, recovered, "correct horse battery staple"
        )

        self.assertFalse(used_legacy)
        self.assertEqual(recovered.read_bytes(), payload)
        self.assertGreaterEqual(encrypted.stat().st_size, HEADER_STRUCT.size + 16)

    def test_round_trip_preserves_exact_bytes(self):
        for payload in (
            b"",
            b"a",
            b"a" * 15,
            b"a" * 16,
            b"a" * 17,
            os.urandom(2 * 1024 * 1024 + 37),
        ):
            with self.subTest(size=len(payload)):
                self.round_trip(payload)

    def test_wrong_password_does_not_replace_existing_output(self):
        source = self.root / "source.bin"
        encrypted = self.root / "source.bin.skrypt"
        recovered = self.root / "recovered.bin"
        source.write_bytes(b"classified")
        recovered.write_bytes(b"keep me")
        encrypt_file(source, encrypted, "right password")

        with self.assertRaises(InvalidEncryptedFile):
            decrypt_file(encrypted, recovered, "wrong password")

        self.assertEqual(recovered.read_bytes(), b"keep me")

    def test_tampering_is_detected(self):
        source = self.root / "source.bin"
        encrypted = self.root / "source.bin.skrypt"
        recovered = self.root / "recovered.bin"
        source.write_bytes(b"authenticated data")
        encrypt_file(source, encrypted, "tamper-test-password")

        damaged = bytearray(encrypted.read_bytes())
        damaged[HEADER_STRUCT.size] ^= 0x01
        encrypted.write_bytes(damaged)

        with self.assertRaises(InvalidEncryptedFile):
            decrypt_file(encrypted, recovered, "tamper-test-password")

        self.assertFalse(recovered.exists())

    def test_short_encryption_password_is_rejected(self):
        source = self.root / "source.bin"
        encrypted = self.root / "source.bin.skrypt"
        source.write_bytes(b"data")

        with self.assertRaisesRegex(CryptoError, "at least 12"):
            encrypt_file(source, encrypted, "too-short")

        self.assertFalse(encrypted.exists())

    def test_legacy_format_is_unpadded_and_reported(self):
        source_data = b"legacy payload with exact recovery"
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100_000,
        ).derive(b"legacy password")
        padder = padding.PKCS7(128).padder()
        padded = padder.update(source_data) + padder.finalize()
        encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        legacy_file = self.root / "legacy.enc"
        legacy_file.write_bytes(
            salt + iv + encryptor.update(padded) + encryptor.finalize()
        )
        recovered = self.root / "legacy.out"

        used_legacy = decrypt_file(legacy_file, recovered, "legacy password")

        self.assertTrue(used_legacy)
        self.assertEqual(recovered.read_bytes(), source_data)

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for web interoperability")
    def test_desktop_and_web_formats_are_interoperable(self):
        password = "cross edition test password"
        payload = os.urandom(4096) + b" cross-platform"
        source = self.root / "source.bin"
        desktop_encrypted = self.root / "desktop.skrypt"
        web_recovered = self.root / "web-recovered.bin"
        web_encrypted = self.root / "web.skrypt"
        desktop_recovered = self.root / "desktop-recovered.bin"
        source.write_bytes(payload)
        bridge = Path(__file__).with_name("web_crypto_bridge.mjs")

        encrypt_file(source, desktop_encrypted, password)
        subprocess.run(
            ["node", bridge, "decrypt", desktop_encrypted, web_recovered, password],
            check=True,
        )
        self.assertEqual(web_recovered.read_bytes(), payload)

        subprocess.run(
            ["node", bridge, "encrypt", source, web_encrypted, password],
            check=True,
        )
        used_legacy = decrypt_file(web_encrypted, desktop_recovered, password)
        self.assertFalse(used_legacy)
        self.assertEqual(desktop_recovered.read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
