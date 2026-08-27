"""Versioned, authenticated file encryption for SheeKryptor.

The current format uses PBKDF2-HMAC-SHA-256 for browser-compatible password
hardening and AES-GCM for authenticated streaming encryption. The module has
no GUI dependencies so security-sensitive behavior can be tested independently.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"SKRYPTOR"
FORMAT_VERSION = 1
KDF_PBKDF2_SHA256 = 1
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
HEADER_STRUCT = struct.Struct(">8sBBI16s12s")
MIN_ENCRYPTED_SIZE = HEADER_STRUCT.size + TAG_SIZE


class CryptoError(Exception):
    """Base exception for encryption and decryption failures."""


class InvalidEncryptedFile(CryptoError):
    """Raised when a password is wrong or encrypted data is invalid."""


def _validate_paths(input_file: os.PathLike[str] | str,
                    output_file: os.PathLike[str] | str) -> tuple[Path, Path]:
    input_path = Path(input_file)
    output_path = Path(output_file)

    if not input_path.is_file():
        raise CryptoError(f"Input file does not exist: {input_path}")

    if os.path.normcase(os.path.abspath(input_path)) == os.path.normcase(
            os.path.abspath(output_path)):
        raise CryptoError("Input and output paths must be different.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    return input_path, output_path


def _derive_current_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise CryptoError("Password must not be empty.")

    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=32,
        iterations=PBKDF2_ITERATIONS,
    ).derive(password.encode("utf-8"))


def _derive_legacy_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    ).derive(password.encode("utf-8"))


def _temporary_output(output_path: Path) -> tuple[int, Path]:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_path.parent,
        prefix=f".{output_path.name}.",
        suffix=".tmp",
    )
    return descriptor, Path(temporary_name)


def _commit_output(output_handle: BinaryIO, temporary_path: Path,
                   output_path: Path) -> None:
    output_handle.flush()
    os.fsync(output_handle.fileno())
    output_handle.close()
    os.replace(temporary_path, output_path)


def encrypt_file(input_file: os.PathLike[str] | str,
                 output_file: os.PathLike[str] | str,
                 password: str) -> None:
    """Encrypt a file using the authenticated SheeKryptor v1 format."""

    if len(password) < 12:
        raise CryptoError("Use a password of at least 12 characters.")
    input_path, output_path = _validate_paths(input_file, output_file)
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = HEADER_STRUCT.pack(
        MAGIC,
        FORMAT_VERSION,
        KDF_PBKDF2_SHA256,
        PBKDF2_ITERATIONS,
        salt,
        nonce,
    )
    key = _derive_current_key(password, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(header)

    descriptor, temporary_path = _temporary_output(output_path)
    output_handle = os.fdopen(descriptor, "wb")
    try:
        with input_path.open("rb") as input_handle:
            output_handle.write(header)
            while chunk := input_handle.read(CHUNK_SIZE):
                output_handle.write(encryptor.update(chunk))
            output_handle.write(encryptor.finalize())
            output_handle.write(encryptor.tag)

        _commit_output(output_handle, temporary_path, output_path)
    except Exception:
        if not output_handle.closed:
            output_handle.close()
        temporary_path.unlink(missing_ok=True)
        raise


def _read_current_header(input_handle: BinaryIO) -> tuple[bytes, bytes]:
    header = input_handle.read(HEADER_STRUCT.size)
    if len(header) != HEADER_STRUCT.size:
        raise InvalidEncryptedFile("The encrypted file header is incomplete.")

    magic, version, kdf_id, iterations, salt, nonce = HEADER_STRUCT.unpack(header)
    if magic != MAGIC or version != FORMAT_VERSION:
        raise InvalidEncryptedFile("Unsupported SheeKryptor file format.")
    if (kdf_id, iterations) != (
            KDF_PBKDF2_SHA256, PBKDF2_ITERATIONS):
        raise InvalidEncryptedFile("Unsupported key-derivation parameters.")

    return salt, nonce


def _decrypt_current(input_path: Path, output_path: Path, password: str) -> None:
    file_size = input_path.stat().st_size
    if file_size < MIN_ENCRYPTED_SIZE:
        raise InvalidEncryptedFile("The encrypted file is too short.")

    descriptor, temporary_path = _temporary_output(output_path)
    output_handle = os.fdopen(descriptor, "wb")
    try:
        with input_path.open("rb") as input_handle:
            header = input_handle.read(HEADER_STRUCT.size)
            input_handle.seek(0)
            salt, nonce = _read_current_header(input_handle)
            input_handle.seek(file_size - TAG_SIZE)
            tag = input_handle.read(TAG_SIZE)
            input_handle.seek(HEADER_STRUCT.size)

            key = _derive_current_key(password, salt)
            decryptor = Cipher(
                algorithms.AES(key), modes.GCM(nonce, tag)
            ).decryptor()
            decryptor.authenticate_additional_data(header)

            remaining = file_size - HEADER_STRUCT.size - TAG_SIZE
            while remaining:
                chunk = input_handle.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    raise InvalidEncryptedFile("The encrypted file is truncated.")
                remaining -= len(chunk)
                output_handle.write(decryptor.update(chunk))
            output_handle.write(decryptor.finalize())

        _commit_output(output_handle, temporary_path, output_path)
    except (InvalidTag, ValueError) as exc:
        if not output_handle.closed:
            output_handle.close()
        temporary_path.unlink(missing_ok=True)
        raise InvalidEncryptedFile(
            "Incorrect password or the encrypted file has been modified."
        ) from exc
    except Exception:
        if not output_handle.closed:
            output_handle.close()
        temporary_path.unlink(missing_ok=True)
        raise


def _decrypt_legacy(input_path: Path, output_path: Path, password: str) -> None:
    """Read the original salt + IV + AES-CBC format for migration purposes."""

    file_size = input_path.stat().st_size
    ciphertext_size = file_size - 32
    if ciphertext_size <= 0 or ciphertext_size % 16:
        raise InvalidEncryptedFile("This is not a valid legacy encrypted file.")

    descriptor, temporary_path = _temporary_output(output_path)
    output_handle = os.fdopen(descriptor, "wb")
    try:
        with input_path.open("rb") as input_handle:
            salt = input_handle.read(16)
            iv = input_handle.read(16)
            key = _derive_legacy_key(password, salt)
            decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
            unpadder = padding.PKCS7(128).unpadder()

            while chunk := input_handle.read(CHUNK_SIZE):
                output_handle.write(unpadder.update(decryptor.update(chunk)))
            padded_tail = decryptor.finalize()
            output_handle.write(unpadder.update(padded_tail))
            output_handle.write(unpadder.finalize())

        _commit_output(output_handle, temporary_path, output_path)
    except ValueError as exc:
        if not output_handle.closed:
            output_handle.close()
        temporary_path.unlink(missing_ok=True)
        raise InvalidEncryptedFile(
            "Incorrect password or the legacy encrypted file is damaged."
        ) from exc
    except Exception:
        if not output_handle.closed:
            output_handle.close()
        temporary_path.unlink(missing_ok=True)
        raise


def decrypt_file(input_file: os.PathLike[str] | str,
                 output_file: os.PathLike[str] | str,
                 password: str) -> bool:
    """Decrypt a file and return True when the unauthenticated legacy format was used."""

    input_path, output_path = _validate_paths(input_file, output_file)
    with input_path.open("rb") as input_handle:
        magic = input_handle.read(len(MAGIC))

    if magic == MAGIC:
        _decrypt_current(input_path, output_path, password)
        return False

    _decrypt_legacy(input_path, output_path, password)
    return True
