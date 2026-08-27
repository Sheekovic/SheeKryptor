"""Safe, standard ZIP archive operations for SheeKryptor."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from pathlib import Path
from typing import Callable, Iterable


class ArchiveError(Exception):
    """Raised when an archive cannot be created or safely extracted."""


def _unique_archive_name(path: Path, used_names: set[str]) -> str:
    name = path.name
    stem = path.stem
    suffix = path.suffix
    counter = 1
    while name.casefold() in used_names:
        name = f"{stem}_{counter}{suffix}"
        counter += 1
    used_names.add(name.casefold())
    return name


def create_zip(
    input_files: Iterable[os.PathLike[str] | str],
    output_file: os.PathLike[str] | str,
    compression_level: int = 9,
    progress: Callable[[float], None] | None = None,
) -> str:
    """Create a ZIP archive and return its SHA-256 checksum."""

    paths = [Path(item) for item in input_files if str(item).strip()]
    if not paths:
        raise ArchiveError("Choose at least one input file.")
    if any(not path.is_file() for path in paths):
        raise ArchiveError("Every selected input must be an existing file.")
    if not 0 <= compression_level <= 9:
        raise ArchiveError("Compression level must be between 0 and 9.")

    output_path = Path(output_file)
    if not output_path.name:
        raise ArchiveError("Choose an output archive path.")
    if output_path.suffix.lower() != ".zip":
        output_path = output_path.with_name(f"{output_path.name}.zip")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    temporary_path = output_path.with_name(f".{output_path.name}.tmp")
    used_names: set[str] = set()
    try:
        with zipfile.ZipFile(
            temporary_path,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=compression_level,
            allowZip64=True,
        ) as archive:
            for index, path in enumerate(paths, start=1):
                archive.write(path, arcname=_unique_archive_name(path, used_names))
                if progress:
                    progress(index / len(paths) * 100)
        os.replace(temporary_path, output_path)
    except (OSError, zipfile.BadZipFile) as exc:
        temporary_path.unlink(missing_ok=True)
        raise ArchiveError(f"Could not create the archive: {exc}") from exc

    digest = hashlib.sha256()
    with output_path.open("rb") as archive_handle:
        while chunk := archive_handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def extract_zip(
    input_file: os.PathLike[str] | str,
    output_dir: os.PathLike[str] | str,
) -> list[Path]:
    """Safely extract a ZIP archive, rejecting traversal paths and symlinks."""

    input_path = Path(input_file)
    if not input_path.is_file():
        raise ArchiveError("Choose an existing ZIP archive.")
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    destination_root = destination.resolve()

    try:
        with zipfile.ZipFile(input_path, "r") as archive:
            members = archive.infolist()
            for member in members:
                member_path = (destination / member.filename).resolve()
                try:
                    member_path.relative_to(destination_root)
                except ValueError as exc:
                    raise ArchiveError(
                        f"Unsafe archive path rejected: {member.filename}"
                    ) from exc
                unix_mode = member.external_attr >> 16
                if stat.S_ISLNK(unix_mode):
                    raise ArchiveError(
                        f"Archive symlink rejected: {member.filename}"
                    )

            bad_member = archive.testzip()
            if bad_member:
                raise ArchiveError(f"Archive checksum failed: {bad_member}")
            archive.extractall(destination)
            return [destination / member.filename for member in members]
    except zipfile.BadZipFile as exc:
        raise ArchiveError("The selected file is not a valid ZIP archive.") from exc
