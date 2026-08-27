import tempfile
import unittest
import zipfile
from pathlib import Path

from archive_core import ArchiveError, create_zip, extract_zip


class ArchiveCoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_multiple_files_round_trip(self):
        first = self.root / "first.txt"
        second = self.root / "second.bin"
        first.write_text("hello", encoding="utf-8")
        second.write_bytes(bytes(range(256)))
        archive = self.root / "bundle.zip"

        checksum = create_zip([first, second], archive, compression_level=6)
        recovered = self.root / "recovered"
        extract_zip(archive, recovered)

        self.assertEqual(len(checksum), 64)
        self.assertEqual((recovered / "first.txt").read_text(encoding="utf-8"), "hello")
        self.assertEqual((recovered / "second.bin").read_bytes(), bytes(range(256)))

    def test_duplicate_basenames_are_preserved(self):
        left = self.root / "left"
        right = self.root / "right"
        left.mkdir()
        right.mkdir()
        (left / "same.txt").write_text("left", encoding="utf-8")
        (right / "same.txt").write_text("right", encoding="utf-8")
        archive = self.root / "duplicates.zip"

        create_zip([left / "same.txt", right / "same.txt"], archive)

        with zipfile.ZipFile(archive) as handle:
            self.assertEqual(handle.namelist(), ["same.txt", "same_1.txt"])

    def test_path_traversal_is_rejected(self):
        archive = self.root / "unsafe.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("../outside.txt", "blocked")

        with self.assertRaises(ArchiveError):
            extract_zip(archive, self.root / "output")

        self.assertFalse((self.root / "outside.txt").exists())


if __name__ == "__main__":
    unittest.main()
