from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_release_assets.py"
SPEC = importlib.util.spec_from_file_location("validate_release_assets", VALIDATOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("release asset validator cannot be loaded")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)

VERSION = "v1.2.3"
SOURCE_REPO = "FutureDevGuys/homelab"
SOURCE_TAG = f"portable-{VERSION}"
SOURCE_COMMIT = "a" * 40
ROOT_NAME = f"compose-apps-{VERSION}"
PAYLOAD_PATH = "apps/example/compose.yaml"
PAYLOAD = b"services: {}\n"


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def canonical(document: object) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def tar_payload() -> bytes:
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            info = tarfile.TarInfo(f"{ROOT_NAME}/{PAYLOAD_PATH}")
            info.size = len(PAYLOAD)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(PAYLOAD))
    return raw.getvalue()


def zip_payload() -> bytes:
    raw = io.BytesIO()
    with zipfile.ZipFile(raw, mode="w") as archive:
        archive.writestr(f"{ROOT_NAME}/{PAYLOAD_PATH}", PAYLOAD)
    return raw.getvalue()


def write_valid_release(directory: Path) -> None:
    manifest = {
        "schema": "compose-apps-release-manifest-v1",
        "version": VERSION,
        "source": {
            "repository": SOURCE_REPO,
            "tag": SOURCE_TAG,
            "commit": SOURCE_COMMIT,
        },
        "files": [
            {"path": PAYLOAD_PATH, "sha256": digest(PAYLOAD), "size": len(PAYLOAD)}
        ],
    }
    sbom = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": ROOT_NAME,
        "files": [
            {
                "SPDXID": "SPDXRef-File-1",
                "fileName": f"./{PAYLOAD_PATH}",
                "checksums": [{"algorithm": "SHA256", "checksumValue": digest(PAYLOAD)}],
            }
        ],
    }
    payloads = {
        f"{ROOT_NAME}.tar.gz": tar_payload(),
        f"{ROOT_NAME}.zip": zip_payload(),
        f"{ROOT_NAME}.manifest.json": canonical(manifest),
        f"{ROOT_NAME}.spdx.json": canonical(sbom),
    }
    for name, payload in payloads.items():
        (directory / name).write_bytes(payload)
    (directory / "SHA256SUMS").write_text(
        "".join(f"{digest(payloads[name])}  {name}\n" for name in sorted(payloads)),
        encoding="utf-8",
    )


def rewrite_sums(directory: Path) -> None:
    payload_names = sorted(path.name for path in directory.iterdir() if path.name != "SHA256SUMS")
    (directory / "SHA256SUMS").write_text(
        "".join(f"{digest((directory / name).read_bytes())}  {name}\n" for name in payload_names),
        encoding="utf-8",
    )


class ReleaseAssetTests(unittest.TestCase):
    def validate(self, directory: Path) -> None:
        VALIDATOR.validate_release(
            directory=directory,
            version=VERSION,
            source_repo=SOURCE_REPO,
            source_tag=SOURCE_TAG,
            source_commit=SOURCE_COMMIT,
        )

    def test_accepts_exact_source_bound_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            self.validate(directory)

    def test_rejects_extra_or_missing_release_assets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            (directory / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "release asset set"):
                self.validate(directory)

        for missing in (
            f"{ROOT_NAME}.manifest.json",
            f"{ROOT_NAME}.spdx.json",
        ):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                write_valid_release(directory)
                (directory / missing).unlink()
                with self.assertRaisesRegex(ValueError, "release asset set"):
                    self.validate(directory)

    def test_rejects_source_identity_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            manifest_path = directory / f"{ROOT_NAME}.manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["source"]["commit"] = "b" * 40
            manifest_path.write_bytes(canonical(manifest))
            rewrite_sums(directory)
            with self.assertRaisesRegex(ValueError, "source identity"):
                self.validate(directory)

    def test_rejects_checksum_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            sums = directory / "SHA256SUMS"
            sums.write_text(sums.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "checksum inventory"):
                self.validate(directory)

    def test_rejects_manifest_archive_or_spdx_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            archive_path = directory / f"{ROOT_NAME}.zip"
            with zipfile.ZipFile(archive_path, mode="w") as archive:
                archive.writestr(f"{ROOT_NAME}/{PAYLOAD_PATH}", b"tampered\n")
            rewrite_sums(directory)
            with self.assertRaisesRegex(ValueError, "archive payload"):
                self.validate(directory)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_valid_release(directory)
            sbom_path = directory / f"{ROOT_NAME}.spdx.json"
            sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
            sbom["files"] = []
            sbom_path.write_bytes(canonical(sbom))
            rewrite_sums(directory)
            with self.assertRaisesRegex(ValueError, "SPDX file inventory"):
                self.validate(directory)


if __name__ == "__main__":
    unittest.main()
