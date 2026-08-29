#!/usr/bin/env python3
"""Validate the exact public portable-release asset contract."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
import tarfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


VERSION = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
DIGEST = re.compile(r"^[0-9a-f]{64}$")
CHECKSUM_ROW = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def release_names(version: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not VERSION.fullmatch(version):
        raise ValueError("version must be vMAJOR.MINOR.PATCH with an optional prerelease suffix")
    stem = f"compose-apps-{version}"
    payloads = tuple(
        sorted(
            (
                f"{stem}.tar.gz",
                f"{stem}.zip",
                f"{stem}.manifest.json",
                f"{stem}.spdx.json",
            )
        )
    )
    return payloads, tuple(sorted((*payloads, "SHA256SUMS")))


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"invalid JSON asset: {path.name}") from error
    if not isinstance(document, dict):
        raise ValueError(f"JSON asset must be an object: {path.name}")
    return document


def validate_asset_set(directory: Path, expected: tuple[str, ...]) -> None:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("release asset directory must be a real directory")
    entries = sorted(directory.iterdir(), key=lambda path: path.name)
    actual = tuple(path.name for path in entries)
    if actual != expected:
        raise ValueError("release asset set does not equal the canonical allowlist")
    for path in entries:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"release asset must be a regular non-symlink file: {path.name}")


def validate_checksums(directory: Path, payload_names: tuple[str, ...]) -> None:
    rows: dict[str, str] = {}
    try:
        lines = (directory / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as error:
        raise ValueError("invalid SHA256SUMS") from error
    for line in lines:
        match = CHECKSUM_ROW.fullmatch(line)
        if match is None:
            raise ValueError("SHA256SUMS has a noncanonical row")
        digest, name = match.groups()
        if name in rows:
            raise ValueError("SHA256SUMS has a duplicate asset")
        rows[name] = digest
    if tuple(sorted(rows)) != payload_names:
        raise ValueError("checksum inventory does not equal the canonical payload set")
    for name in payload_names:
        if sha256((directory / name).read_bytes()) != rows[name]:
            raise ValueError(f"checksum mismatch: {name}")


def manifest_files(document: dict[str, Any]) -> dict[str, tuple[str, int]]:
    rows = document.get("files")
    if not isinstance(rows, list) or not rows:
        raise ValueError("manifest file inventory must be a nonempty list")
    files: dict[str, tuple[str, int]] = {}
    ordered_paths: list[str] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size"}:
            raise ValueError("manifest file row has an invalid schema")
        name = row["path"]
        digest = row["sha256"]
        size = row["size"]
        if not isinstance(name, str):
            raise ValueError("manifest file path must be a string")
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or any(part in ("", ".", "..") for part in path.parts):
            raise ValueError("manifest file path must be relative and nonescaping")
        if not isinstance(digest, str) or DIGEST.fullmatch(digest) is None:
            raise ValueError(f"manifest file digest is invalid: {name}")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError(f"manifest file size is invalid: {name}")
        if name in files:
            raise ValueError(f"manifest file inventory has a duplicate: {name}")
        files[name] = (digest, size)
        ordered_paths.append(name)
    if ordered_paths != sorted(ordered_paths):
        raise ValueError("manifest file inventory must use canonical path order")
    return files


def validate_manifest(
    path: Path,
    *,
    version: str,
    source_repo: str,
    source_tag: str,
    source_commit: str,
) -> dict[str, tuple[str, int]]:
    document = read_json_object(path)
    if document.get("schema") != "compose-apps-release-manifest-v1":
        raise ValueError("manifest schema is invalid")
    if document.get("version") != version:
        raise ValueError("manifest version is invalid")
    expected_source = {
        "repository": source_repo,
        "tag": source_tag,
        "commit": source_commit,
    }
    if document.get("source") != expected_source:
        raise ValueError("manifest source identity does not equal the requested source")
    return manifest_files(document)


def validate_archive_payload(
    name: str,
    payload: bytes,
    expected: tuple[str, int],
) -> None:
    digest, size = expected
    if len(payload) != size or sha256(payload) != digest:
        raise ValueError(f"archive payload does not match the manifest: {name}")


def validate_tar(path: Path, version: str, files: dict[str, tuple[str, int]]) -> None:
    prefix = f"compose-apps-{version}/"
    seen: set[str] = set()
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    raise ValueError("tar archive contains a non-regular entry")
                if not member.name.startswith(prefix):
                    raise ValueError("tar archive entry is outside the versioned root")
                name = member.name.removeprefix(prefix)
                if name in seen or name not in files:
                    raise ValueError("tar archive inventory does not equal the manifest")
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(f"tar archive payload cannot be read: {name}")
                validate_archive_payload(name, extracted.read(), files[name])
                seen.add(name)
    except (OSError, tarfile.TarError) as error:
        raise ValueError("invalid tar release asset") from error
    if seen != set(files):
        raise ValueError("tar archive inventory does not equal the manifest")


def validate_zip(path: Path, version: str, files: dict[str, tuple[str, int]]) -> None:
    prefix = f"compose-apps-{version}/"
    seen: set[str] = set()
    try:
        with zipfile.ZipFile(path, mode="r") as archive:
            for info in archive.infolist():
                mode = (info.external_attr >> 16) & 0xFFFF
                file_type = stat.S_IFMT(mode)
                if info.is_dir() or file_type not in (0, stat.S_IFREG):
                    raise ValueError("zip archive contains a non-regular entry")
                if not info.filename.startswith(prefix):
                    raise ValueError("zip archive entry is outside the versioned root")
                name = info.filename.removeprefix(prefix)
                if name in seen or name not in files:
                    raise ValueError("zip archive inventory does not equal the manifest")
                validate_archive_payload(name, archive.read(info), files[name])
                seen.add(name)
    except (OSError, zipfile.BadZipFile) as error:
        raise ValueError("invalid zip release asset") from error
    if seen != set(files):
        raise ValueError("zip archive inventory does not equal the manifest")


def validate_spdx(path: Path, version: str, files: dict[str, tuple[str, int]]) -> None:
    document = read_json_object(path)
    if document.get("SPDXID") != "SPDXRef-DOCUMENT" or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("SPDX document identity is invalid")
    if document.get("name") != f"compose-apps-{version}":
        raise ValueError("SPDX document name is invalid")
    rows = document.get("files")
    if not isinstance(rows, list):
        raise ValueError("SPDX file inventory must be a list")
    spdx_files: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("SPDX file row must be an object")
        file_name = row.get("fileName")
        if not isinstance(file_name, str) or not file_name.startswith("./"):
            raise ValueError("SPDX file name is invalid")
        name = file_name.removeprefix("./")
        checksums = row.get("checksums")
        if not isinstance(checksums, list) or len(checksums) != 1:
            raise ValueError(f"SPDX checksum inventory is invalid: {name}")
        checksum = checksums[0]
        if not isinstance(checksum, dict) or checksum.get("algorithm") != "SHA256":
            raise ValueError(f"SPDX checksum algorithm is invalid: {name}")
        value = checksum.get("checksumValue")
        if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
            raise ValueError(f"SPDX checksum value is invalid: {name}")
        if name in spdx_files:
            raise ValueError(f"SPDX file inventory has a duplicate: {name}")
        spdx_files[name] = value
    expected = {name: digest for name, (digest, _size) in files.items()}
    if spdx_files != expected:
        raise ValueError("SPDX file inventory does not equal the manifest")


def validate_release(
    *,
    directory: Path,
    version: str,
    source_repo: str,
    source_tag: str,
    source_commit: str,
) -> None:
    if source_repo != "FutureDevGuys/homelab":
        raise ValueError("source repository is not canonical")
    if source_tag != f"portable-{version}":
        raise ValueError("source tag does not match the release version")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise ValueError("source commit must be an exact SHA-1 object ID")
    payload_names, asset_names = release_names(version)
    validate_asset_set(directory, asset_names)
    validate_checksums(directory, payload_names)
    stem = f"compose-apps-{version}"
    files = validate_manifest(
        directory / f"{stem}.manifest.json",
        version=version,
        source_repo=source_repo,
        source_tag=source_tag,
        source_commit=source_commit,
    )
    validate_tar(directory / f"{stem}.tar.gz", version, files)
    validate_zip(directory / f"{stem}.zip", version, files)
    validate_spdx(directory / f"{stem}.spdx.json", version, files)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-repo", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-commit", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        validate_release(
            directory=args.directory.resolve(),
            version=args.version,
            source_repo=args.source_repo,
            source_tag=args.source_tag,
            source_commit=args.source_commit,
        )
    except ValueError as error:
        print(f"release asset validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
