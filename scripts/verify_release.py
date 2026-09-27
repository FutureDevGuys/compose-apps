#!/usr/bin/env python3
"""Verify the exact portable build and optional GitHub Release readback."""

import argparse
import hashlib
import io
import json
import re
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+")
COMMIT = re.compile(r"[0-9a-f]{40}")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_names(version: str) -> tuple[str, ...]:
    stem = "compose-apps-" + version
    return ("SHA256SUMS", stem + ".manifest.json", stem + ".spdx.json",
            stem + ".tar.gz", stem + ".zip")


def verify_artifacts(directory: Path, version: str, source_commit: str | None) -> dict:
    require(VERSION.fullmatch(version) is not None, "invalid_release_version")
    names = expected_names(version)
    require(directory.is_dir() and not directory.is_symlink(), "artifact_directory_invalid")
    found = sorted(path.name for path in directory.iterdir())
    require(found == sorted(names), "artifact_set_differs")
    for name in names:
        path = directory / name
        require(path.is_file() and not path.is_symlink(), "artifact_type_invalid")
    payloads = {name: (directory / name).read_bytes() for name in names}
    checksum_names = sorted(name for name in names if name != "SHA256SUMS")
    expected_sums = "".join(f"{sha256(payloads[name])}  {name}\n" for name in checksum_names).encode()
    require(payloads["SHA256SUMS"] == expected_sums, "checksum_manifest_differs")
    manifest = json.loads(payloads["compose-apps-" + version + ".manifest.json"])
    require(manifest.get("schema") == "compose-apps-release-manifest-v1" and
            manifest.get("version") == version, "source_manifest_invalid")
    source = manifest.get("source") or {}
    require(source.get("repository") == "FutureDevGuys/homelab" and
            source.get("tag") == "portable-" + version and
            COMMIT.fullmatch(source.get("commit", "")) is not None,
            "source_identity_invalid")
    if source_commit is not None:
        require(source["commit"] == source_commit, "source_commit_differs")
    listed = manifest.get("files")
    require(isinstance(listed, list) and bool(listed), "portable_file_inventory_empty")
    paths = []
    for row in listed:
        require(isinstance(row, dict) and isinstance(row.get("path"), str), "portable_file_invalid")
        path = PurePosixPath(row["path"])
        require(not path.is_absolute() and ".." not in path.parts and
                path.as_posix() == row["path"] and row["path"] not in paths,
                "portable_path_unsafe_or_duplicate")
        require(re.fullmatch(r"[0-9a-f]{64}", row.get("sha256", "")) is not None and
                isinstance(row.get("size"), int) and row["size"] >= 0,
                "portable_file_digest_invalid")
        paths.append(row["path"])
    require(paths == sorted(paths), "portable_file_order_changed")
    prefix = "compose-apps-" + version + "/"
    tar_payloads = {}
    with tarfile.open(fileobj=io.BytesIO(payloads[prefix[:-1] + ".tar.gz"]), mode="r:gz") as archive:
        for member in archive:
            require(member.isfile() and member.name.startswith(prefix) and
                    member.mode == 0o644 and member.uid == 0 and member.gid == 0 and member.mtime == 0,
                    "tar_member_invalid")
            relative = member.name.removeprefix(prefix)
            require(relative not in tar_payloads, "tar_member_duplicate")
            source_file = archive.extractfile(member)
            require(source_file is not None, "tar_file_unreadable")
            tar_payloads[relative] = source_file.read()
    zip_payloads = {}
    with zipfile.ZipFile(io.BytesIO(payloads[prefix[:-1] + ".zip"])) as archive:
        require(archive.testzip() is None, "zip_integrity_failed")
        for member in archive.infolist():
            require(not member.is_dir() and member.filename.startswith(prefix) and
                    member.date_time == (1980, 1, 1, 0, 0, 0) and
                    (member.external_attr >> 16) == 0o100644,
                    "zip_member_invalid")
            relative = member.filename.removeprefix(prefix)
            require(relative not in zip_payloads, "zip_member_duplicate")
            zip_payloads[relative] = archive.read(member)
    require(sorted(tar_payloads) == paths and sorted(zip_payloads) == paths,
            "archive_file_inventory_differs")
    for row in listed:
        data = tar_payloads[row["path"]]
        require(data == zip_payloads[row["path"]] and len(data) == row["size"] and
                sha256(data) == row["sha256"], "portable_file_content_differs")
    spdx = json.loads(payloads[prefix[:-1] + ".spdx.json"])
    spdx_files = spdx.get("files")
    require(spdx.get("spdxVersion") == "SPDX-2.3" and isinstance(spdx_files, list) and
            len(spdx_files) == len(listed), "spdx_inventory_differs")
    for row, expected in zip(spdx_files, listed):
        require(row.get("fileName") == "./" + expected["path"] and
                row.get("checksums") == [{"algorithm": "SHA256", "checksumValue": expected["sha256"]}],
                "spdx_file_digest_differs")
    return {"version": version, "source_commit": source["commit"], "files": len(paths),
            "artifacts": len(names)}


def verify_release(document: dict, directory: Path, version: str, commit: str,
                   expect_draft: bool, expect_immutable: bool) -> None:
    require(COMMIT.fullmatch(commit) is not None, "expected_shelf_commit_invalid")
    require(document.get("tag_name") == version and document.get("target_commitish") == commit,
            "release_target_differs")
    require(document.get("draft") is expect_draft, "release_draft_state_differs")
    if expect_immutable:
        require(document.get("immutable") is True, "published_release_not_immutable")
    assets = document.get("assets")
    require(isinstance(assets, list) and len(assets) == 5, "release_asset_set_differs")
    names = expected_names(version)
    require(all(isinstance(asset, dict) and isinstance(asset.get("name"), str) for asset in assets) and
            sorted(asset["name"] for asset in assets) == sorted(names), "release_asset_names_differ")
    for asset in assets:
        path = directory / asset["name"]
        require(asset.get("state") == "uploaded" and asset.get("size") == path.stat().st_size and
                asset.get("digest") == "sha256:" + sha256(path.read_bytes()),
                "release_asset_digest_differs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--release-json", type=Path)
    parser.add_argument("--expected-commit")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--expect-draft", action="store_true")
    group.add_argument("--expect-published-immutable", action="store_true")
    args = parser.parse_args()
    result = verify_artifacts(args.artifact_dir, args.version, args.source_commit)
    if args.release_json:
        require(args.expected_commit is not None and
                (args.expect_draft or args.expect_published_immutable),
                "release_expectation_missing")
        verify_release(json.loads(args.release_json.read_text()), args.artifact_dir,
                       args.version, args.expected_commit, args.expect_draft,
                       args.expect_published_immutable)
        result["release_readback"] = "draft" if args.expect_draft else "published_immutable"
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
