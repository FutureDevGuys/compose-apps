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


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/verify_release.py"
spec = importlib.util.spec_from_file_location("verify_release", SCRIPT)
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class ReleaseVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.version = "v1.2.3"
        self.commit = "a" * 40
        self.shelf_commit = "b" * 40
        self.relative = "apps/example/compose.yaml"
        self.body = b"services: {}\n"
        stem = "compose-apps-" + self.version
        prefix = stem + "/"
        manifest = {"schema": "compose-apps-release-manifest-v1", "version": self.version,
                    "source": {"repository": "FutureDevGuys/homelab",
                               "tag": "portable-" + self.version, "commit": self.commit},
                    "files": [{"path": self.relative, "size": len(self.body),
                               "sha256": hashlib.sha256(self.body).hexdigest()}]}
        spdx = {"spdxVersion": "SPDX-2.3", "files": [{"fileName": "./" + self.relative,
                                                        "checksums": [{"algorithm": "SHA256",
                                                                       "checksumValue": hashlib.sha256(self.body).hexdigest()}]}]}
        raw = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                member = tarfile.TarInfo(prefix + self.relative)
                member.size, member.mode, member.uid, member.gid, member.mtime = len(self.body), 0o644, 0, 0, 0
                archive.addfile(member, io.BytesIO(self.body))
        payloads = {stem + ".tar.gz": raw.getvalue(),
                    stem + ".manifest.json": (json.dumps(manifest) + "\n").encode(),
                    stem + ".spdx.json": (json.dumps(spdx) + "\n").encode()}
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, mode="w") as archive:
            member = zipfile.ZipInfo(prefix + self.relative, date_time=(1980, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, self.body)
        payloads[stem + ".zip"] = raw.getvalue()
        checksums = "".join(hashlib.sha256(payloads[name]).hexdigest() + "  " + name + "\n"
                            for name in sorted(payloads))
        payloads["SHA256SUMS"] = checksums.encode()
        for name, data in payloads.items():
            (self.root / name).write_bytes(data)

    def tearDown(self):
        self.temp.cleanup()

    def release(self, *, draft, immutable):
        assets = []
        for name in verify.expected_names(self.version):
            data = (self.root / name).read_bytes()
            assets.append({"name": name, "state": "uploaded", "size": len(data),
                           "digest": "sha256:" + hashlib.sha256(data).hexdigest()})
        return {"tag_name": self.version, "target_commitish": self.shelf_commit,
                "draft": draft, "immutable": immutable, "assets": assets}

    def test_exact_build_and_both_release_states(self):
        result = verify.verify_artifacts(self.root, self.version, self.commit)
        self.assertEqual(result["files"], 1)
        verify.verify_release(self.release(draft=True, immutable=False), self.root,
                              self.version, self.shelf_commit, True, False)
        verify.verify_release(self.release(draft=False, immutable=True), self.root,
                              self.version, self.shelf_commit, False, True)

    def test_changed_archive_is_rejected_by_checksum_manifest(self):
        artifact = self.root / ("compose-apps-" + self.version + ".zip")
        artifact.write_bytes(artifact.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "checksum_manifest_differs"):
            verify.verify_artifacts(self.root, self.version, self.commit)

    def test_missing_asset_or_immutability_is_rejected(self):
        release = self.release(draft=False, immutable=False)
        with self.assertRaisesRegex(ValueError, "published_release_not_immutable"):
            verify.verify_release(release, self.root, self.version, self.shelf_commit, False, True)
        release = self.release(draft=False, immutable=True)
        release["assets"].pop()
        with self.assertRaisesRegex(ValueError, "release_asset_set_differs"):
            verify.verify_release(release, self.root, self.version, self.shelf_commit, False, True)


if __name__ == "__main__":
    unittest.main()
