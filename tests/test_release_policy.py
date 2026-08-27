from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish-portable.yml"


class ReleasePolicyTests(unittest.TestCase):
    def test_public_workflow_binds_signed_private_source_and_fails_closed(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("push:", text)
        self.assertIn("github.ref == 'refs/heads/main'", text)
        self.assertIn("commits/main", text)
        self.assertIn('= "$GITHUB_SHA"', text)
        self.assertIn("FutureDevGuys/homelab", text)
        self.assertIn(".verification.verified", text)
        self.assertIn("object.type' <<<\"$ref\")\" = tag", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("sparse-checkout:", text)
        self.assertNotIn("--source-commit", text)
        self.assertIn("diff -qr dist dist-repeat", text)
        self.assertIn("actions/attest@", text)
        self.assertIn("--draft", text)
        self.assertIn("diff -qr dist downloaded", text)
        self.assertIn("--draft=false", text)

    def test_publisher_has_no_homelab_decryption_input(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8").lower()
        for forbidden in ("sops", "age_identity", "git-crypt", "decrypt"):
            self.assertNotIn(forbidden, text)

    def test_actions_are_commit_pinned_and_source_token_is_read_only(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn("permission-contents: read", text)

    def test_release_catalog_is_github_releases_not_a_mutable_tracked_file(self) -> None:
        self.assertFalse((ROOT / "releases.json").exists())


if __name__ == "__main__":
    unittest.main()
