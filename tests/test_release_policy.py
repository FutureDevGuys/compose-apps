from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/publish-portable.yml"
WORKFLOW_POLICY = ROOT / "WORKFLOW-POLICY.md"
VERIFICATION = ROOT / "VERIFICATION.md"


def job_block(text: str, name: str) -> str:
    match = re.search(
        rf"^  {re.escape(name)}:\n(?P<body>(?:^(?:    .*|\s*)$\n?)*)",
        text,
        flags=re.MULTILINE,
    )
    if match is None:
        raise AssertionError(f"workflow job is missing: {name}")
    return match.group(0)


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
        self.assertIn("sparse-checkout-cone-mode: false", text)
        export_calls = re.findall(
            r"python3 source/scripts/export_portable\.py \\\n(?:\s+--[^\n]+\n?)+",
            text,
        )
        self.assertEqual(2, len(export_calls))
        for export_call in export_calls:
            self.assertNotIn("--source-commit", export_call)
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

    def test_build_and_publish_authorities_are_separate(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        build = job_block(text, "build")
        publish = job_block(text, "publish")

        self.assertIn("contents: read", build)
        self.assertNotIn("contents: write", build)
        self.assertNotIn("id-token: write", build)
        self.assertNotIn("attestations: write", build)
        self.assertIn("actions/create-github-app-token@", build)
        self.assertIn("source/scripts/export_portable.py", build)
        self.assertIn("actions/upload-artifact@", build)

        self.assertIn("needs: build", publish)
        self.assertIn("contents: write", publish)
        self.assertIn("id-token: write", publish)
        self.assertIn("attestations: write", publish)
        self.assertIn("actions/download-artifact@", publish)
        self.assertNotIn("actions/create-github-app-token@", publish)
        self.assertNotIn("actions/checkout@", publish)
        self.assertNotIn("HOMELAB_SOURCE_APP", publish)
        self.assertNotIn("source/scripts/", publish)

    def test_shelf_cleanliness_is_proved_before_nested_source_checkout(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        shelf_checkout = text.index("- name: Check out exact shelf policy")
        shelf_proof = text.index("- name: Prove exact shelf policy")
        source_checkout = text.index("- name: Check out exact portable source")
        self.assertLess(shelf_checkout, shelf_proof)
        self.assertLess(shelf_proof, source_checkout)
        proof_block = text[shelf_proof:source_checkout]
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', proof_block)
        self.assertIn('test -z "$(git status --porcelain=v1)"', proof_block)

    def test_publication_reserves_tag_and_rereads_the_release(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        publish = job_block(text, "publish")
        create_ref = publish.index('--method POST "repos/$GITHUB_REPOSITORY/git/refs"')
        create_release = publish.index('gh release create "$SOURCE_TAG"')
        publish_release = publish.index('gh release edit "$SOURCE_TAG"')
        final_verification = publish.index("- name: Verify published immutable release")
        self.assertLess(create_ref, create_release)
        self.assertLess(create_release, publish_release)
        self.assertLess(publish_release, final_verification)
        self.assertIn('--raw-field ref="refs/tags/$SOURCE_TAG"', publish)
        self.assertIn('--raw-field sha="$GITHUB_SHA"', publish)
        self.assertIn('X-GitHub-Api-Version: 2026-03-10', publish)
        self.assertIn("--verify-tag", publish)
        self.assertNotIn('--target "$GITHUB_SHA"', publish)
        final = publish[final_verification:]
        self.assertIn('git/ref/tags/$SOURCE_TAG', final)
        self.assertIn('releases/tags/$SOURCE_TAG', final)
        self.assertIn(".draft == false", final)
        self.assertIn(".immutable == true", final)
        self.assertIn(".assets[]", final)
        self.assertIn("published-download", final)
        self.assertIn("SOURCE_COMMIT", final)
        self.assertIn(".source == {repository: $repository, tag: $tag, commit: $commit}", final)

    def test_publication_uses_an_explicit_canonical_asset_set(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        for suffix in (
            ".tar.gz",
            ".zip",
            ".manifest.json",
            ".spdx.json",
        ):
            self.assertIn(f"compose-apps-$VERSION{suffix}", text)
        self.assertIn("SHA256SUMS", text)
        self.assertNotIn("dist/*", text)
        self.assertIn("scripts/validate_release_assets.py", text)

    def test_release_catalog_is_github_releases_not_a_mutable_tracked_file(self) -> None:
        self.assertFalse((ROOT / "releases.json").exists())

    def test_documentation_describes_asset_and_authority_boundaries(self) -> None:
        policy = WORKFLOW_POLICY.read_text(encoding="utf-8")
        verification = VERIFICATION.read_text(encoding="utf-8")
        self.assertIn("five canonical release assets", policy)
        self.assertIn("build job", policy)
        self.assertIn("publish job", policy)
        self.assertIn("reserves the shelf tag", policy)
        self.assertIn("immutable release setting", policy)
        self.assertIn("four payload assets", verification)
        self.assertIn("archive contents", verification)
        self.assertNotIn("archive must be listed in the same release's canonical manifest", verification)

    def test_admin_preflights_immutability_without_broadening_workflow(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        policy = WORKFLOW_POLICY.read_text(encoding="utf-8")

        self.assertIn(
            "repos/FutureDevGuys/compose-apps/immutable-releases",
            policy,
        )
        self.assertIn("Administration(read)", policy)
        self.assertIn("before merge and immediately before every dispatch", policy)
        self.assertIn("do not dispatch", policy.lower())
        self.assertIn(".immutable == true", workflow)
        self.assertNotIn("administration:", workflow.lower())

    def test_documentation_states_the_mutable_draft_window(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        policy = WORKFLOW_POLICY.read_text(encoding="utf-8")
        combined = f"{workflow}\n{policy}".lower()

        self.assertNotIn("atomic", combined)
        self.assertNotIn("failure-safe", combined)
        self.assertIn("draft release, its tag, and its assets remain mutable", policy)
        self.assertIn("publication window", policy)
        self.assertIn("no concurrent contents-write actor", policy)
        self.assertIn("burns the attempted version", policy)


if __name__ == "__main__":
    unittest.main()
