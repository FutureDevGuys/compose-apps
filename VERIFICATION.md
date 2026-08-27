# Artifact verification

Select an explicit `portable-vX.Y.Z` release and download `SHA256SUMS` with the chosen archive. Verify the checksum before extraction:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The archive must be listed in the same release's canonical manifest and provenance subjects. The manifest identifies the exact signed `FutureDevGuys/homelab` source tag and commit. Verify GitHub's artifact attestation against `FutureDevGuys/compose-apps/.github/workflows/publish-portable.yml@refs/heads/main`. Stop if the checksum, manifest, provenance, source repository, source tag, source commit, workflow path, workflow ref, or attestation identity differs.

Extract into a new directory. Do not merge a bundle over an existing application directory. Review the bundled application README and `.env.example`, create local-only credentials where required, and render the Compose model before launch.
