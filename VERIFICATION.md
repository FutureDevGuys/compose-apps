# Artifact verification

Select an explicit `portable-vX.Y.Z` release and download `SHA256SUMS` with the chosen archive. Verify the checksum before extraction:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The archive must be listed in the same release's canonical manifest and provenance subjects. Verify GitHub's artifact attestation against `FutureDevGuys/homelab` and the exact source tag when the release includes the required attestation. Stop if the checksum, manifest, provenance, source repository, source tag, or attestation identity differs.

Extract into a new directory. Do not merge a bundle over an existing application directory. Review the bundled application README and `.env.example`, create local-only credentials where required, and render the Compose model before launch.
