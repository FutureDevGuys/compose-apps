# Artifact verification

Select an explicit `portable-vX.Y.Z` release and download `SHA256SUMS` with the chosen archive. Verify the checksum before extraction:

```sh
sha256sum --check --ignore-missing SHA256SUMS
```

The release contains exactly five assets: tar, zip, canonical manifest, SPDX SBOM, and `SHA256SUMS`. The checksum file enumerates the four payload assets other than itself. The manifest identifies the exact signed `FutureDevGuys/homelab` source repository, tag, and commit and enumerates the exact regular-file archive contents; both archives and the SPDX file inventory must agree with it. Verify GitHub's artifact attestation against `FutureDevGuys/compose-apps/.github/workflows/publish-portable.yml@refs/heads/main`. Stop if the release asset set, checksum inventory, archive contents, SPDX inventory, manifest identity, provenance, source repository, source tag, source commit, workflow path, workflow ref, or attestation identity differs.

Extract into a new directory. Do not merge a bundle over an existing application directory. Review the bundled application README and `.env.example`, create local-only credentials where required, and render the Compose model before launch.
