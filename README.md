# Compose Apps

This public repository is an immutable release shelf for portable Docker Compose applications built from the private `FutureDevGuys/homelab` source repository. It does not accept source changes or act as a mutable mirror.

Use a versioned `portable-vX.Y.Z` release. Download the tar or zip bundle plus `SHA256SUMS`, verify the selected artifact digest, verify the attached provenance, extract into a clean directory, and follow the application README inside the bundle. Do not use an unversioned URL or treat GitHub's latest-release pointer as a trust decision.

- [Artifact verification](VERIFICATION.md)
- [Release workflow policy](WORKFLOW-POLICY.md)
- [Security policy](SECURITY.md)
- [Machine-readable release catalog](releases.json)

Portable bundles contain no homelab hostnames, private networks, provider metadata, encrypted inputs, real credentials, external homelab networks, or files outside the archive. Each supported application runs through ordinary Docker Compose from its extracted directory.
