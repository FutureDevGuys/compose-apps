# Release workflow policy

Only the private `FutureDevGuys/homelab` source repository publishes releases. This shelf has no source build, package update, pull-request deployment, mutable mirror, or general automation workflow.

An explicit signed `portable-vX.Y.Z` source tag produces deterministic tar and zip archives, a canonical manifest, `SHA256SUMS`, an SPDX SBOM, and signed build provenance. The publisher authenticates through a dedicated GitHub App restricted to this repository and release publication. Ordinary workstation automation cannot use its key.

A release version is immutable. Failed publication leaves prior versions unchanged, and a correction uses a higher version. The release catalog changes only after every artifact is uploaded and independently downloadable and verifiable.
