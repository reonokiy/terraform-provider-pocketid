# Releasing `reonokiy/pocketid`

The GitHub Release is the canonical package source for both Terraform and
OpenTofu. Releases are built only from immutable SemVer tags of the form
`vMAJOR.MINOR.PATCH`.

## One-time setup

1. Create an RSA or DSA GPG signing key and retain an offline backup of the
   private key and its passphrase.
2. Add its ASCII-armored private key to the repository Actions secret
   `GPG_PRIVATE_KEY`, and its passphrase to `PASSPHRASE`.
3. Add the matching ASCII-armored public key to the Terraform Registry signing
   keys for the `reonokiy` namespace.
4. Publish the provider in the Terraform Registry from this public GitHub
   repository, then submit the same repository to the OpenTofu Registry.

## Release

1. Merge the intended change into `main` and wait for CI.
2. Create and push a new immutable tag, for example `v2.4.0`.
3. The `Release` workflow builds all supported platform archives, generates a
   checksum manifest, signs it with GPG, creates the GitHub Release, and
   produces GitHub build attestations.

Never replace release assets or move a published tag. Publish a new version
instead; provider lock files verify the published checksums.
