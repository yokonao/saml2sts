# Releasing

Add the release to `CHANGELOG.md` first; it has to be in the tagged tree.

```sh
git tag -a vX.Y.Z -m vX.Y.Z
git push origin vX.Y.Z
```

This repository publishes only the tag; organizations build from it. `.github/workflows/release.yml` builds, signs and notarizes the binaries with GoReleaser, publishes them to GitHub Releases, and attests their build provenance, but only in a fork that sets the `SAML2STS_HOST_NAME` variable, and it fails without the `MACOS_SIGN_*` and `MACOS_NOTARY_*` secrets; see [Running saml2sts in an enterprise](enterprise.md#build-and-sign-your-own-copy). Releases are immutable, so fix a bad release with a new patch version.

`goreleaser release --snapshot --clean` builds the same archives into `dist/` locally without publishing, unsigned unless the secrets are in the environment.
