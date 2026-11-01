# Install

saml2sts is a single binary for macOS (amd64/arm64). Install it into a directory in your `PATH` in one of these ways:

1. [GitHub Releases](#github-releases)
1. [mise](#mise)
1. [go install](#go-install)

## GitHub Releases

Download the archive for your platform from [GitHub Releases](https://github.com/yokonao/saml2sts/releases), then install the binary into `PATH`:

```sh
asset=saml2sts_darwin_arm64.tar.gz # saml2sts_darwin_{amd64,arm64}.tar.gz
gh release download -R yokonao/saml2sts -p "$asset" # the latest release; pass a tag for another
tar -xzf "$asset" saml2sts
mkdir -p ~/.local/bin
install -m 755 saml2sts ~/.local/bin/
```

The macOS binaries of this repository are not signed with a Developer ID or notarized; an organization can sign its own builds, see [Running saml2sts in an enterprise](enterprise.md#build-and-sign-your-own-copy). `gh` and `curl` do not mark downloads as quarantined, but a browser does, and macOS then refuses to run the binary; remove the mark with `xattr -d com.apple.quarantine saml2sts`.

### Verify the archive

Each archive has a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) from the release workflow. Verify it with the [GitHub CLI](https://cli.github.com/):

```sh
gh attestation verify "$asset" \
  -R yokonao/saml2sts \
  --signer-workflow yokonao/saml2sts/.github/workflows/release.yml
```

## mise

With [mise](https://mise.jdx.dev/):

```sh
mise use -g github:yokonao/saml2sts
```

mise verifies the [build provenance attestation](#verify-the-archive) automatically.

## go install

```sh
go install github.com/yokonao/saml2sts/cmd/saml2sts@latest
```

The binary lands in `$(go env GOBIN)`, or `~/go/bin` when that is unset.

## Browser extension

The extension is not in the Chrome Web Store or on addons.mozilla.org yet. Load it from a clone of this repository as the [README](../README.md#try-it-locally) describes, then register saml2sts as its native messaging host:

```sh
saml2sts install --extension-id ljanpcedhfnidohflcgdjflhhjebpikb  # Chrome
saml2sts install --browser firefox --extension-id saml2sts@yokonao.github.io  # Firefox
```

`install` registers the path of the running binary. A version manager runs a version-specific path that an upgrade removes, so with mise pass a path that stays, such as `--path ~/.local/share/mise/shims/saml2sts`.

The Chrome ID is fixed by the `key` in `extension/manifest.json`. An organization that signs its own build gets its own ID and passes that instead. To register the host for every user of a machine, see [Running saml2sts in an enterprise](enterprise.md#register-the-native-messaging-host-for-the-whole-machine).
