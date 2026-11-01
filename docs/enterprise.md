# Running saml2sts in an enterprise

This guide is for administrators who roll saml2sts out to many Macs with a device management tool. It goes in the order of a rollout. Each step closes a way that a program running as a user could get a SAML response, as the [security model](security.md) explains.

1. [Build and sign your own copy](#build-and-sign-your-own-copy)
2. [Package and publish the extension](#package-and-publish-the-extension)
3. [Install the binary in a root-owned path](#install-the-binary-in-a-root-owned-path)
4. [Fix the IdP settings in the system config](#fix-the-idp-settings-in-the-system-config)
5. [Place the native messaging host manifests](#place-the-native-messaging-host-manifests)
6. [Set browser policies](#set-browser-policies)
7. [Check each machine](#check-each-machine)

Then keep it up to date as in [Upgrade](#upgrade), and set up the IAM roles as in [Set up the AWS side](#set-up-the-aws-side).

## Build and sign your own copy

This repository publishes no binaries, so build saml2sts yourself. Fork this repository, or pin a tag, and review the changes between tags before you release them. Nothing in the code needs to change.

In the fork:

- Set the repository variable `SAML2STS_HOST_NAME`, such as `com.example.saml2sts`. The release workflow runs only when it is set, and builds it in as the default of `doctor --name`. Use the same name for the extension and the host manifests.
- Add these secrets, and GoReleaser signs the binaries with your Developer ID and notarizes them. The release workflow fails without them.

  | Secret | Value |
  | --- | --- |
  | `MACOS_SIGN_P12` | base64 of the Developer ID Application certificate and key, as `.p12` |
  | `MACOS_SIGN_PASSWORD` | its password |
  | `MACOS_NOTARY_ISSUER_ID` | App Store Connect API issuer ID |
  | `MACOS_NOTARY_KEY_ID` | App Store Connect API key ID |
  | `MACOS_NOTARY_KEY` | base64 of the `.p8` API key |

Release as [docs/releasing.md](releasing.md) describes. Each archive gets a [build provenance attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations), which your distribution pipeline can verify:

```sh
gh attestation verify saml2sts_darwin_arm64.tar.gz \
  -R example/saml2sts --signer-workflow example/saml2sts/.github/workflows/release.yml
```

## Package and publish the extension

Package the extension with your host name and your own key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem  # once
cd dev/browser && npm ci
node package-extension.mjs --host-name com.example.saml2sts --key key.pem \
  --gecko-id saml2sts@example.com --chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
```

It writes to `dist/extension/`:

| File | For |
| --- | --- |
| `chrome-web-store.zip` | the Chrome Web Store, which assigns the ID |
| `chrome/` | loading unpacked, with the ID the script prints |
| `saml2sts.crx` | self-hosting with an `update_url`, signed with `key.pem`, with the same ID |
| `firefox.zip` | addons.mozilla.org, or `web-ext sign --channel unlisted` for self-distribution |

Keep `key.pem` in your secret store, like a signing key. Whoever has it can publish an extension with your ID. Note the Chromium extension ID and the Firefox add-on ID for the steps below.

## Install the binary in a root-owned path

Install the signed binary where only root can replace it, such as `/usr/local/bin/saml2sts`, with your device management tool. Every user's browser starts this binary with their SAML response, so a user-writable path would let any program running as a user replace it. Do not use a version manager or `go install` on managed machines.

## Fix the IdP settings in the system config

saml2sts reads two config files:

1. `/Library/Application Support/saml2sts/config.toml`, the system config, which you manage.
2. `~/.config/saml2sts/config.toml`, the user config, or `$SAML2STS_CONFIG`.

Every `[idp]` key the system config sets wins over the user config, even when its value is empty. `[roles]` and `[profiles]` of both files are merged, and the system config wins for a name both set. The user config is optional when the system config sets `url`.

The system config, and every directory above it, must be owned by root and writable by no one else, or saml2sts refuses to start. No environment variable moves it.

Fix at least these keys:

```toml
[idp]
url = "https://idp.example.com/..."
region = "ap-northeast-1"
sts_endpoint = ""  # "" keeps the regional STS endpoint and stops a user config from setting one
```

Without them, a program running as a user could point `sts_endpoint` at its own server through the user config and receive the next SAML response; see the [security model](security.md#where-the-saml-response-goes).

Leave `[roles]` short names and `[profiles]` to users unless you want them the same everywhere. Fix `duration` too if you want one session length.

To decide what the [agent](agent.md) gives work machines, set `[remote] accounts` and `roles`, which replace the user's, and `confirm`, which adds to the user's:

```toml
[remote]
accounts = ["222222222222"]  # development accounts only
confirm = ["arn:aws:iam::222222222222:role/admin"]
```

A temporary agent, `saml2sts agent exec`, shares every role regardless, since it lasts only as long as one command; `confirm` still applies to it.

## Place the native messaging host manifests

The browser starts the binary a host manifest names, and only for the extensions it allows. Place one manifest per browser, named after the host name, such as `com.example.saml2sts.json`, in the machine-wide directory:

| Browser | Directory |
| --- | --- |
| Chrome, Chrome Beta | `/Library/Google/Chrome/NativeMessagingHosts` |
| Chromium | `/Library/Application Support/Chromium/NativeMessagingHosts` |
| Edge | `/Library/Microsoft/Edge/NativeMessagingHosts` |
| Firefox | `/Library/Application Support/Mozilla/NativeMessagingHosts` |

For the Chromium-based browsers:

```json
{
  "name": "com.example.saml2sts",
  "description": "saml2sts",
  "path": "/usr/local/bin/saml2sts",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<Chromium extension ID>/"]
}
```

For Firefox, replace `allowed_origins` with `"allowed_extensions": ["<Firefox add-on ID>"]`.

Place them with your device management tool, or in the same package as the binary, so the path cannot drift from where the binary is. The manifests and every directory above them must be owned by root and writable by no one else, like the binary: a program running as a user that could change one would choose which binary every user's browser starts. `saml2sts doctor` fails when they are not.

Brave has no known machine-wide directory, so it is not supported on managed machines.

## Set browser policies

A user-level manifest of the same name overrides the machine-wide one, so a program running as a user could register its own host ([security model](security.md#which-binary-the-browser-starts)). For Chrome and Edge, set these policies:

- `NativeMessagingUserLevelHosts` = `false`, so the browser reads only the machine-wide manifests.
- `ExtensionSettings` with the extension `force_installed`, so users cannot remove or replace it.
- `ExtensionSettings` with `runtime_blocked_hosts` for `"*"` and `runtime_allowed_hosts` for the saml2sts extension, so other extensions cannot read the SAML response on the AWS sign-in pages:

```json
{
  "NativeMessagingUserLevelHosts": false,
  "ExtensionSettings": {
    "*": {
      "runtime_blocked_hosts": ["*://signin.aws.amazon.com", "*://*.signin.aws.amazon.com"]
    },
    "<Chromium extension ID>": {
      "installation_mode": "force_installed",
      "update_url": "https://clients2.google.com/service/update2/crx",
      "runtime_allowed_hosts": ["*://signin.aws.amazon.com", "*://*.signin.aws.amazon.com"]
    }
  }
}
```

Use your own `update_url` for a self-hosted extension, and add the GovCloud and China sign-in hosts if you use them. Firefox reads user-level manifests as well as the machine-wide ones; force-install the add-on with its `ExtensionSettings` policy.

## Check each machine

`saml2sts doctor` checks the config files and where each IdP setting comes from, the host manifests and the binaries they name, the extension in each browser profile, the code signature, and Keychain access, without signing in. It prints what to fix for each failure and exits non-zero when a check fails. Run it as the user from your device management tool after the rollout and after each upgrade.

## Upgrade

- Review the changes between tags, then release from your fork and replace the binary at the same root-owned path. The host manifests name the path, so they stay valid.
- Publish the extension with the same key, or to the same store listing, so its ID stays the same. A new ID needs new host manifests and policies.
- Run `saml2sts doctor` afterwards.

### Keychain access across upgrades

Credentials are kept in Keychain items whose access list trusts the binary that created them. For an unsigned or ad-hoc signed binary that is its exact hash, so macOS asks once after every upgrade. A Developer ID signed binary is trusted by its designated requirement, its identifier and team, so an upgrade signed the same way is expected to read the items of the previous version without a prompt.

This has not been tested with a Developer ID yet. After your first signed upgrade, run `saml2sts doctor`: its Keychain check fails on any item that would need a prompt.

## Set up the AWS side

- Condition each role's trust policy on `SAML:aud` being `https://signin.aws.amazon.com/saml`, so the role accepts only assertions meant for AWS sign-in.
- Set each role's maximum session duration to at least the `duration` you configure for it. A longer `duration` makes saml2sts fall back to 1 hour.
- saml2sts assumes one role per sign-in. Keep the roles your IdP grants each user as narrow as the user needs, since a SAML response can assume any of them until it expires.
