# Deploying saml2sts in an organization

This guide is for administrators who deploy saml2sts to many Macs with a device management tool.

## Fix the IdP settings in the system config

saml2sts reads two config files:

1. `/Library/Application Support/saml2sts/config.toml`, the system config, which the organization manages.
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

The native messaging host sends each SAML response to `sts_endpoint`. A program running as the user can write the user config, so without the system config it could point `sts_endpoint` at its own server and receive the next SAML response, which allows any role the user has. Fixing `sts_endpoint`, `url` and `region` in the system config closes that.

Leave `[roles]` short names and `[profiles]` to users unless the organization wants them the same everywhere. Fix `duration` too if the organization wants one session length.

## Register the native messaging host for the whole machine

Install the binary in a root-owned path, such as `/usr/local/bin/saml2sts`, then register it for every user:

```sh
sudo saml2sts install --system --browser chrome,edge,firefox --path /usr/local/bin/saml2sts \
  --extension-id <Chromium extension ID> --extension-id <Firefox add-on ID>
```

`--system` refuses a binary that a user could replace, since every user's browser would start it. It writes the manifests to:

| Browser | Directory |
| --- | --- |
| Chrome, Chrome Beta | `/Library/Google/Chrome/NativeMessagingHosts` |
| Chromium | `/Library/Application Support/Chromium/NativeMessagingHosts` |
| Edge | `/Library/Microsoft/Edge/NativeMessagingHosts` |
| Firefox | `/Library/Application Support/Mozilla/NativeMessagingHosts` |

For Brave, or to have a device management tool place the file itself, print the manifest instead:

```sh
saml2sts install --print --browser chrome --path /usr/local/bin/saml2sts --extension-id <ID>
```

The file is named after the host, `io.github.yokonao.saml2sts.json` unless your build sets another.

### Browser policies

A user-level manifest of the same name still overrides the machine-wide one, so a program running as the user could register its own host. For Chrome and Edge, set these policies:

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

## Check a machine

`saml2sts doctor` checks the config files, the host manifests, the extension in each browser profile, the code signature and Keychain access, without signing in. It prints what to fix for each failure and exits non-zero when a check fails, so a device management tool can run it as the user.

## Build, sign and distribute your own copy

An organization usually builds saml2sts itself and publishes the extension under its own key rather than trust a personal build.

### What to fork or pin

Fork this repository, or pin a tag, and review the changes between tags before you release them. Nothing else needs to change in the code.

### What to change

- **Host name**: set the repository variable `SAML2STS_HOST_NAME`, such as `com.example.saml2sts`. The release workflow builds it in as the default of `install --name` and `doctor --name`. Use the same name for the extension below.
- **Signing**: add the secrets below to have GoReleaser sign the binaries with your Developer ID and notarize them. Without them it builds unsigned binaries, as this repository does.

  | Secret | Value |
  | --- | --- |
  | `MACOS_SIGN_P12` | base64 of the Developer ID Application certificate and key, as `.p12` |
  | `MACOS_SIGN_PASSWORD` | its password |
  | `MACOS_NOTARY_ISSUER_ID` | App Store Connect API issuer ID |
  | `MACOS_NOTARY_KEY_ID` | App Store Connect API key ID |
  | `MACOS_NOTARY_KEY` | base64 of the `.p8` API key |

- **Extension**: package it with your host name and key:

  ```sh
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out key.pem  # once; keep it secret
  cd dev/browser && npm ci
  node package-extension.mjs --host-name com.example.saml2sts --key key.pem \
    --gecko-id saml2sts@example.com --chrome "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
  ```

  It writes to `dist/extension/`:

  | File | For |
  | --- | --- |
  | `chrome-web-store.zip` | the Chrome Web Store, which assigns the ID; pass that ID to `install` |
  | `chrome/` | loading unpacked, with the ID the script prints |
  | `saml2sts.crx` | self-hosting with an `update_url`, signed with `key.pem`, with the same ID |
  | `firefox.zip` | addons.mozilla.org, or `web-ext sign --channel unlisted` for self-distribution |

### What to distribute

1. The signed binary, in a root-owned path such as `/usr/local/bin/saml2sts`.
2. The system config, with `[idp]` fixed ([above](#fix-the-idp-settings-in-the-system-config)).
3. The host manifests from `install --system` or `install --print` ([above](#register-the-native-messaging-host-for-the-whole-machine)).
4. The extension, force-installed by browser policy.

Then run `saml2sts doctor` as a user to check the result.

### Keychain access across upgrades

Credentials are kept in Keychain items whose access list trusts the binary that created them. For an unsigned or ad-hoc signed binary that is its exact hash, so macOS asks once after every upgrade. A Developer ID signed binary is trusted by its designated requirement, its identifier and team, so an upgrade signed the same way is expected to read the items of the previous version without a prompt.

This has not been tested with a Developer ID yet. After your first signed upgrade, run `saml2sts doctor`: its Keychain check fails on any item that would need a prompt.
