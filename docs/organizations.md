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
