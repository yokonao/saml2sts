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
