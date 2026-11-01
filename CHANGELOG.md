# Changelog

## Unreleased

### Added

- `saml2sts agent` gives work machines credentials over a Unix domain socket that you forward, such as with `ssh -R`. Run as a resident agent, it shares only the accounts and roles `[remote]` names; `saml2sts agent exec -- <command>` runs a temporary agent that shares every role until the command exits. Every request shows a notification on the sign-in machine, and roles in `[remote] confirm` need approval in a dialog. The system config can fix `[remote]`. See `docs/agent.md`.
- A Linux build (amd64, arm64) for work machines. It has only `creds`, `exec` and `roles`, which ask the agent on the sign-in machine over the socket in `$SAML2STS_AGENT_SOCK`, and say how to forward it when it is unreachable. On a Mac, these commands also ask the agent when the variable is set. See `docs/install.md`.
- An organization can build its own copy: `dev/browser/package-extension.mjs` packages the extension with its own host name and key for the Chrome Web Store, a self-hosted CRX and Firefox, and the release workflow, which runs only in a fork that sets `SAML2STS_HOST_NAME`, builds in that host name and signs and notarizes the binaries. See `docs/enterprise.md`.
- `doctor` checks the setup without signing in: the config files and where the IdP settings come from, the host manifests and the binaries they name, that machine-wide ones are owned by root, the extension in each browser profile, the code signature, and whether the Keychain items can be read without a prompt. It says what to fix and exits non-zero when a check fails.
- A system config at `/Library/Application Support/saml2sts/config.toml`, owned by root, whose `[idp]` settings win over the user config. An organization can fix the IdP URL and the STS endpoint there, so a program running as the user can no longer redirect SAML responses by editing the user config. See `docs/enterprise.md`.
- `[profiles]` in the config names the AWS profiles of roles, such as `dev = "arn:aws:iam::...:role/developer"`, so `profiles sync` can manage the profile names scripts already use. It refuses to replace a profile of that name it did not write.
- A role in `[roles]` can set its own session duration, as `name = { arn = "...", duration = "12h" }`. When STS rejects a duration as longer than the role allows, saml2sts retries once with 1 hour and says so, instead of failing the sign-in.

### Removed

- This repository no longer publishes binaries. saml2sts handles every SAML response the browser sees, so use a build your organization reviewed, signed and installed where only root can replace it; see `docs/enterprise.md`. To try it, build it from a clone.
- `install`. An organization places the host manifests machine-wide with its device management tool or package, as `docs/enterprise.md` describes; `dev/register-host.sh` registers a development build for your user.

### Security

- The extension forwards only the SAML response from the tab saml2sts opened, matched by a nonce in the IdP URL fragment, so ordinary console sign-ins are left alone and a web page can no longer answer a waiting login. The extension now asks for the `webNavigation` and `storage` permissions.
- Role and provider ARNs in a SAML response must be well formed, or the role is dropped, so a crafted response can no longer add lines to `~/.aws/config` or control characters to the terminal. `profiles sync` also refuses to write a profile with a control character or an unusual name.

### Fixed

- `exec` replaces AWS credential variables the parent already had, instead of passing both, so nested `exec` or a shell script no longer runs with the parent's credentials.
- Two SAML POSTs for one login, from a reload or two tabs, no longer both call STS; only one is exchanged.
- The SAML response is read only from the attribute statements of its single assertion, by namespace, and an encrypted assertion now says so instead of "no AWS role".
- The extension keeps error messages out of the status page URL, and so out of the browser history.
- The extension also covers the GovCloud and China sign-in hosts.

## v0.0.1 - 2026-11-01

Initial release, a proof of concept for macOS with Chromium-based browsers and Firefox.

### Added

- A browser extension that reads the SAML response your IdP posts to AWS, without stopping it, and hands it to saml2sts over native messaging.
- `profiles sync` reads the roles your IdP allows, assuming none, and writes a `saml2sts-*` AWS profile for each of them.
- `creds` for `credential_process`, and `exec`, get credentials for one role, signing in through the browser when the cache has none.
- `login` signs in and lets you choose a role afterwards; `roles` lists them and `logout` forgets credentials.
- `install` registers the binary as the extension's native messaging host.
- Credentials are cached per role in the macOS Keychain, readable without a prompt only by the saml2sts binary that wrote them.
