# Changelog

## Unreleased

### Security

- The extension forwards only the SAML response from the tab saml2sts opened, matched by a nonce in the IdP URL fragment, so ordinary console sign-ins are left alone and a web page can no longer answer a waiting login. The extension now asks for the `webNavigation` and `storage` permissions.
- Role and provider ARNs in a SAML response must be well formed, or the role is dropped, so a crafted response can no longer add lines to `~/.aws/config` or control characters to the terminal. `profiles sync` also refuses to write a profile with a control character or an unusual name.

### Fixed

- `exec` replaces AWS credential variables the parent already had, instead of passing both, so nested `exec` or a shell script no longer runs with the parent's credentials.
- Two SAML POSTs for one login, from a reload or two tabs, no longer both call STS; only one is exchanged.

## v0.0.1 - 2026-11-01

Initial release, a proof of concept for macOS with Chromium-based browsers and Firefox.

### Added

- A browser extension that reads the SAML response your IdP posts to AWS, without stopping it, and hands it to saml2sts over native messaging.
- `profiles sync` reads the roles your IdP allows, assuming none, and writes a `saml2sts-*` AWS profile for each of them.
- `creds` for `credential_process`, and `exec`, get credentials for one role, signing in through the browser when the cache has none.
- `login` signs in and lets you choose a role afterwards; `roles` lists them and `logout` forgets credentials.
- `install` registers the binary as the extension's native messaging host.
- Credentials are cached per role in the macOS Keychain, readable without a prompt only by the saml2sts binary that wrote them.
