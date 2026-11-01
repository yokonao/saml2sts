# Changelog

## v0.0.1 - 2026-11-01

Initial release, a proof of concept for macOS with Chromium-based browsers and Firefox.

### Added

- A browser extension that reads the SAML response your IdP posts to AWS, without stopping it, and hands it to saml2sts over native messaging.
- `profiles sync` reads the roles your IdP allows, assuming none, and writes a `saml2sts-*` AWS profile for each of them.
- `creds` for `credential_process`, and `exec`, get credentials for one role, signing in through the browser when the cache has none.
- `login` signs in and lets you choose a role afterwards; `roles` lists them and `logout` forgets credentials.
- `install` registers the binary as the extension's native messaging host.
- Credentials are cached per role in the macOS Keychain, readable without a prompt only by the saml2sts binary that wrote them.
