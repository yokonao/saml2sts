# Security model

saml2sts handles two secrets: the SAML response, which can assume any role your IdP allows until it expires, and the temporary AWS credentials of one role. This page says how each is kept from other programs, and what is out of scope.

## Credentials and logins at rest

- Logins and credentials are kept in the OS secure storage, which is the macOS Keychain today. Items are created with the default access list, which lets only the saml2sts binary that created them read them without a prompt. Rebuilding or upgrading an unsigned binary makes a new one, and macOS asks once for the old items; see [Keychain access across upgrades](enterprise.md#keychain-access-across-upgrades) for signed builds.
- Items are deleted and re-added rather than updated, so an item another program planted with a looser access list is never written to.
- Credentials are never written to `~/.aws/credentials`, arguments, or logs.
- Each sign-in assumes only the one role asked for or chosen, never every role the IdP allows.

## The handoff between the CLI and the host

The CLI and the native messaging host never talk to each other directly. They meet only in the Keychain, and the SAML response never leaves the host.

- The login request carries a random secret the host echoes back, so the CLI ignores results it did not ask for.
- Each login is exchanged with STS at most once, even when the browser posts the SAML response twice.

## The browser extension

- The CLI opens the IdP with a random nonce in the URL fragment, which the browser does not send to the IdP. The extension forwards only the next SAML response from the tab opened with it, together with the nonce, and the host ignores a response whose nonce does not match the waiting login. Any other sign-in is never read further or sent to the host, and a page posting a SAML response of its own cannot answer a login.
- To see which tab saml2sts opened, the extension reads the URL of each page a tab starts loading (the `webNavigation` permission, which browsers describe as reading your browsing history). It keeps nothing but the nonce and the tab, in memory, and only for a tab whose URL carries one.
- Other extensions with access to the AWS sign-in pages can read the SAML response too. An organization can block them with browser policy; see [Browser policies](enterprise.md#set-browser-policies).

## Where the SAML response goes

- The host reads the STS endpoint from the config file, never from the login request, so a planted request cannot send the SAML response elsewhere. `sts_endpoint` must be HTTPS, or HTTP to localhost.
- The user config is writable by any program running as you. Such a program could point `sts_endpoint` at its own server and receive the next SAML response. The system config at `/Library/Application Support/saml2sts/config.toml` wins over the user config and must be owned by root, so an organization should fix `sts_endpoint`, `url` and `region` there; see [Fix the IdP settings in the system config](enterprise.md#fix-the-idp-settings-in-the-system-config).

## Which binary the browser starts

- A program running as you can register its own host under the saml2sts name in your user-level browser directories, and receive the SAML response. `install --system` registers a binary only root can replace, and the `NativeMessagingUserLevelHosts` policy makes Chrome and Edge ignore user-level hosts; see [Register the native messaging host for the whole machine](enterprise.md#register-the-native-messaging-host-for-the-whole-machine).
- `saml2sts doctor` shows which manifests are registered and the binaries they name.

## Out of scope

saml2sts does not protect against a compromised user session or saml2sts binary, or against a program the user allows at a Keychain prompt. A program running as you can also run saml2sts itself and get credentials that way; the access list only keeps other tools from reading the items. The organization settings above narrow what such a program can do to the SAML response, but do not stop it from using saml2sts.

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
