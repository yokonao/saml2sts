# Agent for work machines

Use saml2sts on a [work machine that is not the sign-in machine](../README.md#sign-in-machine-and-work-machine), such as an SSH host, WSL, a local VM or a devcontainer, by forwarding the socket of an agent on the sign-in machine to it.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="images/agent-dark.png">
  <img alt="On the work machine, aws runs saml2sts creds as its credential_process, which sends the role over a forwarded Unix domain socket. On the sign-in machine, saml2sts agent answers with credentials, running the usual login flow only when its cache is stale." src="images/agent-light.png">
</picture>

## How it works

- `saml2sts agent` runs on the sign-in machine and listens on a Unix domain socket. On the work machine, `saml2sts creds`, `exec` and `roles` send each request to the socket in `$SAML2STS_AGENT_SOCK`: always on Linux, and on a Mac when the variable is set.
- Only role names or ARNs and short-lived STS credentials cross the socket. The SAML response, the IdP session, the config and the credential cache stay on the sign-in machine, and role names resolve in its config.
- The agent gets credentials as `saml2sts creds` does on the sign-in machine: from the cache, or by opening the browser there.
- Each connection carries one request and one response, each a line of JSON with a protocol version. The agent refuses other versions, so install the same version of saml2sts on both machines.
- While the sign-in machine sleeps or the forward is down, requests fail and say so. Jobs that run unattended beyond the credentials' lifetime should use the work machine's own role instead.

## Two kinds of agent

### Resident

`saml2sts agent` runs until it is stopped and shares only the accounts and roles `[remote]` names in the config file, so production accounts can stay off the machine:

```toml
[remote]
accounts = ["222222222222"]  # every role in these accounts
roles = ["dev"]  # role ARNs or names from [roles]
```

It listens on `~/Library/Caches/saml2sts/agent.sock` unless `--socket` names another path, and reads the config at each request. It suits personal development machines, where a long-lived socket is convenient and the exposure is limited to development roles.

To start it at login and keep it running, save this as `~/Library/LaunchAgents/io.github.yokonao.saml2sts.agent.plist`, with the path of your saml2sts:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.github.yokonao.saml2sts.agent</string>
  <key>ProgramArguments</key>
  <array><string>/Users/me/.local/bin/saml2sts</string><string>agent</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/Users/me/Library/Logs/saml2sts-agent.log</string>
</dict>
</plist>
```

Then load it with `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.github.yokonao.saml2sts.agent.plist`.

### Temporary

`saml2sts agent exec -- <command>` runs an agent for as long as the command, such as `ssh`, runs. It creates its socket in a new private directory, puts the path in `$SAML2STS_AGENT_SOCK` for the command, and removes it when the command exits. It shares every role the IdP allows, since the socket exists only while you are connected. It suits shared hosts, where the roles you need are not known in advance.

With OpenSSH 8.4 or later, which expands environment variables in `RemoteForward`, name the forward in `~/.ssh/config`:

```
Host devbox
  RemoteForward /home/me/.saml2sts/agent.sock ${SAML2STS_AGENT_SOCK}
```

and connect with `saml2sts agent exec -- ssh devbox`.

## Setting up the work machine

1. Install saml2sts; see [installing on a Linux work machine](install.md#on-a-linux-work-machine).
2. Create a directory for the socket that only you can enter, such as with `mkdir -m 700 ~/.saml2sts`, and point `$SAML2STS_AGENT_SOCK` at the socket in your shell profile, such as with `export SAML2STS_AGENT_SOCK=~/.saml2sts/agent.sock`.
3. Name the roles in `~/.aws/config`, as `credential_process = saml2sts creds --role dev`.

sshd does not replace a socket an earlier connection left unless the server sets `StreamLocalBindUnlink yes`. Without it, remove the socket before connecting again, or ssh warns that the forward failed.

## Guards

Root on the work machine, and anything else that reaches the forwarded socket, can ask for credentials while the socket exists. Instead of authenticating the client, which root could imitate, the agent makes requests visible and lets you stop the dangerous ones:

- Every request for credentials shows a notification on the sign-in machine, naming where it came from (the socket of a resident agent, or the command of a temporary one) and the role. macOS shows them as from Script Editor, so allow its notifications in System Settings.
- Roles in `[remote] confirm` need your approval in a dialog on the sign-in machine. No answer within a minute denies the request.

  ```toml
  [remote]
  confirm = ["arn:aws:iam::222222222222:role/admin"]
  ```
- A temporary agent and its socket last only as long as its command.
- An organization can fix `[remote] accounts` and `roles` in the [system config](enterprise.md#fix-the-idp-settings-in-the-system-config), which win over the user's, and add roles to `confirm`, which the user cannot remove.

Not planned: client key pairs or tokens. A key placed on the work machine is readable by its root, and other users there are already kept out by the socket's permissions.

## Forwarding the socket

saml2sts does not forward the socket itself; anything that carries a Unix domain socket will do, as long as nothing on the way can read or alter the traffic and only the intended side can reach the socket. For example:

- `ssh -R`, the same mechanism as ssh-agent forwarding. sshd creates the socket readable only by you.
- A bind mount into a container on a Linux host, which never leaves the kernel.
- An SSH forward into the VM of colima, Lima or a similar runtime, since macOS cannot bind mount a socket into a container.

Do not bridge the socket onto a network port, for example with `socat`, without encryption and authentication.
