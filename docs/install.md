# Install

This repository publishes no binaries. Every browser that signs in to AWS starts saml2sts with the SAML response, so the binary has to come from a build your organization reviewed, signed and installed where only root can replace it. Use the build your organization distributes, as [Running saml2sts in an enterprise](enterprise.md) describes. To try saml2sts, build it from a clone as the [README](../README.md#try-it-locally) describes.

A Mac can be the [sign-in machine](../README.md#sign-in-machine-and-work-machine); Linux can only be a [work machine](#on-a-linux-work-machine).

## On a Linux work machine

The Linux binary has only `creds`, `exec` and `roles`, which ask the [agent](agent.md) on the sign-in machine over the socket in `$SAML2STS_AGENT_SOCK`. It needs no config file, browser or secure storage, and `--role` takes a name from `[roles]` in the agent's config. Without a reachable agent, it says how to forward the socket instead of signing in.

Install the same version as the sign-in machine, from your organization's release or built from the same tag:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -o saml2sts ./cmd/saml2sts
```

`profiles sync` runs only on the sign-in machine, so write the profiles into `~/.aws/config` yourself:

```ini
[profile dev]
credential_process = saml2sts creds --role dev
```

### On a shared host

Where you cannot install software, put the binary in your home directory; it is statically linked and needs nothing else:

```sh
mkdir -p ~/.local/bin
install -m 755 saml2sts ~/.local/bin/
```

Then write its full path in `credential_process`, such as `/home/you/.local/bin/saml2sts creds --role dev`, since the AWS CLI does not expand `~` and may not see the `PATH` of your login shell.

If the home directory does not allow running programs, ask an administrator to install the binary for every user, such as with `sudo install -m 755 saml2sts /usr/local/bin/`.
