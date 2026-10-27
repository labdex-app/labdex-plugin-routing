# Routing discovery

A [labdex](https://github.com/reykimedev/labdex) plugin. Read-only. BGP neighbours and the routing table of a router (OPNsense with FRR, or Cisco IOS-XE over RESTCONF), compared with the networks in the inventory: routed prefixes labdex doesn't know, inventory networks the router has no route for, and neighbours that aren't established.

**Version** 1.0 · **Works with** labdex >=1.3,<2 · **Plugin id** `routing`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| Router |  |
| URL | OPNsense web UI, or the IOS-XE device (https://router) |
| API key / user name | OPNsense: the API key (needs Diagnostics: FRR). IOS-XE: a privilege-15 user with RESTCONF enabled |
| API secret / password |  |
| Check the TLS certificate |  |
| Count /32 and /128 routes as networks |  |
| Ignore prefixes | CIDRs that are fine without an inventory network, e.g. the tailnet or a provider's transfer net |

## Actions

- **Check connection** (run)
- **Read routes and neighbours** (run)

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
publish a GitHub release tagged `v<version>` (web UI, or `gh release create v<version> --target main --notes ""`).
The release workflow signs the plugin with the `LABDEX_SIGNING_KEY` secret, attaches the zip and
`CHANGELOG.md` to the release and puts that version's CHANGELOG section into its description.
Files listed in `.releaseignore` stay out of the zip.
