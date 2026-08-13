# reefterm-sync

A small, self-hostable, end-to-end encrypted sync server for
[Reef Terminal](https://github.com/reefterm/reefterm).

## What this is

Reef Terminal can sync your hosts, keys, snippets, folders and settings across
devices. This server is what it syncs *to* when you don't want to trust a
third party with that data.

The design is zero-knowledge: this server stores opaque, encrypted blobs and
never sees the passphrase, the recovery code, or the key that decrypts them.
Encryption and decryption happen entirely on the client, before anything is
sent here. An operator running this server -- including you, running it for
yourself -- cannot read what it stores.

This is genuinely new code, not derived from CloudTerm/CloudBlast in any way,
which is why it carries its own license (AGPL-3.0, see [LICENSE](LICENSE)) and
lives in its own repository rather than inside
[reefterm/reefterm](https://github.com/reefterm/reefterm).

## Status

Early. The design is settled (see the parent project's planning discussion),
implementation is starting now. Not ready to run in production yet -- this
notice will be removed once it is.

## Design

- Single static Go binary, no CGO, cross-compiles cleanly.
- SQLite by default (via a pure-Go driver), so running it is `docker run` or
  copying one binary -- no separate database to stand up. A `Store` interface
  keeps a Postgres backend possible later without changing the API.
- Auth is opaque, hashed bearer session tokens, not JWT: revocation needs
  server-side state either way, so JWT's usual advantage doesn't apply here,
  and opaque tokens avoid an unnecessary footgun surface in a service meant to
  be written once and rarely touched again.
- Login passwords are hashed with argon2id. The client-side passphrase that
  actually derives the E2EE key never reaches this server in any form --
  see Reef Terminal's `src/main/sync-keys.js` for that half of the design.

## Development

Requires Go (see [go.dev/dl](https://go.dev/dl/) for the installer).

```bash
go build ./...
go test ./...
```

More once the initial implementation lands.

## License

AGPL-3.0 (see [LICENSE](LICENSE)) -- chosen deliberately: if you run a modified
version of this server as a network service, the AGPL requires making your
changes available to the people using it. That's the point, for a project
whose whole reason to exist is not trusting an operator you can't verify.
