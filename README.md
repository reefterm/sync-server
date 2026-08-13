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

Early. The core API (register, login, sync keys, snapshots, password change,
email-based recovery) is implemented and tested. Not ready to run in
production yet -- this notice will be removed once it is.

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

## Configuration

All environment variables, all optional except where noted:

| Variable | Default | What it does |
| --- | --- | --- |
| `REEFTERM_SYNC_DB_PATH` | `reefterm-sync.db` | Path to the SQLite file. |
| `REEFTERM_SYNC_LISTEN_ADDR` | `:8420` | Address to listen on. |
| `REEFTERM_SYNC_ALLOW_REGISTRATION` | `true` | Set to `false` once everyone who needs an account has one, to close the server to new signups. |
| `REEFTERM_SYNC_SESSION_TTL` | `720h` (30 days) | How long a session lasts before login is required again. Go duration syntax (`24h`, `30m`). |
| `REEFTERM_SYNC_RECOVERY_TOKEN_TTL` | `30m` | How long an emailed recovery link stays valid. |
| `REEFTERM_SYNC_SMTP_HOST` | unset | SMTP server hostname. Email-based account recovery (a forgotten passphrase, with no device left signed in) is unavailable until this is set. |
| `REEFTERM_SYNC_SMTP_PORT` | `587` | SMTP port. `465` for implicit TLS, `587` for STARTTLS, `25` for neither. |
| `REEFTERM_SYNC_SMTP_USERNAME` | unset | SMTP auth username, if your server requires it. |
| `REEFTERM_SYNC_SMTP_PASSWORD` | unset | SMTP auth password. |
| `REEFTERM_SYNC_SMTP_FROM` | unset | The `From:` address on recovery emails. Required alongside `SMTP_HOST` to enable recovery. |
| `REEFTERM_SYNC_SMTP_TLS` | `starttls` | `tls` (implicit, port 465), `starttls` (port 587), or `none` (unencrypted -- only ever appropriate for a relay on localhost or a private network). |
| `REEFTERM_SYNC_SMTP_INSECURE_SKIP_VERIFY` | `false` | Skip TLS certificate verification. For a self-signed relay in development; never appropriate against a real provider. |

Generic SMTP rather than a specific provider's API on purpose: every
transactional-mail provider speaks it, alongside whatever API they'd rather
sell you, and it's the only option that also works for an operator relaying
through their own mail server. If you use [Zeptomail](https://www.zoho.com/zeptomail/),
their SMTP credentials work here directly -- no separate integration needed.

## Development

Requires Go (see [go.dev/dl](https://go.dev/dl/) for the installer).

```bash
go build ./...
go test ./...
```

## License

AGPL-3.0 (see [LICENSE](LICENSE)) -- chosen deliberately: if you run a modified
version of this server as a network service, the AGPL requires making your
changes available to the people using it. That's the point, for a project
whose whole reason to exist is not trusting an operator you can't verify.
