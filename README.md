# supa-emu (Supabase Emulator)

A lightweight Go emulator exposing Supabase Auth (GoTrue) compatible HTTP endpoints. A fast, single-binary alternative to `supabase start` (Docker) for CI and local development.

- Module: `github.com/rin2yh/supa-emu`
- Binary: `supa-emu`

## Install

```bash
go install github.com/rin2yh/supa-emu@latest
```

Or download a prebuilt binary from [GitHub Releases](https://github.com/rin2yh/supa-emu/releases).

## Run

```bash
go build -o bin/supa-emu .
./bin/supa-emu -addr 127.0.0.1:54321
```

| Flag | Env | Default |
|------|-----|---------|
| `-addr` | `SUPA_EMU_ADDR` | `127.0.0.1:54321` |
| `-jwt-secret` | `SUPA_EMU_JWT_SECRET` | Supabase CLI default |
| `-jwt-issuer` | - | `http://127.0.0.1:54321/auth/v1` |
| `-access-token-ttl` | - | `1h` |
| `-refresh-reuse-interval` | - | `10s` |
| `-webauthn-rp-id` | - | `127.0.0.1` |
| `-webauthn-rp-name` | - | `supa-emu` |

CLI flags take precedence over environment variables.

## Use as a GitHub Action

A composite action (`action.yml`) downloads the release binary, starts the emulator in the background, and waits for it to be healthy.

```yaml
jobs:
  e2e:
    runs-on: ubuntu-latest   # or macos-*; amd64 / arm64
    steps:
      - uses: actions/checkout@v4
      - uses: rin2yh/supa-emu@v0.1.0   # pin to a released tag
        with:
          version: v0.1.0
          addr: 127.0.0.1:54321
      - run: npm test   # the emulator is up for the rest of the job
```

Inputs: `version` (default `latest`), `addr` (default `127.0.0.1:54321`), `jwt-secret`, `jwt-issuer`, `access-token-ttl`, `refresh-reuse-interval`, `wait-for-health` (default `true`), `github-token` (default `${{ github.token }}`). Outputs: `addr`, `pid`, `log`.

## Endpoints

Supports `/auth/v1/*` (health, settings, signup, token, user, logout, factors, passkeys, admin/users) plus `/__emulator/*` test helpers (reset, snapshot, users). Unmatched paths return `404`.

In-memory only, no apikey validation, HS256 fixed. OAuth / Phone / TOTP / email / Realtime / Storage are out of scope.

The emulator implements **two distinct WebAuthn features** — they share the `-webauthn-rp-*` Relying Party settings but are otherwise separate: passwordless passkeys are a primary login, WebAuthn factors are a second factor. Because there is no real authenticator, neither verifies attestation/assertion signatures.

## Passwordless passkeys (`auth.passkey.*`)

A passkey is the login itself: `authentication/verify` issues a **new session** from an unauthenticated request (not an `aal2` upgrade). Authentication matches the presented credential id against one persisted at registration, so a client must register before it can authenticate. The `access_token` is signed with the same key as a password login, so app-side `getClaims()` accepts it. The verify response is the standard GoTrue token response at the top level (like the password-login token endpoint), so supabase-js's `_sessionResponse` resolves the session from the top-level `access_token`.

| Method | Path | supabase-js | Response |
|--------|------|-------------|----------|
| `POST` | `/auth/v1/passkeys/registration/options` | `passkey.register` (Bearer) | `{ challenge_id, options, expires_at }` |
| `POST` | `/auth/v1/passkeys/registration/verify` | body `{ challenge_id, credential }` (Bearer) | `{ id, friendly_name?, created_at }` |
| `POST` | `/auth/v1/passkeys/authentication/options` | `passkey.signIn` (no auth) | `{ challenge_id, options, expires_at }` |
| `POST` | `/auth/v1/passkeys/authentication/verify` | body `{ challenge_id, credential }` (no auth) | `{ access_token, refresh_token, user, ... }` (GoTrue token response) |
| `GET` | `/auth/v1/passkeys` | `passkey.list` (Bearer) | `[ { id, friendly_name?, created_at, last_used_at } ]` (top-level array) |
| `DELETE` | `/auth/v1/passkeys/{id}` | `passkey.unenroll` (Bearer) | `{ id }` |

Challenges are single-use with a 5&nbsp;min TTL. Registration options require a Bearer token; authentication options are discoverable (no auth). The RP id defaults to `127.0.0.1` to match a local E2E origin (`http://127.0.0.1:PORT`).

`GET /auth/v1/passkeys` and `DELETE /auth/v1/passkeys/{id}` are user-scoped management endpoints (Bearer, the caller's own passkeys — no service_role). The list body is a **top-level JSON array** because supabase-js `auth.passkey.list()` uses `xform: (data) => ({ data })` and hands the array straight back as `PasskeyListItem[]`. `last_used_at` is `null` until the passkey's first successful authentication. The `{id}` is the passkey record ID (from `registration/verify`), not the credential id; deleting a passkey that does not exist or belongs to another user returns `404 passkey_not_found`.

## WebAuthn MFA factors (`auth.mfa.*`)

A second factor that upgrades an existing session to `aal2`; also drives `getAuthenticatorAssuranceLevel()`. All endpoints require a Bearer access token.

| Method | Path | supabase-js |
|--------|------|-------------|
| `POST` | `/auth/v1/factors` | `mfa.enroll({ factorType: 'webauthn', friendlyName })` |
| `POST` | `/auth/v1/factors/{id}/challenge` | `mfa.challenge({ factorId })` |
| `POST` | `/auth/v1/factors/{id}/verify` | `mfa.verify({ factorId, challengeId, ... })` |
| `DELETE` | `/auth/v1/factors/{id}` | `mfa.unenroll({ factorId })` |

Flow: `enroll` creates an `unverified` factor and returns `credential_creation_options`; `challenge` issues a single-use challenge (5&nbsp;min TTL) with creation options (registration) or request options (authentication); `verify` consumes the challenge, marks the factor `verified`, upgrades the session to `aal2`, and returns a rotated `access_token` / `refresh_token`. Factors appear on `GET /auth/v1/user` under `factors`, backing `mfa.listFactors()`.

Relying Party defaults (`127.0.0.1` / `supa-emu`) are overridable via `-webauthn-rp-id`, `-webauthn-rp-name`.

## License

[LICENSE](./LICENSE)
