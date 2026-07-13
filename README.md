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

One row per endpoint. Per-endpoint behavior and rationale live in the godoc next
to each handler (`internal/auth/handler/*.go`) — this table is just the map, so
adding an endpoint means adding a row here and the detail in code, not a new
prose section.

| Method | Path | supabase-js | Notes |
|--------|------|-------------|-------|
| `GET` | `/auth/v1/health` | — | liveness |
| `GET` | `/auth/v1/settings` | — | provider / flag discovery |
| `POST` | `/auth/v1/signup` | `signUp` | email + password |
| `POST` | `/auth/v1/token?grant_type=password` | `signInWithPassword` | |
| `POST` | `/auth/v1/token?grant_type=refresh_token` | `refreshSession` | rotating refresh tokens |
| `POST` | `/auth/v1/token?grant_type=pkce` | `exchangeCodeForSession` | body `{ auth_code, code_verifier }`; code single-use |
| `GET` | `/auth/v1/user` | `getUser` | Bearer; includes `identities`, `factors` |
| `GET` | `/auth/v1/authorize` | `signInWithOAuth` entry | `302` → `redirect_to?code=…`; needs `provider` + `redirect_to`; `login_hint` optional |
| `GET` | `/auth/v1/user/identities/authorize` | `linkIdentity` | Bearer; `200 { url }` or empty `302` |
| `DELETE` | `/auth/v1/user/identities/{identity_id}` | `unlinkIdentity` | Bearer; `204`; matches `identity.identity_id` |
| `POST` | `/auth/v1/logout` | `signOut` | Bearer |
| `POST` | `/auth/v1/factors` | `mfa.enroll` | Bearer; `webauthn` only |
| `POST` | `/auth/v1/factors/{factorId}/challenge` | `mfa.challenge` | Bearer |
| `POST` | `/auth/v1/factors/{factorId}/verify` | `mfa.verify` | Bearer; upgrades session to `aal2` |
| `DELETE` | `/auth/v1/factors/{factorId}` | `mfa.unenroll` | Bearer |
| `POST` | `/auth/v1/passkeys/registration/options` | `passkey.register` | Bearer |
| `POST` | `/auth/v1/passkeys/registration/verify` | `passkey.register` | Bearer; body `{ challenge_id, credential }` |
| `POST` | `/auth/v1/passkeys/authentication/options` | `passkey.signIn` | no auth (discoverable) |
| `POST` | `/auth/v1/passkeys/authentication/verify` | `passkey.signIn` | no auth; returns GoTrue token response |
| `GET` | `/auth/v1/passkeys` | `passkey.list` | Bearer; top-level JSON array |
| `DELETE` | `/auth/v1/passkeys/{id}` | `passkey.unenroll` | Bearer; `{id}` is the passkey record id, not the credential id |
| `GET` | `/auth/v1/admin/users` | `admin.listUsers` | |
| `DELETE` | `/auth/v1/admin/users/{id}` | `admin.deleteUser` | |
| `POST` | `/__emulator/reset` | test helper | clears all state |
| `GET` | `/__emulator/snapshot` | test helper | dumps the store |
| `POST` | `/__emulator/users` | test helper (seed) | `{ email, password, identities?: [{ provider, identity_data? }] }` |

Unmatched paths return `404`.

### Notes

- **In-memory only**, no apikey validation, HS256 with a fixed secret. Phone / TOTP / email / Realtime / Storage are out of scope.
- **WebAuthn and OAuth are emulated locally**: no real authenticator, no real provider — attestation/assertion signatures and PKCE are **not verified**. The two WebAuthn features share the `-webauthn-rp-*` Relying Party settings (default `127.0.0.1` / `supa-emu`) but are otherwise separate: passwordless **passkeys** are a primary login (a new session from an unauthenticated request), **MFA factors** are a second factor that upgrades a session to `aal2`.
- **OAuth sign-in** completes in-process: `/auth/v1/authorize` fabricates a provider identity, mints a single-use code (5&nbsp;min TTL) and redirects to `redirect_to?code=…`; the `pkce` grant swaps it for a session whose `amr` is `oauth`. `login_hint` fixes the email (find-or-create); otherwise a unique address is synthesized per flow. `linkIdentity`'s authorize points at this same local `/auth/v1/authorize`.
- **Identity seeding**: `POST /__emulator/users` with an `identities` array attaches provider identities on top of the default `email` identity and updates `app_metadata.providers`, so `getUserIdentities()` / `linked:true` holds without an OAuth round trip.
- **Bearer endpoints** share a `401` classification: `no_authorization` / `bad_jwt` / `session_not_found`. Passkey and MFA challenges are single-use with a 5&nbsp;min TTL.

## License

[LICENSE](./LICENSE)
