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
| `-webauthn-rp-id` | - | `localhost` |
| `-webauthn-rp-name` | - | `supa-emu` |
| `-webauthn-rp-origin` | - | `http://localhost:3000` |

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

Supports `/auth/v1/*` (health, settings, signup, token, user, logout, factors, admin/users) plus `/__emulator/*` test helpers (reset, snapshot, users). Unmatched paths return `404`.

In-memory only, no apikey validation, HS256 fixed. OAuth / Phone / TOTP / email / Realtime / Storage are out of scope.

## Passkey (WebAuthn MFA)

Emulates the GoTrue passkey factor API so `supabase.auth.mfa.*` and `getAuthenticatorAssuranceLevel()` can be exercised in tests. All endpoints require a Bearer access token.

| Method | Path | supabase-js |
|--------|------|-------------|
| `POST` | `/auth/v1/factors` | `mfa.enroll({ factorType: 'webauthn', friendlyName })` |
| `POST` | `/auth/v1/factors/{id}/challenge` | `mfa.challenge({ factorId })` |
| `POST` | `/auth/v1/factors/{id}/verify` | `mfa.verify({ factorId, challengeId, ... })` |
| `DELETE` | `/auth/v1/factors/{id}` | `mfa.unenroll({ factorId })` |

Flow: `enroll` creates an `unverified` factor and returns `credential_creation_options`; `challenge` issues a single-use challenge (5&nbsp;min TTL) with creation options (registration) or request options (authentication); `verify` consumes the challenge, marks the factor `verified`, upgrades the session to `aal2`, and returns a rotated `access_token` / `refresh_token`. Factors appear on `GET /auth/v1/user` under `factors`, backing `mfa.listFactors()`.

Because there is no real authenticator, the emulator does **not** verify WebAuthn attestation/assertion signatures — any `credential_response` is accepted. Relying Party defaults (`localhost` / `supa-emu` / `http://localhost:3000`) are overridable via `-webauthn-rp-id`, `-webauthn-rp-name`, `-webauthn-rp-origin`.

## License

[LICENSE](./LICENSE)
