# supa-emu (Supabase Emulator)

A lightweight Go emulator exposing Supabase Auth (GoTrue) compatible HTTP endpoints. A fast, single-binary alternative to `supabase start` (Docker) for CI and local development.

- Module: `github.com/rin2yh/supa-emu`
- Binary: `supabase-emulator`

## Install

```bash
go install github.com/rin2yh/supa-emu@latest
```

Or download a prebuilt binary from [GitHub Releases](https://github.com/rin2yh/supa-emu/releases).

## Run

```bash
go build -o bin/supabase-emulator .
./bin/supabase-emulator -addr 127.0.0.1:54321
```

| Flag | Env | Default |
|------|-----|---------|
| `-addr` | `SUPABASE_EMULATOR_ADDR` | `127.0.0.1:54321` |
| `-jwt-secret` | `SUPABASE_EMULATOR_JWT_SECRET` | Supabase CLI default |
| `-jwt-issuer` | - | `http://127.0.0.1:54321/auth/v1` |
| `-access-token-ttl` | - | `1h` |
| `-refresh-reuse-interval` | - | `10s` |

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

Supports `/auth/v1/*` (health, settings, signup, token, user, logout, admin/users) plus `/__emulator/*` test helpers (reset, snapshot, users). Unmatched paths return `404`.

In-memory only, no apikey validation, HS256 fixed. OAuth / Phone / MFA / email / Realtime / Storage are out of scope.

## License

[LICENSE](./LICENSE)
