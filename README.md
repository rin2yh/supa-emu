# supa-emu (Supabase Emulator)

A lightweight Go emulator that exposes Supabase Auth (GoTrue) compatible HTTP endpoints. As an alternative to `supabase start` (Docker), it starts up fast on CI and developer machines.

- Module name: `github.com/rin2yh/supa-emu`
- Binary name: `supabase-emulator`

A **single binary** with `main.go` as the entry point. It is designed so that services other than auth (storage/realtime) can be mounted here in the future — extending it is as simple as adding a single `Handle` line to `main.go`.

## Installation

### From GitHub Releases

Releases attach assets in the form `supabase-emulator_<version>_<os>_<arch>.tar.gz`. Download and extract them with the `gh` CLI.

macOS (arm64):

```bash
gh release download v0.1.0 \
  --repo rin2yh/supa-emu \
  --pattern 'supabase-emulator_*_darwin_arm64.tar.gz'
tar -xzf supabase-emulator_*_darwin_arm64.tar.gz
./supabase-emulator -addr 127.0.0.1:54321
```

Linux (amd64):

```bash
gh release download v0.1.0 \
  --repo rin2yh/supa-emu \
  --pattern 'supabase-emulator_*_linux_amd64.tar.gz'
tar -xzf supabase-emulator_*_linux_amd64.tar.gz
./supabase-emulator -addr 127.0.0.1:54321
```

Replace `v0.1.0` with the version tag you want. To grab the latest version, omit the tag and run something like `gh release download --repo rin2yh/supa-emu ...`.

### From go install

```bash
go install github.com/rin2yh/supa-emu@latest
```

## Build and run

### Via Makefile

```bash
make build              # Build the Go binary to bin/supabase-emulator
make run                # Build and run
make test               # Run Go tests
make test-race          # Run Go tests with the race detector
make clean              # Remove the bin directory
```

`make lint` (`go vet ./...`) and `make fmt` (`gofmt -w .`) are also available.

### Plain go commands

```bash
go build -o bin/supabase-emulator .
./bin/supabase-emulator -addr 127.0.0.1:54321

go test -count=1 ./...        # tests
go test -race -count=1 ./...  # tests with the race detector
```

## Implemented endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/auth/v1/health` | Health check |
| GET | `/auth/v1/settings` | Public settings |
| POST | `/auth/v1/signup` | Sign up (returns an `AccessTokenResponse`, assuming mailer_autoconfirm=true) |
| POST | `/auth/v1/token?grant_type=password` | Login |
| POST | `/auth/v1/token?grant_type=refresh_token` | Refresh token rotation (reuse_interval defaults to 10s) |
| GET | `/auth/v1/user` | Get the current user |
| POST | `/auth/v1/logout` | Logout (revokes the refresh token) |
| GET | `/auth/v1/admin/users` | List all users (supports page / per_page) |
| DELETE | `/auth/v1/admin/users/{id}` | Delete a user |

Any path that does not match the above is handled by a catch-all that returns `404 Not Found`.

### Emulator extensions (`/__emulator/*` for testing)

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/__emulator/reset` | Clear all in-memory state |
| GET | `/__emulator/snapshot` | Dump the current users / sessions / refresh_tokens |
| POST | `/__emulator/users` | Seed test users directly |

## CLI flags / environment variables / defaults

CLI flags take precedence over environment variables.

| Flag | Environment variable | Default |
|------|----------------------|---------|
| `-addr` | `SUPABASE_EMULATOR_ADDR` | `127.0.0.1:54321` |
| `-jwt-secret` | `SUPABASE_EMULATOR_JWT_SECRET` | Supabase CLI default |
| `-jwt-issuer` | - | `http://127.0.0.1:54321/auth/v1` |
| `-access-token-ttl` | - | `1h` |
| `-refresh-reuse-interval` | - | `10s` |

`-jwt-secret` sets the HS256 signing key, `-jwt-issuer` sets the JWT `iss` claim, `-access-token-ttl` sets the access_token lifetime, and `-refresh-reuse-interval` sets the allowed reuse window for refresh token rotation.

## Use as a GitHub Action

This repository ships a composite action that downloads the release binary, starts the emulator in the background, and waits for it to become healthy. Use it from any workflow so your integration/E2E tests can run against a live emulator.

```yaml
jobs:
  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rin2yh/supa-emu@v1
        with:
          version: latest        # or a specific tag like v0.1.0
          addr: 127.0.0.1:54321
      # The emulator is now running at 127.0.0.1:54321 for the rest of the job.
      - run: npm test            # your integration/E2E tests
```

### Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `version` | `latest` | Release tag to download (e.g. `v0.1.0`), or `latest`. |
| `addr` | `127.0.0.1:54321` | Listen address (`-addr`). |
| `jwt-secret` | (emulator default) | HS256 signing key (`-jwt-secret`). |
| `jwt-issuer` | (emulator default) | JWT `iss` claim (`-jwt-issuer`). |
| `access-token-ttl` | (emulator default) | Access token lifetime (`-access-token-ttl`). |
| `refresh-reuse-interval` | (emulator default) | Refresh token reuse window (`-refresh-reuse-interval`). |
| `wait-for-health` | `true` | Wait until `/auth/v1/health` responds before finishing. |
| `github-token` | `${{ github.token }}` | Token used to download the release asset via the `gh` CLI. |

### Outputs

| Output | Description |
|--------|-------------|
| `addr` | The address the emulator is listening on. |
| `pid` | PID of the started emulator process. |
| `log` | Path to the emulator log file. |

Runs on Linux and macOS runners (amd64 / arm64).

## Combining with application-layer integration tests

The emulator is designed so that starting and building it is not part of the test-side scripts. Start this binary in a separate terminal beforehand, then run your application-layer integration or E2E tests.

```bash
# Terminal 1: keep the emulator running
./bin/supabase-emulator -addr 127.0.0.1:54321

# Terminal 2: run integration tests or E2E
```

## Design decisions

- **In-memory only**: No persistence, since it targets testing/development. Reset state with `/__emulator/reset`.
- **No apikey validation**: apikey / Authorization are not validated. Anything you send is accepted.
- **HS256 fixed**: It adopts the same secret key as the Supabase CLI as its default, so no client-side configuration changes are needed.
- **Single binary**: When adding storage/realtime, just add a single `Handle` line to `main.go`.

## Unsupported features

- OAuth / Phone / MFA / Email confirmation / Captcha
- Email sending
- DB Hooks / Functions
- Realtime / Storage / Postgrest

## License

See [LICENSE](./LICENSE).
