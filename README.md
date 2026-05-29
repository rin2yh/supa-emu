# supa-emu (Supabase Emulator)

Supabase Auth (GoTrue) 互換の HTTP エンドポイントを提供する軽量 Go エミュレータ。`supabase start`（Docker）の代替として、CI や開発機で高速に起動できる。

- モジュール名: `github.com/rin2yh/supa-emu`
- バイナリ名: `supabase-emulator`

`main.go` がエントリポイントの**シングルバイナリ**。auth 以外（storage/realtime）も今後ここに mount する設計で、`main.go` に `Handle` を 1 行足すだけで拡張できる。

## インストール

### GitHub Releases から

リリースには `supabase-emulator_<version>_<os>_<arch>.tar.gz` 形式のアセットが添付される。`gh` CLI でダウンロードして展開する。

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

`v0.1.0` は取得したいバージョンタグに置き換えること。最新版を取得する場合はタグを省略して `gh release download --repo rin2yh/supa-emu ...` のように指定できる。

### go install から

```bash
go install github.com/rin2yh/supa-emu@latest
```

## ビルドと起動

### Makefile 経由

```bash
make build              # Go バイナリを bin/supabase-emulator にビルド
make run                # ビルドして起動
make test               # Go テストを実行
make test-race          # Race detector 付きで Go テストを実行
make clean              # bin ディレクトリを削除
```

その他に `make lint`（`go vet ./...`）、`make fmt`（`gofmt -w .`）が利用できる。

### 素の go コマンド

```bash
go build -o bin/supabase-emulator .
./bin/supabase-emulator -addr 127.0.0.1:54321

go test -count=1 ./...        # テスト
go test -race -count=1 ./...  # Race detector 付きテスト
```

## 実装済みエンドポイント

| Method | Path | 用途 |
|--------|------|------|
| GET | `/auth/v1/health` | ヘルスチェック |
| GET | `/auth/v1/settings` | 公開設定 |
| POST | `/auth/v1/signup` | サインアップ（mailer_autoconfirm=true 想定で `AccessTokenResponse` を返す） |
| POST | `/auth/v1/token?grant_type=password` | ログイン |
| POST | `/auth/v1/token?grant_type=refresh_token` | refresh token rotation（reuse_interval 既定 10 秒） |
| GET | `/auth/v1/user` | 現在ユーザー取得 |
| POST | `/auth/v1/logout` | ログアウト（refresh token 失効） |
| GET | `/auth/v1/admin/users` | 全ユーザー一覧（page / per_page サポート） |
| DELETE | `/auth/v1/admin/users/{id}` | ユーザー削除 |

上記に一致しないパスはすべて catch-all で `404 Not Found` を返す。

### エミュレータ拡張（テスト用 `/__emulator/*`）

| Method | Path | 用途 |
|--------|------|------|
| POST | `/__emulator/reset` | 全インメモリ State クリア |
| GET | `/__emulator/snapshot` | users / sessions / refresh_tokens の現状ダンプ |
| POST | `/__emulator/users` | テスト用ユーザの直接シード |

## CLIフラグ / 環境変数 / 既定値

CLI フラグは環境変数より優先される。

| フラグ | 環境変数 | 既定値 |
|--------|----------|--------|
| `-addr` | `SUPABASE_EMULATOR_ADDR` | `127.0.0.1:54321` |
| `-jwt-secret` | `SUPABASE_EMULATOR_JWT_SECRET` | Supabase CLI 既定値 |
| `-jwt-issuer` | - | `http://127.0.0.1:54321/auth/v1` |
| `-access-token-ttl` | - | `1h` |
| `-refresh-reuse-interval` | - | `10s` |

`-jwt-secret` は HS256 の署名鍵、`-jwt-issuer` は JWT の `iss` クレーム、`-access-token-ttl` は access_token の有効期間、`-refresh-reuse-interval` は refresh token rotation の再利用許容間隔を指定する。

## アプリ層の結合テストと組み合わせる

エミュレータの起動・ビルドはテスト側スクリプトに含めない設計。事前にこのバイナリを別ターミナルで起動しておき、アプリ層の結合テストや E2E を実行する。

```bash
# ターミナル1: エミュレータを起動しっぱなしにする
./bin/supabase-emulator -addr 127.0.0.1:54321

# ターミナル2: 結合テスト or E2E を実行
```

## 設計判断

- **インメモリのみ**: テスト/開発用途のため永続化なし。`/__emulator/reset` で初期化。
- **apikey 検証なし**: apikey / Authorization の検証は行わない。何を送っても通る。
- **HS256 固定**: Supabase CLI と同じ秘密鍵を既定値に採用しているため、クライアント側の設定変更が不要。
- **シングルバイナリ**: storage/realtime を追加するときは `main.go` に `Handle` を 1 行足すだけ。

## 未対応機能

- OAuth / Phone / MFA / Email confirmation / Captcha
- メール送信
- DB Hooks / Functions
- Realtime / Storage / Postgrest

## ライセンス

[LICENSE](./LICENSE) を参照。
