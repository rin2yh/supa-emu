package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSmoke(t *testing.T) {
	t.Run("バイナリ起動後にhealthエンドポイントが応答する", func(t *testing.T) {
		port, err := freePort()
		if err != nil {
			t.Fatalf("freePort: %v", err)
		}
		bin := buildBinary(t)
		cmd := exec.Command(bin, "-addr", "127.0.0.1:"+port)
		stdout, _ := cmd.StdoutPipe()
		stderr, _ := cmd.StderrPipe()
		if err := cmd.Start(); err != nil {
			t.Fatalf("Start: %v", err)
		}
		t.Cleanup(func() {
			_ = cmd.Process.Kill()
			_, _ = io.Copy(io.Discard, stdout)
			_, _ = io.Copy(io.Discard, stderr)
			_, _ = cmd.Process.Wait()
		})

		// ListenAndServe が立ち上がるまで待つ
		base := "http://127.0.0.1:" + port
		deadline := time.Now().Add(5 * time.Second)
		var lastErr error
		for time.Now().Before(deadline) {
			resp, err := http.Get(base + "/auth/v1/health")
			if err == nil {
				_ = resp.Body.Close()
				lastErr = nil
				break
			}
			lastErr = err
			time.Sleep(50 * time.Millisecond)
		}
		if lastErr != nil {
			t.Fatalf("server did not start: %v", lastErr)
		}

		// middleware 配線 drift を検知するため、複数経路の応答形式を確認する。
		// health: 通常応答、settings: 別 handler、unknown: 404 catch-all、user: error_code 経路。
		t.Run("/auth/v1/health は GoTrue name を返す", func(t *testing.T) {
			resp, err := http.Get(base + "/auth/v1/health")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status: %d", resp.StatusCode)
			}
			var body map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if body["name"] != "GoTrue" {
				t.Errorf("name: %v", body["name"])
			}
		})

		t.Run("/auth/v1/user は X-Supabase-Api-Version 付き 401 を返す", func(t *testing.T) {
			resp, err := http.Get(base + "/auth/v1/user")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status: %d", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Supabase-Api-Version"); got == "" {
				t.Error("X-Supabase-Api-Version header missing (middleware drift?)")
			}
		})

		t.Run("未知 path は JSON 404 を返す（catch-all）", func(t *testing.T) {
			resp, err := http.Get(base + "/auth/v1/unknown")
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status: %d", resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type: %s", got)
			}
		})
	})
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = l.Close() }()
	addr := l.Addr().String()
	return addr[strings.LastIndex(addr, ":")+1:], nil
}

func buildBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "supabase-emulator")
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build: %v", err)
	}
	return out
}
