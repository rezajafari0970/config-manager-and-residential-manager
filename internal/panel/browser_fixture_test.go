package panel

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const browserURI = "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls&sni=vpn.example#Original%20Label\r\n"
const browserUnreachable = "trojan://fixture@192.0.2.3:443?sni=failed.example#FixtureFailed\n"
const browserJSON = "{ \"outbounds\" : [{\"protocol\":\"vless\",\"settings\":{\"address\":\"vpn.example\",\"port\":443,\"id\":\"00000000-0000-4000-8000-000000000002\"}}], \"stats\" : [], \"opaque\" : 9007199254740993 }\r\n"

type browserDriver struct{}

func (browserDriver) Name() string { return "synthetic-browser-fixture.v1" }
func (browserDriver) Fetch(ctx context.Context, job collect.Job) (collect.Response, error) {
	if dir := os.Getenv("CONFIG_PANEL_BROWSER_FIXTURE_DIR"); dir != "" {
		if _, e := os.Stat(filepath.Join(dir, "upstream-offline")); e == nil {
			return collect.Response{}, errors.New("synthetic upstream outage")
		}
	}
	if strings.Contains(job.URL, "Broken") {
		return collect.Response{}, errors.New("synthetic failure")
	}
	if strings.Contains(job.URL, "Slow") {
		<-ctx.Done()
		return collect.Response{}, ctx.Err()
	}
	body := browserURI
	if strings.Contains(job.URL, "Verde") {
		blockedProfile := base64.RawStdEncoding.EncodeToString([]byte(`{"outbounds":[{"protocol":"hysteria2","settings":{"address":"blocked.invalid","port":443}}]}`))
		body = browserURI + browserURI + browserJSON + browserUnreachable + "hy2://fixture@blocked.invalid:443\njson://" + blockedProfile + "\n"
	}
	if strings.Contains(job.URL, "Empty") {
		body = "\n"
	}
	return collect.Response{Status: 200, Body: io.NopCloser(strings.NewReader(body)), ETag: `"synthetic-browser"`}, nil
}

// Explicit development harness, skipped by normal CI. Never compiled into cmd/config-panel.
func TestBrowserFixtureServer(t *testing.T) {
	dir := os.Getenv("CONFIG_PANEL_BROWSER_FIXTURE_DIR")
	if dir == "" {
		t.Skip("browser harness not requested")
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	origin := "http://" + listener.Addr().String()
	store, e := Open(filepath.Join(dir, "data", "panel.db"), bytes.Repeat([]byte{17}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	app, e := NewServer(store, origin)
	if e != nil {
		t.Fatal(e)
	}
	engine := collect.NewEngine(store, store.vault, browserDriver{})
	app.SetEngine(engine)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- engine.Run(ctx) }()
	preparerDone := make(chan struct{})
	go func() { defer close(preparerDone); store.RunPreparer(ctx) }()
	defer func() { stop(); <-preparerDone }()
	// Synthetic UI evidence only; this harness is never part of a shipped binary.
	converted := make(chan struct{})
	go func() {
		defer close(converted)
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				j, e := store.ClaimProbe(ctx)
				if e != nil || j == nil {
					continue
				}
				if len(convert.Prepare(j.Raw).Candidates) == 0 {
					continue
				}
				r := conversionResult(*j, 0, !bytes.Contains(j.Raw, []byte("#FixtureFailed")))
				_ = store.CompleteProbe(ctx, r)
			}
		}
	}()

	server := &http.Server{Addr: listener.Addr().String(), Handler: app.Handler(), ReadHeaderTimeout: 5 * time.Second}
	httpDone := make(chan error, 1)
	go func() { httpDone <- server.Serve(listener) }()
	ready, _ := json.Marshal(map[string]any{"origin": origin, "pid": os.Getpid()})
	if e := os.WriteFile(filepath.Join(dir, "ready.json"), ready, 0600); e != nil {
		t.Fatal(e)
	}
	select {
	case <-ctx.Done():
	case e := <-httpDone:
		t.Fatal(e)
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server.Shutdown(shutdown)
	<-converted
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
