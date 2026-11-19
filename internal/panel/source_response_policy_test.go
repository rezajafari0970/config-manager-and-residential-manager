package panel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSourceResponseAppliesProtocolPolicyBeforeOriginalDownload(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	id, err := store.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewServer(store, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	mixed := conversionSample + "\nhy://blocked.invalid:443\n"
	clash := "proxies:\n - name: example\n   type: hysteria2\n   server: blocked.invalid\n"
	for _, tt := range []struct {
		name, raw string
		blocked   bool
	}{
		{"allowed_exact_bytes", conversionSample + "\r\n", false},
		{"incidental_text", `{"remarks":"hysteria2","outbounds":[{"protocol":"vless","tag":"hy2","settings":{"address":"hysteria.example"}}]}`, false},
		{"unrelated_error", "[Peer]\nPublicKey=invalid\n", false},
		{"mixed_source", mixed, true},
		{"json_metadata", `{"payload":"hysteria2","status":"unavailable"}`, false},
		{"json_proxy_payload", `{"payload":[{"type":"hysteria2","server":"blocked.invalid"}]}`, true},
		{"yaml_share_payload", "payload:\n - hy2://credential@blocked.invalid:443\n", true},
		{"clash", clash, true},
		{"encoded_clash", base64.StdEncoding.EncodeToString([]byte(clash)), true},
		{"allowed_clash", "proxies:\n - {name: hysteria2, type: vless, server: hysteria.example}\n", false},
		{"encoded_mixed_source", base64.StdEncoding.EncodeToString([]byte(mixed)), true},
		{"native_profile", `{"outbounds":[{"type":"hysteria2","server":"blocked.invalid"}]}`, true},
		{"standalone_profile", `{"type":"hysteria","server":"blocked.invalid"}`, true},
		{"custom_share", "json://" + base64.RawURLEncoding.EncodeToString([]byte(`{"outbounds":[{"protocol":"vless","streamSettings":{"network":"hysteria"}}]}`)), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ref, err := store.vault.Put(ctx, strings.NewReader(tt.raw))
			if err != nil {
				t.Fatal(err)
			}
			defer store.vault.Release(ref.Hash)
			now := time.Now()
			_, err = store.db.ExecContext(ctx, "INSERT OR REPLACE INTO responses(source_id,hash,size,created,expires) VALUES(?,?,?,?,?)",
				id, ref.Hash, ref.Size, now.UnixMilli(), now.Add(time.Hour).UnixMilli())
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			api := "http://127.0.0.1:18191/input/raw/" + id
			server.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, api, nil))
			if !tt.blocked {
				if w.Code != http.StatusOK || w.Body.String() != tt.raw || w.Header().Get("X-Content-SHA256") != ref.Hash {
					t.Fatalf("allowed original changed: status %d", w.Code)
				}
				return
			}
			var message map[string]string
			if w.Code != http.StatusConflict || json.Unmarshal(w.Body.Bytes(), &message) != nil || message["export_url"] != server.exportURL(id, false) ||
				w.Header().Get("X-Content-SHA256") != "" || strings.Contains(w.Body.String(), "blocked.invalid") {
				t.Fatalf("blocked original was available or lacked safe alternative: status %d", w.Code)
			}
		})
	}
}
