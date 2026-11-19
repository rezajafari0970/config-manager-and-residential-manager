package collect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCollectorDisablesHysteriaBeforeMembership(t *testing.T) {
	healthy := "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls#hy2"
	mixed := `{"outbounds":[{"protocol":"vless"},{"protocol":"hysteria","settings":{"version":2}}]}`
	disabled := "hy1://192.0.2.1\nhysteria2://192.0.2.2\njson://" + base64.StdEncoding.EncodeToString([]byte(mixed)) + "\n" + mixed + "\n"
	quoted, _ := json.Marshal(healthy + "\nhy2://blocked.example\ntrojan://key@192.0.2.1:443")
	other := "trojan://key@192.0.2.1:443"
	nested, _ := json.Marshal([]string{healthy + "\nhysteria2://disabled.invalid" + "\n" + other})
	for _, tc := range []struct {
		body  string
		n     int
		state string
	}{{disabled + healthy, 1, "updated"}, {disabled, 0, "empty"}, {string(quoted), 2, "updated"}, {string(nested), 2, "updated"}} {
		e, repo := pipelineFixture(t, 0)
		e.fetch = pipelineFetch{io.NopCloser(strings.NewReader(tc.body))}
		e.runJobWithBudgets(context.Background(), Job{}, time.Second, 30*time.Second)
		if repo.items != tc.n || repo.result.Extracted != tc.n || repo.result.State != tc.state {
			t.Fatalf("unexpected collection: items %d result %+v", repo.items, repo.result)
		}
	}
}

func TestSourcePolicyRecognizesForbiddenEnvelopesAndLeavesMetadataAlone(t *testing.T) {
	ctx := context.Background()
	hy := "hysteria2://password@example.com:8443"
	hidden := base64.RawURLEncoding.EncodeToString([]byte(hy))
	quoted, _ := json.Marshal(hidden)
	for _, tc := range []struct {
		body  string
		dirty bool
	}{
		{hy, true},
		{string(quoted), true},
		{url.PathEscape(hy), true},
		{strconv.Quote(url.PathEscape(hy)), true},
		{`{"type":"custom","config":"json://` + base64.RawURLEncoding.EncodeToString([]byte(`{"outbound":{"protocol":"hy2"}}`)) + `"}`, true},
		{"proxies:\n - {name: custom, type: hysteria2, server: proxy.example}\n", true},
		{base64.StdEncoding.EncodeToString([]byte("payload:\n - " + hy + "\n")), true},
		{"proxies:\n - {name: hysteria2, type: trojan, server: proxy.example}\n", false},
		{"payload:\n - 'DOMAIN-SUFFIX,example.org'\n", false},
		{`{"error":"Hysteria not available"}`, false},
	} {
		e, repo := pipelineFixture(t, 0)
		e.fetch = pipelineFetch{io.NopCloser(strings.NewReader(tc.body))}
		e.runJobWithBudgets(ctx, Job{}, time.Second, 30*time.Second)
		if got := repo.result.DiscardResponse; got != tc.dirty {
			t.Fatalf("discard=%v want=%v for %s; %+v", got, tc.dirty, tc.body, repo.result)
		}
	}
	for _, kind := range []string{"hysteria", "hysteria2", "tuic", "socks", "ssh"} {
		if kindOf([]byte(kind+"://example.com")) != "unsupported" || NewInspectionRegistry().Inspect([]byte(kind+"://example.com"), true, kind) == "valid" {
			t.Fatalf("%s has an active collector", kind)
		}
	}
}
