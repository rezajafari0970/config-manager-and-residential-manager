package collect

import (
	"context"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"
)

func TestCollectorDisablesHysteriaBeforeMembership(t *testing.T) {
	healthy := "vless://00000000-0000-4000-8000-000000000001@192.0.2.1:443?security=tls#hy2"
	mixed := `{"outbounds":[{"protocol":"vless"},{"protocol":"hysteria","settings":{"version":2}}]}`
	disabled := "hy1://192.0.2.1\nhysteria2://192.0.2.2\njson://" + base64.StdEncoding.EncodeToString([]byte(mixed)) + "\n" + mixed + "\n"
	for _, tc := range []struct {
		body  string
		n     int
		state string
	}{{disabled + healthy, 1, "updated"}, {disabled, 0, "empty"}} {
		e, repo := pipelineFixture(t, 0)
		e.fetch = pipelineFetch{io.NopCloser(strings.NewReader(tc.body))}
		e.runJobWithBudgets(context.Background(), Job{}, time.Second, 30*time.Second)
		if repo.items != tc.n || repo.result.Extracted != tc.n || repo.result.State != tc.state {
			t.Fatalf("unexpected collection: items %d result %+v", repo.items, repo.result)
		}
	}
}
