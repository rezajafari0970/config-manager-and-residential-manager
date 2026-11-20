package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestSideWorkerSendsEvidenceWithExactBytesAndIdentity(t *testing.T) {
	cfg, err := settingsForLane("side")
	ordinary, _ := settingsForLane("conversion")
	if err != nil || cfg.prefix != "/side" || ordinary.prefix != "" || cfg.lock == ordinary.lock || cfg.helper == ordinary.helper {
		t.Fatal("worker lanes share a namespace")
	}
	if _, err := settingsForLane("other"); err == nil {
		t.Fatal("unknown work queue")
	}
	candidate := []byte(`{"fixture":true}`)
	hash := repair.Digest(candidate)
	raw := []byte("local fixture")
	j := probe.Job{Identity: "canonical", Hash: repair.Digest(raw), Token: "leased", Raw: raw, Settings: probe.Settings{TimeoutSeconds: 2}}
	helper := filepath.Join(t.TempDir(), "fixture.py")
	script := `import json, sys
if '--cleanup-slot' not in sys.argv:
    config = json.load(sys.stdin)['plan']['candidates'][0]
    print(json.dumps({'sha256':config['sha256'], 'code':'passed', 'evidence':{'candidate_sha256':config['sha256']}}))
`
	if err := os.WriteFile(helper, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	var receipts []probe.Result
	c := client{prefix: cfg.prefix, version: "test", prepare: func(raw []byte) probe.Plan {
		return probe.Plan{Candidates: []probe.Candidate{{SHA256: hash, Config: candidate}}}
	}, http: &http.Client{Transport: testTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/side/complete" {
			t.Fatalf("unexpected RPC %s", r.URL.Path)
		}
		var got probe.Result
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, got)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("true"))}, nil
	})}}
	execute(context.Background(), c, helper, "fixture-core", 1, j)
	j.Raw = []byte("changed after grant")
	execute(context.Background(), c, helper, "fixture-core", 1, j)
	if len(receipts) != 2 || receipts[0].Identity != j.Identity || receipts[0].Token != j.Token ||
		string(receipts[0].Candidate) != string(candidate) || receipts[0].Evidence["candidate_sha256"] != hash ||
		receipts[1].Code != "original_blob_unavailable" || len(receipts[1].Candidate) != 0 {
		t.Fatal("changed bytes or unissued candidate used for the receipt")
	}
}
