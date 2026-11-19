package collect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/blob"
)

const allowedShare = "vless://97f4c148-2db9-420b-97aa-4e9c2abb3a36@192.0.2.1:443?security=tls#hysteria-label"

type responseWithStatus struct {
	status int
	body   string
}

func (f responseWithStatus) Name() string { return "fixture" }
func (f responseWithStatus) Fetch(context.Context, Job) (Response, error) {
	return Response{Status: f.status, Body: io.NopCloser(strings.NewReader(f.body))}, nil
}

func assertResponseBytes(t *testing.T, v *blob.Vault, ref blob.Ref, want string) {
	t.Helper()
	r, err := v.Open(ref.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil || string(b) != want {
		t.Fatal("retained source differs from expected bytes", len(b), len(want), err)
	}
}

func TestFreshSourceNeverStoresForbiddenBodyEvenOnHTTPError(t *testing.T) {
	bad := "custom://" + base64.RawURLEncoding.EncodeToString([]byte(`{"outbounds":[{"protocol":"hysteria2"}]}`))
	cases := []struct {
		name, body, kept string
		drop             bool
	}{
		{"clean_plain", allowedShare + "\r\n", allowedShare + "\r\n", false},
		{"diagnostic", "upstream temporarily unavailable", "upstream temporarily unavailable", false},
		{"blocked", bad, "", true},
		{"base64_mixed", base64.StdEncoding.EncodeToString([]byte(bad + "\n" + allowedShare)), allowedShare, false},
		{"late_blocked", `{"tag":"` + strings.Repeat("x", inspectionSampleSize+10) + `","outbounds":[{"protocol":"hysteria2"}]}`, "", true},
	}
	for _, status := range []int{200, 503} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("%d/%s", status, tc.name), func(t *testing.T) {
				engine, repo := pipelineFixture(t, 0)
				engine.fetch = responseWithStatus{status, tc.body}
				engine.runJobWithBudgets(context.Background(), Job{}, time.Second, 30*time.Second)
				got := repo.result
				if got.ReceivedBytes != int64(len(tc.body)) {
					t.Fatal("received byte count must include the complete upstream response")
				}
				if got.DiscardResponse != tc.drop || (got.Raw.Hash == "") != tc.drop {
					t.Fatal("incorrect discard decision", got)
				}
				if !tc.drop {
					assertResponseBytes(t, engine.vault, got.Raw, tc.kept)
				}
				if tc.drop || tc.kept != tc.body {
					h := fmt.Sprintf("%x.blob", sha256.Sum256([]byte(tc.body)))
					if _, err := os.Stat(filepath.Join(engine.vault.Directory(), h)); !os.IsNotExist(err) {
						t.Fatal("original forbidden body entered durable storage", err)
					}
				}
				if status == 503 && (repo.items != 0 || got.ErrorCode != "http_error") {
					t.Fatal("HTTP error staged a config", got)
				}
			})
		}
	}
}

func TestArchivePreservesCleanEncodingAndMultilineMembers(t *testing.T) {
	v, err := blob.New(t.TempDir(), bytes.Repeat([]byte{4}, 32))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clean := base64.RawStdEncoding.EncodeToString([]byte(allowedShare))
	blocked := "hy2://redacted@192.0.2.2:443"
	doc := "{\n \"outbounds\": [{\"protocol\": \"trojan\"}]\n}"
	ini := "[Interface]\nPrivateKey=key\n[Peer]\nPublicKey=peer\nEndpoint=192.0.2.5:51820"
	arr, err := json.Marshal([]any{blocked, allowedShare, json.RawMessage(doc), ini, allowedShare})
	if err != nil {
		t.Fatal(err)
	}
	// Marshal RawMessage compacts its JSON. Use the original formatted
	// object to exercise an actual multiline profile embedded in the array.
	mixed := strings.Replace(string(arr), `{"outbounds":[{"protocol":"trojan"}]}`, doc, 1)
	for _, tc := range []struct {
		body    string
		changed bool
		want    string
	}{
		{clean, false, clean},
		{blocked, true, ""},
		{mixed, true, allowedShare + "\n" + doc + "\n" + ini + "\n" + allowedShare},
	} {
		ref, err := v.Put(ctx, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		got, changed, err := SanitizeResponse(ctx, v, ref)
		if err != nil || tc.changed != changed {
			t.Fatal("archive sanitation", changed, err)
		}
		if tc.want == "" {
			if got.Hash != "" {
				t.Fatal("forbidden archive retained")
			}
		} else {
			assertResponseBytes(t, v, got, tc.want)
			if changed {
				v.Release(got.Hash)
			} else if got != ref {
				t.Fatal("clean archive encoding changed")
			}
		}
		v.Release(ref.Hash)
	}
	if err := v.Sweep(ctx, func(context.Context, string) (bool, error) { return false, nil }); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(v.Directory())
	if err != nil || len(files) != 0 {
		t.Fatal("sanitation leaked a pin", len(files), err)
	}
}
