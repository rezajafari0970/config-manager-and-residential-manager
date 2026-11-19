package panel

import (
	"bytes"
	"context"

	"io"
	"net/http/httptest"
	"testing"
)

func TestRawAllPrintsOriginalBodiesAndRetiresZIP(t *testing.T) {
	s := testStore(t)
	_, first := addConversion(t, s, " \n"+conversionSample+"\n ")
	if err := s.CompleteProbe(context.Background(), conversionResult(first, 0, true)); err != nil {
		t.Fatal(err)
	}
	_, next := addConversion(t, s, "vless://00000000-0000-4000-8000-000000000002@192.0.2.15:443?security=tls&sni=example.com")
	if err := s.CompleteProbe(context.Background(), conversionResult(next, 0, true)); err != nil {
		t.Fatal(err)
	}
	var refs []Artifact
	if e := s.WalkOutputs(context.Background(), func(a Artifact) error { refs = append(refs, a); return nil }); e != nil {
		t.Fatal(e)
	}
	var raw [][]byte
	for _, a := range refs {
		r, e := s.vault.Open(a.Hash)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		raw = append(raw, b)
	}
	server, _ := NewServer(s, "http://127.0.0.1:18191")
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, httptest.NewRequest("GET", "http://127.0.0.1:18191/output/raw.txt", nil))
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), bytes.Join(raw, []byte{'\n'})) || w.Header().Get("Content-Disposition") != "inline" {
		t.Fatal(w.Code, w.Header())
	}
	z := httptest.NewRecorder()
	server.Handler().ServeHTTP(z, httptest.NewRequest("GET", "http://127.0.0.1:18191/output/archive.zip", nil))
	if z.Code != 308 || z.Header().Get("Location") != "/output/raw.txt" {
		t.Fatal(z.Code, z.Header())
	}
}

func TestRawSnapshotAllowsArrivalsButFencesInvalidatedMembers(t *testing.T) {
	for _, mutation := range []string{"arrival", "disable", "delete", "expire", "evidence"} {
		t.Run(mutation, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			_, j := addConversion(t, s, conversionSample)
			if err := s.CompleteProbe(ctx, conversionResult(j, 0, true)); err != nil {
				t.Fatal(err)
			}
			before, err := s.verifiedRawEntries(ctx, s.read(ctx), rawScope{})
			if err != nil || len(before) != 1 {
				t.Fatal(before, err)
			}
			captured := before[0]
			_, addition := addConversion(t, s, sourceURI(29))
			if err := s.CompleteProbe(ctx, conversionResult(addition, 0, true)); err != nil {
				t.Fatal(err)
			}
			var e error
			switch mutation {
			case "disable", "delete":
				_, e = s.ManageConfigs(ctx, ConfigBatch{Action: mutation, IDs: []string{captured.ID}})
			case "expire":
				_, e = s.db.ExecContext(ctx, "UPDATE artifacts SET expires=1 WHERE id=?", captured.ID)
			case "evidence":
				_, e = s.db.ExecContext(ctx, "UPDATE conversion_results SET valid_until=0 WHERE hash=?", captured.Hash)
			}
			if e != nil {
				t.Fatal(e)
			}
			current, e := s.verifiedRawEntries(ctx, s.read(ctx), rawScope{})
			valid := networkSnapshotCurrent(before, current)
			if e != nil || valid != (mutation == "arrival") {
				t.Fatal("snapshot admission", valid, e)
			}
		})
	}
}
