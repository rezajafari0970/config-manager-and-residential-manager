package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func prepareAll(t *testing.T, s *Store) {
	t.Helper()
	for i := 0; i < 20; i++ {
		n, e := s.PrepareBatch(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if n < 128 {
			return
		}
	}
	t.Fatal("preparation did not drain")
}
func TestPreparationIndependentOfHealthAndSourceIsolation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raws := []string{}
	for i := 0; i < 200; i++ {
		raws = append(raws, sourceURI(1000+i))
	}
	a, _ := newExportSource(t, s, "bulk", raws...)
	b, _ := newExportSource(t, s, "other", sourceURI(9))
	if _, e := s.db.Exec("DELETE FROM conversion_results;UPDATE conversion_jobs SET state='queued',next_run=0"); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	prepareAll(t, s)
	t.Log("200 preparations", time.Since(start))
	stats, e := s.SourceConversionSummaries(ctx, []Source{{ID: a}, {ID: b}})
	if e != nil || stats[a].Prepared != 200 || stats[a].Ready != 0 || stats[a].Pending != 200 || stats[b].Prepared != 1 {
		t.Fatal(stats, e)
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	fetch := func(path string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		app.preparedExport(rr, httptest.NewRequest("GET", path, nil))
		return rr
	}
	rr := fetch("/api/prepared/export?source=" + a)
	if rr.Code != 200 || rr.Header().Get("X-Config-Count") != "200" || !strings.Contains(rr.Header().Get("X-Verification-Scope"), "not-verified") {
		t.Fatal(rr.Code, rr.Header())
	}
	var profiles []json.RawMessage
	if e := json.Unmarshal(rr.Body.Bytes(), &profiles); e != nil || len(profiles) != 200 {
		t.Fatal("invalid import array", e)
	}
	first := fetch("/api/prepared/export?source=" + a + "&single=1")
	second := fetch("/api/prepared/export?source=" + a + "&single=1")
	if first.Code != 200 || second.Code != 200 || first.Body.String() == second.Body.String() {
		t.Fatal("rotation failed")
	}
	rows, e := preparedEntries(ctx, s.reader(), a, "xray")
	if e != nil {
		t.Fatal(e)
	}
	if used, e := s.Referenced(ctx, rows[0].Candidate); !used || e != nil {
		t.Fatal("prepared blob not protected from GC", e)
	}
	if _, e := s.ManageConfigs(ctx, ConfigBatch{Action: "disable", IDs: []string{rows[0].ID}}); e != nil {
		t.Fatal(e)
	}
	rr = fetch("/api/prepared/export?source=" + a)
	if rr.Header().Get("X-Config-Count") != "199" {
		t.Fatal("disabled template leaked")
	}
}

func TestExactCandidateReceiptReuseDoesNotCrossDifferentBytes(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, job := addConversion(t, s, conversionSample)
	source := testSource()
	source.URL = "https://example.com/alias"
	id, e := s.Save(ctx, "", 0, source)
	if e != nil {
		t.Fatal(e)
	}
	fetched := claimOne(t, s, id)
	alias := conversionSample + "-alias"
	different := sourceURI(44)
	result := fixtureResult(t, s, alias)
	result.Items = append(result.Items, fixtureResult(t, s, different).Items...)
	if e = s.Complete(ctx, fetched, result, time.Now()); e != nil {
		t.Fatal(e)
	}
	prepareAll(t, s)
	if e = s.CompleteProbe(ctx, conversionResult(job, 0, true)); e != nil {
		t.Fatal(e)
	}
	var proof, origin string
	hash := repair.Digest([]byte(alias))
	e = s.db.QueryRow("SELECT candidate_hash FROM conversion_results WHERE hash=?", hash).Scan(&proof)
	if e != nil || proof != convert.Prepare(job.Raw).Candidates[0].SHA256 {
		t.Fatal("identical bytes not reused", e)
	}
	if e = s.db.QueryRow("SELECT json_extract(metadata,'$.reused_from_raw_sha256') FROM conversion_evidence WHERE hash=?", hash).Scan(&origin); e != nil || origin != job.Hash {
		t.Fatal("receipt provenance lost", e)
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM conversion_results WHERE hash=?", repair.Digest([]byte(different))).Scan(&count)
	if count != 0 {
		t.Fatal("proof crossed credentials/endpoint")
	}
}

func TestPreparedExportUsesProvenRepairAlternative(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, j := addConversion(t, s, "trojan://secret@192.0.2.1:443?security=none&sni=example.com")
	prepareAll(t, s)
	result := conversionResult(j, 1, true)
	if e := s.CompleteProbe(ctx, result); e != nil {
		t.Fatal(e)
	}
	entries, e := preparedEntries(ctx, s.reader(), source, "xray")
	if e != nil || len(entries) != 1 || !entries[0].Healthy || entries[0].Candidate != result.SHA256 {
		t.Fatal("working repair was replaced by initial hypothesis", entries, e)
	}
}

func BenchmarkPreparationBatch200(b *testing.B) {
	raw := []byte(fmt.Sprintf("%s", conversionSample))
	b.ReportAllocs()
	for b.Loop() {
		for i := 0; i < 200; i++ {
			convert.Prepare(raw)
		}
	}
}
