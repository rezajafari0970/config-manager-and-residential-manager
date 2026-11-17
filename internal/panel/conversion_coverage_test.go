package panel

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/native"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCoverageSeventeenInputsAndVerifiedExportsAgree(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raws := []string{}
	for i := 1; i <= 17; i++ {
		raws = append(raws, sourceURI(i))
	}
	id, _ := newExportSource(t, s, "seventeen", raws...)
	prepareAll(t, s)
	rows, e := s.Conversions(ctx, 0, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range rows {
		if e = s.saveNetwork(ctx, c.Hash, networkclass.Result{Datacenter: "amazon", CDN: "none", Reason: "fixture", Checked: time.Now().UnixMilli(), Expires: time.Now().Add(time.Hour).UnixMilli()}); e != nil {
			t.Fatal(e)
		}
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	check := func(want int) {
		t.Helper()
		stats, e := s.SourceConversionSummaries(ctx, []Source{{ID: id}})
		if e != nil {
			t.Fatal(e)
		}
		c := stats[id].Coverage
		if c.Total != 17 || c.Ready != want || c.Total != c.Ready+c.Queued+c.Running+c.Structural+c.ConnectionFailed+c.Environment+c.Expired {
			t.Fatalf("unaccounted input: %+v", c)
		}
		for _, url := range []string{app.origin + "/api/prepared/export?source=" + id, app.networkURL("datacenter", "amazon", "configs.json"), app.networkURL("datacenter", "amazon", "raw.txt")} {
			rr := exportRequest(t, app.Handler(), "GET", url)
			if rr.Code != 200 {
				t.Fatal(rr.Code, rr.Body.String())
			}
			var count int
			if _, e := fmt.Sscan(rr.Header().Get("X-Config-Count"), &count); e != nil || count != want {
				t.Fatal(url, count, want)
			}
		}
		rr := httptest.NewRecorder()
		app.networkSummary(rr, httptest.NewRequest("GET", "/api/datacenter", nil))
		var out struct {
			Datacenters []networkGroup `json:"datacenters"`
		}
		if e = json.Unmarshal(rr.Body.Bytes(), &out); e != nil {
			t.Fatal(e)
		}
		for _, g := range out.Datacenters {
			if g.ID == "amazon" && (g.Inventory != 17 || g.Raw != want || g.Ready != want || g.Coverage.Total != 17) {
				t.Fatalf("group count mismatch: %+v", g)
			}
		}
	}
	check(17)
	if _, e = s.db.Exec("UPDATE conversion_results SET connection='failed',valid_until=0,code='proxy_request_failed' WHERE hash=?", rows[0].Hash); e != nil {
		t.Fatal(e)
	}
	check(16)
}

func TestMixedNativeNetworkIdentityCoverage(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "xray", sourceURI(33))
	_, j := addConversion(t, s, "hy2://synthetic@192.0.2.55:443?sni=example.com")
	c := convert.Prepare(j.Raw).Candidates[0]
	evidence := syntheticCompatibilityEvidence()
	evidence["native_core"] = "passed"
	evidence["runtime_core"] = "sing_box_1_14_4"
	r := probe.Result{Hash: j.Hash, Token: j.Token, Revision: j.Revision, Version: convert.Version, CoreSHA256: native.NativeSHA, Candidate: c.Config, Attempt: probe.Attempt{Engine: "sing-box", SHA256: c.SHA256, Rule: c.Rule, Core: "passed", Connection: "passed", Code: "https_payload_verified", RuntimeSHA256: c.SHA256, EndpointsPassed: 2, Evidence: evidence}}
	if e := s.CompleteProbe(ctx, r); e != nil {
		t.Fatal(e)
	}
	prepareAll(t, s)
	rows, e := s.Conversions(ctx, 0, true)
	if e != nil {
		t.Fatal(e)
	}
	for _, c := range rows {
		if e = s.saveNetwork(ctx, c.Hash, networkclass.Result{Datacenter: "amazon", CDN: "none", Reason: "fixture", Checked: time.Now().UnixMilli(), Expires: time.Now().Add(time.Hour).UnixMilli()}); e != nil {
			t.Fatal(e)
		}
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	for file, want := range map[string]string{"raw.txt": "2", "configs.json": "1", "native.jsonl": "1", "native-next.json": "1"} {
		rr := exportRequest(t, app.Handler(), "GET", app.networkURL("datacenter", "amazon", file))
		if rr.Code != 200 || rr.Header().Get("X-Config-Count") != want {
			t.Fatal(file, rr.Code, rr.Header())
		}
	}
}

func TestFirstProbeFIFOBeatsNewLowHash(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "fifo", sourceURI(41), sourceURI(42), sourceURI(43))
	var oldest string
	if e := s.db.QueryRow("SELECT max(hash) FROM conversion_jobs").Scan(&oldest); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec("DELETE FROM conversion_receipts;DELETE FROM conversion_results;UPDATE conversion_jobs SET state='queued',version='',token='',next_run=0;UPDATE conversion_schedule SET created=2"); e != nil {
		t.Fatal(e)
	}
	s.db.Exec("UPDATE conversion_schedule SET created=1 WHERE hash=?", oldest)
	j, e := s.ClaimProbe(ctx)
	if e != nil || j == nil || j.Hash != oldest {
		t.Fatal("new low hash bypassed older input", j, e)
	}
}

func TestReceiptSurvivesResponseChurnWithoutExtendingProof(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, job := addConversion(t, s, conversionSample)
	if e := s.CompleteProbe(ctx, conversionResult(job, 0, true)); e != nil {
		t.Fatal(e)
	}
	var tested, until int64
	s.db.QueryRow("SELECT tested,valid_until FROM conversion_results WHERE hash=?", job.Hash).Scan(&tested, &until)
	// Ordinary response retirement, not an explicit user deletion/restoration.
	if _, e := s.db.Exec("DELETE FROM memberships;DELETE FROM conversion_jobs"); e != nil {
		t.Fatal(e)
	}
	src := testSource()
	src.URL = "https://example.com/new-label"
	id, e := s.Save(ctx, "", 0, src)
	if e != nil {
		t.Fatal(e)
	}
	alias := conversionSample + "-new-label"
	fetch := claimOne(t, s, id)
	if e = s.Complete(ctx, fetch, fixtureResult(t, s, alias), time.Now()); e != nil {
		t.Fatal(e)
	}
	prepareAll(t, s)
	var gotTested, gotUntil int64
	var proof string
	if e = s.db.QueryRow("SELECT tested,valid_until,candidate_hash FROM conversion_results WHERE hash=?", repair.Digest([]byte(alias))).Scan(&gotTested, &gotUntil, &proof); e != nil {
		t.Fatal(e)
	}
	if gotTested != tested || gotUntil != until || proof != convert.Prepare(job.Raw).Candidates[0].SHA256 {
		t.Fatal("receipt lifetime or bytes changed")
	}
	if used, e := s.Referenced(ctx, proof); e != nil || !used {
		t.Fatal("receipt bytes not retained", e)
	}
}

func TestPreparedReceiptReuseAndFailedRetestRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, j := addConversion(t, s, conversionSample)
	if e := s.CompleteProbe(ctx, conversionResult(j, 0, true)); e != nil {
		t.Fatal(e)
	}
	prepareAll(t, s)
	// An already prepared alias may lose its transient result; a fresh exact
	// receipt repairs that reference without extending or rerunning its proof.
	var tested, expiry int64
	s.db.QueryRow("SELECT tested,valid_until FROM conversion_results WHERE hash=?", j.Hash).Scan(&tested, &expiry)
	s.db.Exec("DELETE FROM conversion_results WHERE hash=?", j.Hash)
	if n, e := s.PrepareBatch(ctx); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	var got, until int64
	s.db.QueryRow("SELECT tested,valid_until FROM conversion_results WHERE hash=?", j.Hash).Scan(&got, &until)
	if got != tested || until != expiry {
		t.Fatal("proof lifetime changed")
	}
	if n, e := s.PrepareBatch(ctx); e != nil || n != 0 {
		t.Fatal("receipt reuse loop", n, e)
	}
	s.db.Exec("UPDATE conversion_jobs SET next_run=0 WHERE hash=?", j.Hash)
	again, e := s.ClaimProbe(ctx)
	if e != nil || again == nil {
		t.Fatal(e)
	}
	if e = s.CompleteProbe(ctx, conversionResult(*again, 0, false)); e != nil {
		t.Fatal(e)
	}
	var cached int
	s.db.QueryRow("SELECT count(*) FROM conversion_receipts").Scan(&cached)
	if cached != 0 {
		t.Fatal("new failure retained cached proof")
	}
	if n, e := s.PrepareBatch(ctx); e != nil || n != 0 {
		t.Fatal(n, e)
	}
}

func TestPreparedHeadAndPrefetchDoNotConsumeRotation(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "head", sourceURI(91), sourceURI(92))
	prepareAll(t, s)
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	url := app.origin + "/api/prepared/export?single=1"
	rr := exportRequest(t, app.Handler(), "HEAD", url)
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Sec-Purpose", "prefetch")
	rr = httptest.NewRecorder()
	app.Handler().ServeHTTP(rr, req)
	if rr.Code != 204 {
		t.Fatal(rr.Code)
	}
	var cursors int
	s.db.QueryRow("SELECT count(*) FROM prepared_rotation").Scan(&cursors)
	if cursors != 0 {
		t.Fatal("non-download consumed cursor")
	}
	rr = exportRequest(t, app.Handler(), "GET", url)
	if rr.Code != 200 || rr.Header().Get("X-Export-Cycle") != "1" {
		t.Fatal(rr.Code, rr.Header())
	}
}

func TestCoverageAccountsForPausedAndSafetyGatedSourceInputs(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raws := []string{}
	for i := 101; i <= 117; i++ {
		raws = append(raws, sourceURI(i))
	}
	source, _ := newExportSource(t, s, "account-every-input", raws...)
	rows, e := s.Conversions(ctx, 0, true)
	if e != nil {
		t.Fatal(e)
	}
	for i, c := range rows[:5] {
		if i < 2 {
			_, e = s.db.Exec("INSERT INTO config_controls VALUES(?,'disabled',?,?)", c.ID, time.Now().UnixMilli(), time.Now().Add(time.Hour).UnixMilli())
		} else {
			_, e = s.db.Exec("INSERT INTO input_exclusions(identity,at,hash,manual) VALUES(?,?,?,1)", c.ID, time.Now().UnixMilli(), c.Hash)
		}
		if e != nil {
			t.Fatal(e)
		}
	}
	summaries, e := s.SourceConversionSummaries(ctx, []Source{{ID: source}})
	if e != nil {
		t.Fatal(e)
	}
	v := summaries[source]
	c := v.Coverage
	if c.Total != 17 || c.Ready != 12 || c.Paused != 2 || c.Withheld != 3 || len(v.Excluded) != 5 {
		t.Fatalf("lost input: %+v", v)
	}
	visible, e := querySourceConversions(ctx, s.reader(), source, 0, true)
	if e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, c := range visible {
		seen[c.ID] = true
	}
	for _, x := range v.Excluded {
		if seen[x.ID] {
			t.Fatal("double counted", x.ID)
		}
		seen[x.ID] = true
	}
	if len(seen) != 17 {
		t.Fatal("unaccounted identity", len(seen))
	}
}
