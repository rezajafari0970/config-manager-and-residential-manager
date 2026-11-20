package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestSideSubscriptionsSelectionRotationAndRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := []string{sourceURI(141), sourceURI(142), sourceURI(143), sourceURI(144)}
	source, _ := newExportSource(t, s, "side-http", raw...)
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	links := sideOutputModule{app}.links()
	for _, file := range []string{"raw.txt", "next.json"} {
		r := exportRequest(t, handler, "GET", links[file])
		if r.Code != 204 || r.Header().Get("X-Config-Count") != "0" {
			t.Fatal("untested input published", file, r.Code)
		}
	}
	empty := exportRequest(t, handler, "GET", links["configs.json"])
	if empty.Code != 200 || strings.TrimSpace(empty.Body.String()) != "[]" {
		t.Fatal("invalid empty JSON feed")
	}
	expected := map[string][]byte{}
	for range raw {
		job := sideClaim(t, s)
		if job.Hash == repair.Digest([]byte(raw[3])) {
			result := SideResult{Identity: job.Identity, Hash: job.Hash, Token: job.Token, Code: "side_checks_failed",
				Evidence: map[string]string{"warp": "warp_not_active", "google": "passed", "upload": "not_run",
					"private_detail": "sensitive_fixture_marker"}}
			if err := s.CompleteSide(ctx, result); err != nil {
				t.Fatal(err)
			}
			continue
		}
		result := sidePass(t, job)
		if err := s.CompleteSide(ctx, result); err != nil {
			t.Fatal(err)
		}
		if job.Hash == repair.Digest([]byte(raw[2])) {
			// Isolate the feed's native-only branch; the driver and ledger test
			// actual engine validation separately.
			if _, err := s.db.Exec("UPDATE side_jobs SET engine='sing-box' WHERE identity=?", job.Identity); err != nil {
				t.Fatal(err)
			}
		} else {
			expected[repair.Digest(result.Candidate)] = result.Candidate
		}
	}
	reviews := exportRequest(t, handler, "GET", app.origin+"/api/side/reviews")
	var history []sideReview
	if reviews.Code != 200 || json.Unmarshal(reviews.Body.Bytes(), &history) != nil || len(history) != 4 ||
		strings.Contains(reviews.Body.String(), "sensitive_fixture_marker") || strings.Contains(reviews.Body.String(), raw[0]) {
		t.Fatal("unexpected review history")
	}
	var classified bool
	for _, entry := range history {
		if len(entry.ID) != 12 || len(entry.Checks) != len(sideServices) {
			t.Fatal("missing diagnostic scope")
		}
		if entry.State == "rejected" && entry.Checks["warp"] == "warp_not_active" &&
			entry.Checks["upload"] == "not_run" && entry.Checks["stability"] == "unrecorded" {
			classified = true
		}
	}
	if !classified {
		t.Fatal("missing separate negative, unrun and unrecorded outcomes")
	}
	assertExportLines(t, handler, links["configs.json"], expected)
	rr := exportRequest(t, handler, "GET", links["raw.txt"])
	if rr.Code != 200 || rr.Header().Get("X-Config-Count") != "3" || repair.Digest(rr.Body.Bytes()) != rr.Header().Get("X-Content-SHA256") {
		t.Fatal("unexpected raw export", rr.Code)
	}
	lines := strings.Split(rr.Body.String(), "\n")
	for _, uri := range raw[:3] {
		found := false
		for _, line := range lines {
			if uri == line {
				found = true
			}
		}
		if !found {
			t.Fatal("missing original bytes")
		}
	}
	var summary struct {
		Counts SideStats
		Links  map[string]string
	}
	info := exportRequest(t, handler, "GET", app.origin+"/api/side")
	if info.Code != 200 || json.Unmarshal(info.Body.Bytes(), &summary) != nil || summary.Counts.Accepted != 3 || summary.Counts.Template != 2 || summary.Links["raw.txt"] != links["raw.txt"] {
		t.Fatal("dashboard is inconsistent with published membership")
	}
	wrong := strings.TrimSuffix(links["next.json"], "next.json") + "raw.txt"
	if exportRequest(t, handler, "GET", wrong).Code != 404 {
		t.Fatal("token reused across feed formats")
	}
	exportRequest(t, handler, "HEAD", links["next.json"])
	req := httptest.NewRequest("GET", links["next.json"], nil)
	req.Header.Set("Sec-Purpose", "prefetch")
	prefetch := httptest.NewRecorder()
	handler.ServeHTTP(prefetch, req)
	if prefetch.Code != http.StatusNoContent {
		t.Fatal("prefetch should not consume a turn")
	}
	const readers = 8
	results := make(chan *httptest.ResponseRecorder, readers)
	for range readers {
		go func() { results <- exportRequest(t, handler, "GET", links["next.json"]) }()
	}
	perCycle := map[int]map[string]bool{}
	for range readers {
		r := <-results
		hash := r.Header().Get("X-Content-SHA256")
		cycle, err := strconv.Atoi(r.Header().Get("X-Export-Cycle"))
		if r.Code != 200 || err != nil || !bytes.Equal(expected[hash], r.Body.Bytes()) || !json.Valid(r.Body.Bytes()) {
			t.Fatal("invalid single export", r.Code)
		}
		if perCycle[cycle] == nil {
			perCycle[cycle] = map[string]bool{}
		}
		if perCycle[cycle][hash] {
			t.Fatal("duplicate within round", cycle)
		}
		perCycle[cycle][hash] = true
	}
	for cycle := 1; cycle <= readers/2; cycle++ {
		if len(perCycle[cycle]) != 2 {
			t.Fatal("lost rotation turn", cycle)
		}
	}
	captured, err := sideTemplateEntries(ctx, s.reader())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE sources SET enabled=0 WHERE id=?", source); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.verifiedSnapshotCurrent(ctx, rawScope{sideTemplates: true}, captured); err != nil || ok {
		t.Fatal("revoked source passed final publication check", err)
	}
	if exportRequest(t, handler, "GET", links["next.json"]).Code != 204 || exportRequest(t, handler, "GET", links["raw.txt"]).Code != 204 {
		t.Fatal("disabled source still published")
	}
}

func TestSideRestoresMissingAndCorruptTestedTemplate(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "side-repair", sourceURI(149))
	job := sideClaim(t, s)
	result := sidePass(t, job)
	if err := s.CompleteSide(ctx, result); err != nil {
		t.Fatal(err)
	}
	digest := repair.Digest(result.Candidate)
	path := filepath.Join(s.vault.Directory(), digest+".blob")
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	links := sideOutputModule{app}.links()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	single := exportRequest(t, handler, "GET", links["next.json"])
	if single.Code != 200 || !bytes.Equal(single.Body.Bytes(), result.Candidate) || single.Header().Get("X-Content-SHA256") != digest {
		t.Fatal("missing candidate was not restored", single.Code)
	}
	if err := os.WriteFile(path, []byte("corrupt fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	assertExportLines(t, handler, links["configs.json"], map[string][]byte{digest: result.Candidate})
	fresh, err := s.ClaimSide(ctx)
	if err != nil || fresh != nil {
		t.Fatal("storage repair caused a re-test", err)
	}
	if _, err = s.db.Exec("UPDATE side_jobs SET expires=0 WHERE identity=?", job.Identity); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c := Conversion{ID: job.Identity, Hash: job.Hash, CandidateHash: digest, Available: true}
	if _, err = s.sideTemplateBytes(ctx, c); err == nil {
		t.Fatal("expired receipt repaired")
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("revoked blob reappeared", err)
	}
}

func TestSideOutputPanelLinks(t *testing.T) {
	app, err := NewServer(testStore(t), "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	page := exportRequest(t, handler, "GET", app.origin+"/output")
	for _, id := range []string{"side-reviews", "side-output", "side-all", "side-next", "side-raw", "side-counts"} {
		if page.Code != 200 || !strings.Contains(page.Body.String(), `id="`+id+`"`) {
			t.Fatal("missing Side panel control", id)
		}
	}
	if exportRequest(t, handler, "GET", app.origin+"/assets/side-output.js").Code != 200 {
		t.Fatal("Side module not served")
	}
}
