package panel

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestDatacenterRejectedSubscription(t *testing.T) {
	s := testStore(t)
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	module := egressModule{app}
	url := module.datacenterRejectedURL()
	ctx := context.Background()
	if rr := exportRequest(t, handler, "GET", url); rr.Code != http.StatusNoContent || rr.Header().Get("X-Config-Count") != "0" {
		t.Fatalf("empty feed: %d", rr.Code)
	}
	complete := func(hosting bool) egress.Job {
		t.Helper()
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil {
			t.Fatal("expected first evaluation", err)
		}
		report := syntheticEgress(*job)
		if hosting {
			for i := range report.Samples {
				x := &report.Samples[i]
				if x.ActualAds && x.Domain == egress.Domains[0] {
					x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
				}
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: report}); err != nil {
			t.Fatal(err)
		}
		return *job
	}
	newExportSource(t, s, "access", sourceURI(67))
	complete(false)
	raw := sourceURI(68)
	newExportSource(t, s, "hosting", raw)
	held := complete(true)
	newExportSource(t, s, "duplicate", raw+"-alias")
	check := func(want bool) {
		t.Helper()
		rr := exportRequest(t, handler, "GET", url)
		if !want {
			if rr.Code != http.StatusNoContent || rr.Body.Len() != 0 || rr.Header().Get("X-Config-Count") != "0" {
				t.Fatalf("rejected feed should be empty: %d", rr.Code)
			}
			return
		}
		if rr.Code != http.StatusOK || rr.Body.String() != raw || rr.Header().Get("X-Config-Count") != "1" || rr.Header().Get("X-Verification-Scope") != "ads-datacenter-rejection" {
			t.Fatalf("wrong raw membership: %d, count %s", rr.Code, rr.Header().Get("X-Config-Count"))
		}
		head := exportRequest(t, handler, "HEAD", url)
		if head.Code != rr.Code || head.Body.Len() != 0 || head.Header().Get("X-Content-SHA256") != rr.Header().Get("X-Content-SHA256") {
			t.Fatal("HEAD must report membership without serving bytes")
		}
	}
	check(true)
	summary := exportRequest(t, handler, "GET", app.origin+"/api/egress?brief=1")
	var state struct {
		Links      map[string]string `json:"links"`
		Rejections struct {
			Count int    `json:"count"`
			URL   string `json:"raw_url"`
		} `json:"datacenter_rejections"`
	}
	if summary.Code != 200 || json.Unmarshal(summary.Body.Bytes(), &state) != nil || len(state.Links) != 4 || state.Rejections.Count != 1 || state.Rejections.URL != url {
		t.Fatal("dashboard count/link mismatch", summary.Code)
	}
	dcToken := s.digest("egress-export-v2", "datacenter-rejected")
	residentialToken := s.digest("egress-export-v2", "all")
	for _, wrong := range []string{strings.Replace(url, dcToken, residentialToken, 1), strings.Replace(state.Links["raw.txt"], residentialToken, dcToken, 1)} {
		if rr := exportRequest(t, handler, "GET", wrong); rr.Code != http.StatusNotFound {
			t.Fatal("token authorized across feeds", rr.Code)
		}
	}
	// Later inconclusive data and changes of the residential country filter
	// cannot erase a verified veto. Administrative and Iran guards take effect
	// immediately, including between raw spooling and the final writer fence.
	if _, err := s.db.Exec("UPDATE egress_network_results SET state='unknown',valid_until=0 WHERE hash=?; UPDATE egress_country_policy SET allowed='[]'", held.Hash); err != nil {
		t.Fatal(err)
	}
	check(true)
	entries, err := datacenterRejectedEntries(ctx, s.db)
	if err != nil || len(entries) != 1 {
		t.Fatal(entries, err)
	}
	if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", entries[0].ID); err != nil {
		t.Fatal(err)
	}
	check(false)
	current, err := s.verifiedSnapshotCurrent(ctx, rawScope{datacenterRejected: true}, entries)
	if err != nil || current {
		t.Fatal("guard must fence the captured membership", err)
	}
	if _, err = s.db.Exec("DELETE FROM egress_iran_guard WHERE identity=?", entries[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET paused=1 WHERE hash=?", held.Hash); err != nil {
		t.Fatal(err)
	}
	check(false)
	if _, err = s.db.Exec("UPDATE egress_jobs SET paused=0 WHERE hash=?", held.Hash); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err = s.db.Exec("UPDATE egress_network_results SET held=0 WHERE hash=?", held.Hash); err != nil {
		t.Fatal(err)
	}
	check(false)
	// Recreate an archived veto with no ordinary membership/control. Delete-all
	// must still remove it from the diagnostic feed permanently.
	if _, err = s.db.Exec("UPDATE egress_network_results SET held=1 WHERE hash=?", held.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE egress_jobs SET ever_accepted=0 WHERE hash=?", held.Hash); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM artifacts WHERE id=?", entries[0].ID); err != nil {
		t.Fatal(err)
	}
	check(true)
	if _, err = s.ManageConfigs(ctx, ConfigBatch{Action: "delete", All: true}); err != nil {
		t.Fatal(err)
	}
	check(false)
}
