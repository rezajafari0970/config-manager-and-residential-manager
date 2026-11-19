package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestEgressSourceCoverageEnabledMembershipPartition(t *testing.T) {
	s := testStore(t)
	a, _ := newExportSource(t, s, "A", sourceURI(81), sourceURI(82), sourceURI(83))
	b, _ := newExportSource(t, s, "B", sourceURI(81), sourceURI(84))
	disabled, _ := newExportSource(t, s, "hidden", sourceURI(85))
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("UPDATE sources SET enabled=0 WHERE id=?", disabled)
	exec("UPDATE sources SET name='https://example.com/secret-label' WHERE id=?", b)
	// A and B share one tested identity; create two awaiting/excluded states
	// on A and a missing representative on B.
	exec("UPDATE egress_jobs SET tested=1 WHERE hash IN (SELECT min(raw_hash) FROM memberships GROUP BY artifact_id HAVING count(*)>1)")
	exec("INSERT INTO input_exclusions(identity,at,hash) SELECT artifact_id,1,raw_hash FROM memberships WHERE source_id=? AND artifact_id NOT IN (SELECT artifact_id FROM memberships WHERE source_id=?) LIMIT 1", a, b)
	exec("DELETE FROM egress_unique WHERE identity IN (SELECT artifact_id FROM memberships WHERE source_id=? AND artifact_id NOT IN (SELECT artifact_id FROM memberships WHERE source_id=?))", b, a)
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	h := app.Handler()
	// The overview includes all committed memberships, including disabled sources.
	// An interrupted input remains unmeasured even if a worker previously claimed it.
	exec("UPDATE egress_jobs SET reason='initial_lease_exhausted' WHERE hash IN (SELECT raw_hash FROM memberships WHERE source_id=?)", disabled)
	snapshot, err := freezeEgress(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	accounting, err := egressAccounting(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	current := accounting["current_assessment"].(map[string]int)
	if accounting["current_identities"] != 5 || current["tested"] != 1 || current["awaiting"] != 2 ||
		current["excluded"] != 1 || current["missing"] != 1 || current["exhausted"] != 1 {
		t.Fatal(current)
	}
	rr := exportRequest(t, h, "GET", "http://127.0.0.1:18191/api/egress/source-coverage")
	var result struct {
		Global  egressCoverageCounts `json:"global"`
		Sources []egressSourceRow    `json:"sources"`
		Total   int                  `json:"enabled_sources"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "example.com") || strings.Contains(rr.Body.String(), disabled) || strings.Contains(rr.Body.String(), sourceURI(81)) {
		t.Fatal("private fields or disabled source exposed")
	}
	if result.Total != 2 || len(result.Sources) != 2 || result.Global != (egressCoverageCounts{Current: 4, Registered: 2, Tested: 1, Awaiting: 1, Excluded: 1, Missing: 1}) {
		t.Fatal(result)
	}
	for _, r := range result.Sources {
		switch r.ID {
		case a:
			if r.Name != "A" || r.egressCoverageCounts != (egressCoverageCounts{Current: 3, Registered: 2, Tested: 1, Awaiting: 1, Excluded: 1}) {
				t.Fatal(r)
			}
		case b:
			if r.Name != "" || r.egressCoverageCounts != (egressCoverageCounts{Current: 2, Registered: 1, Tested: 1, Missing: 1}) {
				t.Fatal(r)
			}
		default:
			t.Fatal(r)
		}
	}
	rr = exportRequest(t, h, "GET", "http://127.0.0.1:18191/api/egress/source-coverage?offset=2")
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil || len(result.Sources) != 0 || result.Global.Current != 4 {
		t.Fatal(rr.Code, rr.Body.String())
	}
	if rr = exportRequest(t, h, "GET", "http://127.0.0.1:18191/api/egress/source-coverage?offset=-1"); rr.Code != 422 {
		t.Fatal(rr.Code)
	}
}

func TestEgressFiveMinuteUniqueSettlementProvenance(t *testing.T) {
	s := testStore(t)
	now := time.Now().UnixMilli()
	for _, event := range []struct {
		hash       string
		at         int64
		definitive int
	}{
		{"first", now - 1000, 1}, {"first", now - 500, 1}, {"old", now - 305000, 1}, {"old", now - 1000, 1},
		{"orphan", now - 1000, 1}, {"uncertain", now - 1000, 0}, {"future", now + 60000, 1},
	} {
		if _, err := s.db.Exec("INSERT INTO egress_events(hash,at,state,reason,definitive) VALUES(?,?,'TEST','fixture',?)", event.hash, event.at, event.definitive); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("INSERT INTO egress_settlements VALUES('first',?,'TEST'),('old',?,'TEST')", now-1000, now-305000); err != nil {
		t.Fatal(err)
	}
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	egressModule{app}.state(rr, httptest.NewRequest("GET", "/api/egress?brief=1", nil))
	var result struct {
		Throughput map[string]int `json:"throughput"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &result) != nil {
		t.Fatal(rr.Code, rr.Body.String())
	}
	for key, want := range map[string]int{"target_5m": 500, "completed_5m": 5, "unique_5m": 4, "unique_definitive_5m": 3, "first_settled_5m": 1, "previously_settled_5m": 1, "settlement_unknown_5m": 1} {
		if result.Throughput[key] != want {
			t.Fatal(key, result.Throughput)
		}
	}
}

func TestEgressSourceCoverageTracksPublishedAndWithdrawn(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, _ := newExportSource(t, s, "rotate-A", sourceURI(87))
	b, _ := newExportSource(t, s, "rotate-B", sourceURI(87))
	c, _ := newExportSource(t, s, "stays-current", sourceURI(87))
	first, err := s.ClaimEgress(ctx)
	if err != nil || first == nil {
		t.Fatal("first claim", err)
	}
	fillExportSource(t, s, a, sourceURI(88))
	fillExportSource(t, s, b, sourceURI(88))
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	h := app.Handler()
	check := func(published, withdrawn int) {
		t.Helper()
		resp := exportRequest(t, h, "GET", "http://127.0.0.1:18191/api/egress/source-coverage")
		var result struct {
			Global  egressCoverageCounts
			Sources []egressSourceRow
		}
		if resp.Code != 200 || json.Unmarshal(resp.Body.Bytes(), &result) != nil || len(result.Sources) != 3 {
			t.Fatal(resp.Code, resp.Body.String())
		}
		if result.Global.Published != published || result.Global.WithdrawnAwaitingFirst != withdrawn || result.Global.Current != 2 {
			t.Fatal(result)
		}
		for _, row := range result.Sources {
			if row.ID == c {
				if row.Published != published || row.WithdrawnAwaitingFirst != 0 {
					t.Fatal(row)
				}
			} else if row.Published != 0 || row.WithdrawnAwaitingFirst != withdrawn {
				t.Fatal(row)
			}
		}
	}
	// A and B withdrew the same identity; C still lists it. It is globally
	// counted once in both the current set and the separate withdrawal metric.
	check(0, 1)
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *first, Report: syntheticEgress(*first)}); err != nil {
		t.Fatal(err)
	}
	check(1, 0)
	if _, err = s.db.Exec("UPDATE egress_country_policy SET allowed='[]'"); err != nil {
		t.Fatal(err)
	}
	check(0, 0)
}
