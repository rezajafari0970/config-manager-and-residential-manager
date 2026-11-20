package panel

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSideReviewCoverageDistinguishesServiceAndLocalFailures(t *testing.T) {
	for _, c := range []struct {
		record                map[string]string
		state, code, coverage string
		measured              int
	}{
		{map[string]string{"warp": "warp_not_active", "google": "not_run", "side_version": "side_v1"}, "rejected", "side_checks_failed", "legacy_partial", 1},
		{map[string]string{"side_version": "side_v2", "facebook": "response_too_large", "upload": "side_driver_unavailable"}, "inconclusive", "side_driver_unavailable", "partial", 1},
		{map[string]string{"raw_checks": "failed", "google": "passed", "raw_warp": "warp_not_active", "raw_upload": "untrusted_payload"}, "rejected", "side_checks_failed", "partial", 1},
		{nil, "rejected", "client_vless_encryption_required", "no_session", 0},
		{nil, "inconclusive", "worker_lease_exhausted", "infrastructure", 0},
		{nil, "rejected", "unlisted_reason", "unrecorded", 0},
	} {
		_, checks := sideReviewChecks(c.record)
		measured, coverage := sideReviewCoverage(checks, c.record["side_version"], c.state, sideReviewReason(c.code, c.state))
		if measured != c.measured || coverage != c.coverage {
			t.Errorf("%s: got %d %s", c.code, measured, coverage)
		}
	}
}

func TestSideThroughputUsesDistinctRecentDecisionsAndTenServiceMeasurements(t *testing.T) {
	store := testStore(t)
	now := int64(2000000000000)
	ctx := context.WithValue(context.Background(), readTimeKey{}, now)
	add := func(id, state string, record map[string]string, finished int64) {
		t.Helper()
		b, err := json.Marshal(record)
		if err != nil {
			t.Fatal(err)
		}
		_, err = store.db.Exec(`INSERT INTO side_jobs(identity,raw_hash,kind,size,admitted,expires,queued_at,state,finished,evidence)
  VALUES(?,'','vless',1,1,1,1,?,?,?)`, id, state, finished, string(b))
		if err != nil {
			t.Fatal(err)
		}
	}
	record := make(map[string]string)
	for _, k := range sideServices {
		record[k] = "passed"
	}
	add("ten", "accepted", record, now)
	record["warp"] = "warp_not_active"
	add("also-ten", "rejected", record, now-1)
	add("legacy", "rejected", map[string]string{"warp": "warp_not_active"}, now-1)
	record["raw_checks"] = "failed"
	record["raw_warp"] = "warp_not_active"
	add("raw-failed-with-limited-evidence", "rejected", record, now-1)
	for _, k := range sideServices {
		record["raw_"+k] = "transport_failed"
	}
	add("raw-all-measured", "rejected", record, now-1)
	add("outside", "accepted", record, now-(15*time.Minute).Milliseconds())
	add("later", "accepted", record, now+1)
	add("exhausted", "inconclusive", record, now)
	add("unmeasured", "expired", nil, now)
	add("leased", "pending", nil, now)

	got, err := readSideThroughput(ctx, store.db)
	if err != nil || got.Target != 2000 || got.Decided != 5 || got.Full != 3 {
		t.Fatalf("window: %+v %v", got, err)
	}
	rows, err := store.db.Query("EXPLAIN QUERY PLAN "+sideThroughputQuery, len(sideServices), now-900000, now)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "side_recent") {
		t.Error("expected a bounded recent-result scan", plan.String())
	}
}
