package panel

import (
	"context"
	"testing"
	"time"
)

func TestConversionViewsCountOnlyLiveLeasesAsRunning(t *testing.T) {
	s := testStore(t)
	id, _ := newExportSource(t, s, "lease-state", sourceURI(481), sourceURI(482), sourceURI(483))
	if _, err := s.db.Exec("UPDATE conversion_jobs SET state='running',token='leased',lease_until=0"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UnixMilli()
	ctx := context.WithValue(context.Background(), readTimeKey{}, now)
	before, err := s.Conversions(ctx, 0, true)
	if err != nil || len(before) != 3 {
		t.Fatal(len(before), err)
	}
	// Two inputs still need a first result. The third retains a verified
	// result through a canceled renewal and remains available.
	if _, err = s.db.Exec("DELETE FROM conversion_results WHERE hash IN (?,?)", before[0].Hash, before[1].Hash); err != nil {
		t.Fatal(err)
	}
	before, err = s.Conversions(ctx, 0, true)
	if err != nil || len(before) != 3 || !before[2].Available {
		t.Fatal("fixture lost its verified result", err)
	}
	// Simulate an interrupted worker, a live replacement and a canceled lease.
	for i, lease := range []struct {
		token string
		until int64
	}{{"old", now}, {"replacement", now + 1}, {"", now + 1000}} {
		if _, err = s.db.Exec("UPDATE conversion_jobs SET token=?,lease_until=? WHERE hash=?", lease.token, lease.until, before[i].Hash); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := s.Conversions(ctx, 0, true)
	if err != nil || len(rows) != 3 {
		t.Fatal(len(rows), err)
	}
	for i, state := range []string{"queued", "running", "queued"} {
		if rows[i].State != state || rows[i].Tested != before[i].Tested || rows[i].NextRetry != before[i].NextRetry || rows[i].Available != before[i].Available {
			t.Fatalf("lease %d: state %q tested %d next %d", i, rows[i].State, rows[i].Tested, rows[i].NextRetry)
		}
	}
	summary, err := s.SourceConversionSummaries(ctx, []Source{{ID: id}})
	if err != nil {
		t.Fatal(err)
	}
	c := summary[id].Coverage
	if c.Running != 1 || c.Queued != 1 || c.Ready != 1 {
		t.Fatalf("source coverage includes expired or canceled leases: %+v", c)
	}
	var persisted int
	if err = s.db.QueryRow("SELECT count(*) FROM conversion_jobs WHERE state='running'").Scan(&persisted); err != nil || persisted != 3 {
		t.Fatal("read path rewrote queue state", persisted, err)
	}
}
