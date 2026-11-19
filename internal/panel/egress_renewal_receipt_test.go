package panel

import (
	"context"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestRenewalDriverOutagePreservesOnlyOriginalUnexpiredReceipt(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "renewal", sourceURI(803))
	claim := func() *egress.Job {
		t.Helper()
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal("expected a due job", err)
		}
		return j
	}
	job := claim()
	if err := s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
		t.Fatal(err)
	}
	deadline := egress.Now() + 100000 // typical near-expiry renewal
	if _, err := s.db.Exec("UPDATE egress_jobs SET valid_until=?,next_run=0 WHERE hash=?", deadline, job.Hash); err != nil {
		t.Fatal(err)
	}
	var checked int64
	if err := s.db.QueryRow("SELECT tested FROM egress_export_eligible WHERE hash=?", job.Hash).Scan(&checked); err != nil {
		t.Fatal(err)
	}
	outage := func(j *egress.Job) {
		t.Helper()
		now := egress.Now()
		r := egress.Report{Version: egress.Version, Hash: j.Hash, Started: now, Finished: now, Code: "driver_session_failed"}
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	outage(claim())
	var until, tested, health, geo int64
	if err := s.db.QueryRow(`SELECT e.valid_until,e.tested,h.checked_at,g.checked_at FROM egress_export_eligible e
 JOIN egress_health h ON h.hash=e.hash JOIN egress_geo_results g ON g.hash=e.hash WHERE e.hash=?`, job.Hash).Scan(&until, &tested, &health, &geo); err != nil {
		t.Fatal("a local driver outage invalidated a fresh receipt", err)
	}
	if until != deadline || tested != checked || health != checked || geo != checked {
		t.Fatal("retry extended or modified an earlier proof", tested, health, geo, until)
	}
	if j, err := s.ClaimEgress(ctx); err != nil || j != nil {
		t.Fatal("expiry urgency bypassed outage backoff", err)
	}
	var lastReason, lastState string
	if err := s.db.QueryRow("SELECT reason,state FROM egress_events WHERE hash=? ORDER BY id DESC LIMIT 1", job.Hash).Scan(&lastReason, &lastState); err != nil || lastReason != "driver_session_failed" || lastState != "UNKNOWN" {
		t.Fatal("renewal failure is missing from history", lastReason, lastState, err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET valid_until=1,next_run=0 WHERE hash=?", job.Hash); err != nil {
		t.Fatal(err)
	}
	outage(claim())
	var exports, retained int
	if err := s.db.QueryRow(`SELECT (SELECT count(*) FROM egress_export_eligible),
 (SELECT count(*) FROM egress_work WHERE hash=? AND ever_accepted=1 AND candidate_hash!='')`, job.Hash).Scan(&exports, &retained); err != nil || exports != 0 || retained != 1 {
		t.Fatal("expired receipt exported or retained identity lost", exports, retained, err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", job.Hash); err != nil {
		t.Fatal(err)
	}
	job = claim()
	if err := s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT count(*) FROM egress_export_eligible").Scan(&exports); err != nil || exports != 1 {
		t.Fatal("fresh measurement did not restore publication", exports, err)
	}
}
