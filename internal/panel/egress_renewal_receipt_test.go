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

func TestRenewalDeadlinesAheadOfOrdinaryReviews(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "renewal-deadlines", sourceURI(1201), sourceURI(1202), sourceURI(1203))
	var hashes []string
	for range 3 {
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil {
			t.Fatal("missing initial job", err)
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
			t.Fatal(err)
		}
		hashes = append(hashes, job.Hash)
	}
	review, first, second := hashes[0], hashes[1], hashes[2]
	type schedule struct{ expiresIn, dueIn, retryStreak int64 }
	later := schedule{360000, 300000, 0}
	for _, tc := range []struct {
		name          string
		first, second schedule
		turn          uint64
		want          string
	}{
		{"slow probe due three minutes before expiry", schedule{180000, -1000, 0}, later, 1, first},
		{"slow probe still scheduled", schedule{180000, 30000, 0}, later, 1, review},
		{"due retry with preserved proof", schedule{20000, -1000, 1}, later, 1, first},
		{"future retry respects backoff", schedule{20000, 10000, 1}, later, 1, review},
		{"reserved FIFO safety turn", schedule{20000, -1000, 1}, later, 4, review},
		{"earliest expiry at equal due time", schedule{90000, -1000, 0}, schedule{30000, -1000, 0}, 1, second},
		{"earliest expiry ahead of older due time", schedule{90000, -30000, 0}, schedule{30000, -1000, 0}, 1, second},
		{"urgent before ordinary due maintenance", schedule{300000, -30000, 0}, schedule{30000, -1000, 0}, 1, second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := egress.Now()
			if _, err := s.db.Exec(`INSERT INTO egress_network_review(identity,attempts) SELECT identity,1 FROM egress_unique WHERE hash=?
 ON CONFLICT(identity) DO UPDATE SET attempts=1`, review); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE egress_jobs SET token='',lease_until=0,next_run=0,valid_until=0 WHERE hash=?", review); err != nil {
				t.Fatal(err)
			}
			// With equal due times, ordinary FIFO would choose the first job.
			for i, job := range []schedule{tc.first, tc.second} {
				if _, err := s.db.Exec(`UPDATE egress_jobs SET token='',lease_until=0,valid_until=?,next_run=?,retry_streak=?,first_seen=? WHERE hash=?`,
					now+job.expiresIn, now+job.dueIn, job.retryStreak, i+1, hashes[i+1]); err != nil {
					t.Fatal(err)
				}
			}
			s.renewalTurn.Store(tc.turn - 1)
			job, err := s.ClaimEgressLane(ctx, "followup")
			if err != nil || job == nil || job.Hash != tc.want {
				t.Fatal("unexpected follow-up selection", job, err)
			}
		})
	}
}
