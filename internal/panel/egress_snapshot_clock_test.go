package panel

import (
	"context"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestEgressSnapshotFreezesQueueAndRejectionControls(t *testing.T) {
	s := testStore(t)
	// The override expired between the start of a read snapshot and this SQL
	// statement. Independent read paths must see it as active.
	start := time.Now().Add(-2 * time.Minute).UnixMilli()
	ctx := context.WithValue(context.Background(), readTimeKey{}, start)
	source, _ := newExportSource(t, s, "clock-hosting", sourceURI(35))
	job, err := s.ClaimEgress(context.Background())
	if err != nil || job == nil {
		t.Fatalf("claim synthetic hosting fixture: %v", err)
	}
	report := syntheticEgress(*job)
	for i := range report.Samples {
		x := &report.Samples[i]
		if x.ActualAds && x.Domain == egress.Domains[0] {
			x.Network.Kind, x.Network.Provider, x.Network.ASN = "hosting", "vultr", 20473
		}
	}
	if err := s.CompleteEgress(context.Background(), egress.Completion{Job: *job, Report: report}); err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO config_controls SELECT artifact_id,'disabled',?,? FROM memberships WHERE source_id=?", start-1000, start+60000, source)
	backlog, _ := newExportSource(t, s, "clock-withdrawn", sourceURI(36))
	exec("INSERT OR IGNORE INTO egress_first_backlog SELECT m.source_id,u.hash FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id WHERE m.source_id=?", backlog)
	exec("INSERT INTO config_controls SELECT artifact_id,'deleted',?,? FROM memberships WHERE source_id=?", start-1000, start+60000, backlog)
	exec("DELETE FROM memberships WHERE source_id=?", backlog)
	review, _ := newExportSource(t, s, "clock-review", sourceURI(37))
	exec("UPDATE egress_jobs SET tested=?,first_completed=1,ever_accepted=1 WHERE hash IN(SELECT u.hash FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id WHERE m.source_id=?)", start-1000, review)
	exec("INSERT INTO egress_residential_history SELECT u.hash FROM memberships m JOIN egress_unique u ON u.identity=m.artifact_id WHERE m.source_id=?", review)
	exec("INSERT INTO egress_network_review SELECT artifact_id,0 FROM memberships WHERE source_id=?", review)
	exec("INSERT INTO config_controls SELECT artifact_id,'disabled',?,? FROM memberships WHERE source_id=?", start-1000, start+60000, review)
	retirement, _ := newExportSource(t, s, "clock-retirement", sourceURI(38))
	hash := egress.Hash([]byte(sourceURI(38)))
	exec("UPDATE egress_jobs SET first_completed=1,tested=? WHERE hash=?", start-1000, hash)
	exec("INSERT INTO egress_retirements(hash,reason,hits,at,first_at) VALUES(?,'confirmed_ads_delivery_unhealthy',1,?,?)", hash, start-1000, start-1000)
	exec("INSERT INTO egress_retirement_limits(hash,through_attempt) VALUES(?,3)", hash)
	exec("INSERT INTO egress_retirement_sources(hash,source_id) VALUES(?,?)", hash, retirement)
	exec("INSERT INTO config_controls SELECT artifact_id,'disabled',?,? FROM memberships WHERE source_id=?", start-1000, start+60000, retirement)
	exec("DELETE FROM memberships WHERE source_id=?", retirement)
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	frozen, err := freezeEgress(ctx, snapshotReader{tx, start})
	if err != nil {
		t.Fatal(err)
	}
	for name, query := range map[string]string{
		"withdrawn inventory":     "SELECT count(*) FROM egress_inventory WHERE hash IN(SELECT hash FROM egress_first_backlog)",
		"retirement confirmation": "SELECT count(*) FROM egress_work WHERE hash IN(SELECT hash FROM egress_retirement_sources)",
		"active review":           "SELECT count(*) FROM egress_work WHERE hash IN(SELECT u.hash FROM egress_network_review v JOIN egress_unique u ON u.identity=v.identity)",
		"rejection feed":          "SELECT count(*) " + datacenterRejectedFrom,
	} {
		t.Run(name, func(t *testing.T) {
			var live, asOf int
			if err := tx.QueryRowContext(ctx, query).Scan(&live); err != nil {
				t.Fatal(err)
			}
			if err := frozen.QueryRowContext(ctx, query).Scan(&asOf); err != nil {
				t.Fatal(err)
			}
			want := 1
			if name == "retirement confirmation" {
				want = 0
			}
			if live != want || asOf != 0 {
				t.Fatalf("live=%d as-of=%d, expected %d and 0", live, asOf, want)
			}
		})
	}
}
