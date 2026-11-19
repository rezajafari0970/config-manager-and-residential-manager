package panel

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestUnmeasuredFirstSurvivesWithdrawalRefetchAndRestart(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	id, _ := newExportSource(t, s, "failure", sourceURI(994))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	fillExportSource(t, s, id, sourceURI(995))
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=? WHERE hash!=?", egress.Now()+3600000, j.Hash); err != nil {
		t.Fatal(err)
	}
	at := egress.Now()
	r := egress.Report{Version: egress.Version, Hash: j.Hash, Started: at, Finished: at, Code: "driver_session_failed"}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND tested=0 AND first_completed=0 AND next_run>? AND token=''", j.Hash, at)
	pendingCount(t, s.db, 0, "SELECT first_assessments FROM egress_metrics")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_events WHERE hash=?", j.Hash)
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != ErrConflict {
		t.Fatal("duplicate acknowledgement", err)
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	fillExportSource(t, s, id, sourceURI(994))
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", j.Hash); err != nil {
		t.Fatal(err)
	}
	again, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || again == nil || again.Hash != j.Hash || again.Attempt != 2 {
		t.Fatal(err)
	}
	r = syntheticEgress(*again)
	for i := range r.Samples {
		r.Samples[i].Source = egress.Hash([]byte("ordinary"))
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *again, Report: r}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT first_assessments FROM egress_metrics")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", j.Hash)
	fillExportSource(t, s, id, sourceURI(994))
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", j.Hash)
}

func TestV50ReopensOnlyProvenSingleUnmeasuredReceipts(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	type mode struct {
		name, code       string
		withdraw, edited bool
	}
	cases := []mode{{"current", "driver_session_failed", false, false}, {"withdrawn", "driver_session_failed", true, false}, {"no-source-provenance", "driver_session_failed", true, true}, {"endpoint", "endpoint_dns_failed", false, false}, {"alternate-measured", "driver_subprocess_failed", false, false}}
	for i, c := range cases {
		source, _ := newExportSource(t, s, c.name, sourceURI(960+i))
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil {
			t.Fatal(err)
		}
		now := egress.Now()
		r := egress.Report{Version: egress.Version, Hash: j.Hash, Started: now, Finished: now, Code: c.code}
		if c.name == "alternate-measured" {
			r.Evidence = []egress.Report{{Samples: []egress.Sample{{Code: "network_failure"}}}}
		}
		b, _ := json.Marshal(r)
		if _, err = s.db.Exec("UPDATE egress_jobs SET state='UNKNOWN',reason=?,report=?,tested=?,first_completed=1,token='',lease_until=0 WHERE hash=?", c.code, string(b), now, j.Hash); err != nil {
			t.Fatal(err)
		}
		if c.withdraw {
			if _, err = s.db.Exec("DELETE FROM memberships WHERE source_id=?", source); err != nil {
				t.Fatal(err)
			}
		}
		if c.edited {
			if _, err = s.db.Exec("UPDATE sources SET revision=revision+1 WHERE id=?", source); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := s.db.Exec("PRAGMA user_version=49"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := s.migrateV50(); err != nil {
			t.Fatal(err)
		}
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_work WHERE first_completed=0 AND tested=0")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog")
	pendingCount(t, s.db, 3, "SELECT count(*) FROM egress_jobs WHERE first_completed=0")
	pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_jobs WHERE first_completed=1 AND tested>0")
}

func TestUnmeasuredFirstRequiresExplicitLocalFailureAndNoMeasurements(t *testing.T) {
	for _, code := range []string{"driver_session_failed", "input_unavailable", "driver_subprocess_timeout", "missing_runtime_asset", "core_pin_mismatch"} {
		r := egress.Report{Code: code}
		if got := unmeasuredFirstReason(r, "exact_variants_incomplete"); got != code {
			t.Errorf("local blocker %s: %s", code, got)
		}
		r.Attempts = []egress.Attempt{{Code: "core_schema_mismatch"}}
		if got := unmeasuredFirstReason(r, "exact_variants_incomplete"); got != "" {
			t.Errorf("mixed core outcomes treated as unmeasured: %s", got)
		}
	}
	for _, code := range []string{"endpoint_dns_failed", "ipv6_only_probe_pending", "core_rejected", "driver_unavailable", "direct_route_not_qualified", "runtime_start_failed", "network_retry_pending"} {
		if got := unmeasuredFirstReason(egress.Report{Code: code}, code); got != "" {
			t.Errorf("reopened actual input outcome %s", got)
		}
	}
}
