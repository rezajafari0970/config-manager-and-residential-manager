package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestFreshInitialReceiptAfterColdArchiveAndWorkerRestart(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	f := historyInput(t, s, "cold", 87)
	// Reproduce an inherited archive lease and its old source custody.
	if _, err := s.db.Exec(`INSERT INTO egress_first_history(hash,source_id,created,phase,ready_at,raw_available) VALUES(?1,?2,1,'active',1,1);
 UPDATE egress_jobs SET token='archive-worker',lease_until=?3,attempts=1 WHERE hash=?1;
 INSERT INTO egress_first_backlog(source_id,hash) VALUES(?2,?1);
 UPDATE egress_first_arrivals SET queued_at=1,received_at=1; PRAGMA user_version=55`, f.hash, f.source, egress.Now()+120000); err != nil {
		t.Fatal(err)
	}
	key, path := s.key, filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_jobs WHERE token='archive-worker'")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
	if job, err := s.ClaimEgress(ctx); err != nil || job != nil {
		t.Fatal("cold recovery ran", err)
	}
	commitProbeInputs(t, s, f.source, f.raw)
	newExportSource(t, s, "another", f.raw+"-renamed")
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil || j.Hash != f.hash {
		t.Fatal("fresh canonical reappearance not picked up", err)
	}
	if next, err := s.ClaimEgress(ctx); err != nil || next != nil {
		t.Fatal("duplicate first lease", err)
	}
	report := syntheticEgress(*j)
	for i := range report.Samples {
		report.Samples[i].Source = egress.Hash([]byte("control"))
		if report.Samples[i].Network != nil {
			report.Samples[i].Network.Source = report.Samples[i].Source
		}
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: report}); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, f.source, f.raw)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE first_result_scope='current'")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
}

func TestUnmeasuredFirstCannotOutliveItsLastReceipt(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "receipt", sourceURI(91))
	if _, err := s.db.Exec("UPDATE egress_first_arrivals SET received_at=1,queued_at=1"); err != nil {
		t.Fatal(err)
	}
	j, err := s.ClaimEgress(ctx)
	if err != nil || j != nil {
		t.Fatal("stale current member admitted", err)
	}
	p, err := firstAssessmentState(ctx, s.db, egress.Now())
	if err != nil || p.Current.Awaiting != 0 {
		t.Fatal("expired receipt counted as waiting", err)
	}
	commitProbeInputs(t, s, id, sourceURI(91))
	j, err = s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal("new receipt did not authorize unmeasured first", err)
	}
	if _, err = s.db.Exec("UPDATE egress_first_arrivals SET received_at=1"); err != nil {
		t.Fatal(err)
	}
	if err = s.RenewEgress(ctx, *j); err != ErrConflict {
		t.Fatal("expired authority renewed", err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != ErrConflict {
		t.Fatal("expired authority produced a result", err)
	}
}

func TestFreshFirstSourceFencesSurviveReenable(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	one, _ := newExportSource(t, s, "one", sourceURI(92))
	two, _ := newExportSource(t, s, "two", sourceURI(92)+"-alias")
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE sources SET enabled=0 WHERE id=?", one); err != nil {
		t.Fatal(err)
	}
	if err = s.RenewEgress(ctx, *j); err != nil {
		t.Fatal("independent current source lost custody", err)
	}
	if _, err = s.db.Exec("UPDATE sources SET enabled=0 WHERE id=?; UPDATE sources SET enabled=1", two); err != nil {
		t.Fatal(err)
	}
	if err = s.RenewEgress(ctx, *j); err != ErrConflict {
		t.Fatal("source revocation resurrected old grant", err)
	}
	newJob, err := s.ClaimEgress(ctx)
	if err != nil || newJob == nil || newJob.Token == j.Token {
		t.Fatal("new source grant", err)
	}
}

func TestFirstReceiptPersistsAcrossRepresentativeReplacement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "first", sourceURI(93))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: badDelivery(*j)}); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_verdicts WHERE hash=?", j.Hash)
	if _, err = s.db.Exec("DELETE FROM egress_unique WHERE hash=?", j.Hash); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, id, sourceURI(93)+"-new-label")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE hash!=?", j.Hash)
	if job, err := s.ClaimEgress(ctx); err != nil || job != nil {
		t.Fatal("canonical verdict was lost", err)
	}
}
