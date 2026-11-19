package panel

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestInterruptedInitialLeaseBudgetPersistsWithoutInventingReceipt(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	source, _ := newExportSource(t, s, "interrupted", sourceURI(637))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	hash := j.Hash
	fillExportSource(t, s, source, sourceURI(638))
	if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=? WHERE hash!=?", egress.Now()+3600000, hash); err != nil {
		t.Fatal(err)
	}
	for n := 1; n <= 3; n++ {
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND attempts=? AND first_completed=0", hash, n)
		if again, err := s.ClaimEgress(ctx); err != nil || again != nil {
			t.Fatal("live lease was charged", n, again, err)
		}
		if _, err = s.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", hash); err != nil {
			t.Fatal(err)
		}
		j, err = s.ClaimEgress(ctx)
		if err != nil || (j != nil) != (n < 3) {
			t.Fatal("interrupted lease budget", n, j, err)
		}
	}
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND state='UNKNOWN' AND reason='initial_lease_interrupted' AND tested=0 AND first_completed=0 AND attempts=3 AND token=''", hash)
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", hash)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", hash)
	pendingCount(t, reopened.db, 0, "SELECT completed FROM egress_metrics")
	if referenced, err := reopened.Referenced(ctx, hash); err != nil || !referenced {
		t.Fatal("withdrawn interrupted input lost its bytes", err)
	}
	// A trustworthy independent completion revives the same parked record once.
	if _, err = reopened.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash!=?", hash); err != nil {
		t.Fatal(err)
	}
	other, err := reopened.ClaimEgress(ctx)
	if err != nil || other == nil || other.Hash == hash {
		t.Fatal(other, err)
	}
	if err = reopened.CompleteEgress(ctx, egress.Completion{Job: *other, Report: syntheticEgress(*other)}); err != nil {
		t.Fatal(err)
	}
	last, err := reopened.ClaimEgress(ctx)
	if err != nil || last == nil || last.Hash != hash || last.Attempt != 4 {
		t.Fatal(last, err)
	}
	if _, err = reopened.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", hash); err != nil {
		t.Fatal(err)
	}
	if repeated, err := reopened.ClaimEgress(ctx); err != nil || repeated != nil {
		t.Fatal("recovery exceeded its total lease budget", repeated, err)
	}
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND reason='initial_lease_exhausted' AND attempts=4 AND first_completed=0 AND tested=0", hash)
	tx, err := reopened.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err = reopened.manageEgress(ctx, tx, "enable", true, egress.Now()); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rearmed, err := reopened.ClaimEgress(ctx)
	if err != nil || rearmed == nil || rearmed.Hash != hash || rearmed.Attempt != 5 {
		t.Fatal("explicit enable did not recover parked job", rearmed, err)
	}
}

func TestMigrationRestoresArchivedInitialReceiptWithoutRequeue(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	newExportSource(t, s, "legacy", sourceURI(639))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil {
		t.Fatal(err)
	}
	r := syntheticEgress(*j)
	r.Samples = nil
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
		t.Fatal(err)
	}
	_, err = s.db.Exec("UPDATE egress_jobs SET state='PENDING',reason='implementation_changed',tested=0,token='legacy',lease_until=? WHERE hash=?; PRAGMA user_version=47", egress.Now()+120000, j.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.migrateV48(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND state='UNKNOWN' AND reason=json_extract(decision,'$.reason') AND tested=? AND attempts=1 AND token='' AND valid_until=0", j.Hash, r.Finished)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
}
