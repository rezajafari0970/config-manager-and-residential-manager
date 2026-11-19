package panel

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestHistoryDiscoveryShareSurvivesRestartAndRefetch(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	first := historyInput(t, s, "history-first", 80)
	second := historyInput(t, s, "history-second", 81)
	refetch := historyInput(t, s, "history-refetch", 82)
	pinned := historyInput(t, s, "history-pinned", 83)
	exerciseHistoryUpgrade(t, s)
	commitProbeInputs(t, s, refetch.source, refetch.raw)
	if _, err := s.db.Exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", pinned.source, pinned.hash); err != nil {
		t.Fatal(err)
	}
	for i, f := range []historyFixture{first, second, refetch, pinned} {
		if _, err := s.db.Exec("UPDATE egress_unique SET created=? WHERE hash=?", i+1, f.hash); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec("UPDATE egress_first_history SET ready_at=? WHERE hash=?", i+1, f.hash); err != nil {
			t.Fatal(err)
		}
	}
	var current []string
	for i := 0; i < 9; i++ {
		current = append(current, sourceURI(90+i))
	}
	newExportSource(t, s, "modern", current...)
	seen := map[string]bool{}
	for i := 1; i <= 13; i++ {
		if i == 9 {
			path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			s = reopened
		}
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil || seen[job.Hash] {
			t.Fatalf("discovery grant %d: %+v, %v", i, job, err)
		}
		seen[job.Hash] = true
		if (job.Hash == first.hash) != (i == 10) || (job.Hash == second.hash) != (i == 13) ||
			(job.Hash == refetch.hash) != (i == 1) || (job.Hash == pinned.hash) != (i == 2) {
			t.Fatalf("wrong modern/history share on grant %d: %s", i, job.Hash)
		}
	}
	pendingCount(t, s.db, 2, "SELECT total FROM egress_first_history_counts WHERE phase='active'")
	pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_export_eligible")
}

func TestHistoryHeadAtCapacityRecoversActiveInsteadOfOpeningAnother(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	older := historyInput(t, s, "older-cold", 101)
	retry := historyInput(t, s, "active-retry", 102)
	exerciseHistoryUpgrade(t, s)
	// Model 31 occupied archive slots plus one interrupted lease. Capacity
	// limits must hold even when active rows survived a previous worker crash.
	if _, err := s.db.Exec(`WITH RECURSIVE slots(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM slots WHERE i<31)
 INSERT INTO egress_first_history(hash,source_id,created,phase,ready_at,raw_available)
 SELECT printf('standin-%d',i),?,1,'active',?,1 FROM slots`, older.source, egress.Now()+60000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET token='expired',lease_until=2,attempts=1 WHERE hash=?", retry.hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE egress_first_history SET ready_at=1 WHERE hash=?", older.hash); err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || job == nil || job.Hash != retry.hash || job.Token == "expired" {
		t.Fatal("did not recover active history at the bound", job, err)
	}
	next, err := s.ClaimEgressLane(ctx, "initial")
	if err != nil || next != nil {
		t.Fatal("opened a new archive slot above the bound", next, err)
	}
	pendingCount(t, s.db, 32, "SELECT total FROM egress_first_history_counts WHERE phase='active'")
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='waiting'", older.hash)
}

func TestHistoryHeadPlanUsesOnlyIndexedCandidates(t *testing.T) {
	s := testStore(t)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN SELECT "+egressHistoryHead, sql.Named("claim_now", egress.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	active, ready := false, false
	for rows.Next() {
		var id, parent, aux int
		var detail string
		if err := rows.Scan(&id, &parent, &aux, &detail); err != nil {
			t.Fatal(err)
		}
		active = active || strings.Contains(detail, "egress_first_history_active_due (ready_at<")
		ready = ready || strings.Contains(detail, "egress_first_history_due (ready_at<")
		if strings.Contains(detail, "SCAN egress_first_history") || strings.Contains(detail, "USE TEMP B-TREE") {
			t.Fatal("historical selector scans or resorts the archive", detail)
		}
	}
	if err := rows.Err(); err != nil || !active || !ready {
		t.Fatal("missing bounded historical index seek", active, ready, err)
	}
}

func TestStaleHistoryPreflightRollsBackSlot(t *testing.T) {
	s := testStore(t)
	f := historyInput(t, s, "stale-history", 104)
	exerciseHistoryUpgrade(t, s)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	before := s.db.Stats().WaitCount
	result := make(chan error, 1)
	go func() {
		job, err := s.ClaimEgressLane(ctx, "initial")
		if job != nil {
			err = ErrConflict
		}
		result <- err
	}()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for s.db.Stats().WaitCount == before {
		select {
		case e := <-result:
			t.Fatal("claim did not reach the writer fence", e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
	// A competing lease advanced the discovery turn after this reader ranked.
	if _, err := tx.Exec("INSERT INTO metadata(key,value) VALUES('egress-modern-first-grants',1)"); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal("stale history lease escaped", err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_history WHERE hash=? AND phase='waiting'", f.hash)
	pendingCount(t, s.db, 0, "SELECT attempts FROM egress_jobs WHERE hash=?", f.hash)
}
