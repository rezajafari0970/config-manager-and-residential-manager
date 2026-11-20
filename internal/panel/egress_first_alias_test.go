package panel

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func missingFirstReport(j *egress.Job) egress.Completion {
	n := egress.Now()
	return egress.Completion{Job: *j, Report: egress.Report{Version: egress.Version, Hash: j.Hash, Code: "input_unavailable", Started: n, Finished: n}}
}

func TestFirstRawAliasRecoveryAfterArchiveRefetch(t *testing.T) {
	for _, mode := range []string{"same_bytes", "renamed", "network_hold", "operator_disabled", "iran_guard", "past_assessment", "past_event", "settled_run", "busy_target", "withdrawn_source"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			exec := func(query string, args ...any) {
				t.Helper()
				if _, err := s.db.ExecContext(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
			}
			f := historyInput(t, s, "lost", 190)
			commitProbeInputs(t, s, f.source, f.raw)
			if err := os.Remove(filepath.Join(s.vault.Directory(), f.hash+".blob")); err != nil {
				t.Fatal(err)
			}
			claim := func() *egress.Job {
				t.Helper()
				j, err := s.ClaimEgressLane(ctx, "initial")
				if err != nil || j == nil {
					t.Fatal("first lease", err)
				}
				return j
			}
			old := claim()
			if old.Hash != f.hash || old.Issue != "input_unavailable" {
				t.Fatal("missing raw preflight")
			}
			if err := s.CompleteEgress(ctx, missingFirstReport(old)); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND reason='input_unavailable' AND first_completed=0", f.hash)
			raw := f.raw
			if mode != "same_bytes" {
				raw += "-renamed"
			}
			commitProbeInputs(t, s, f.source, raw)
			exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", f.hash)
			old = claim()
			if mode == "same_bytes" {
				if old.Hash != f.hash || old.Issue != "" || string(old.Raw) != raw {
					t.Fatal("exact refetch did not repair original")
				}
				return
			}
			if old.Hash != f.hash || old.Issue != "input_unavailable" {
				t.Fatal("expected original hash preflight")
			}
			alias := egress.Hash([]byte(raw))
			var created int64
			if err := s.db.QueryRow("SELECT created FROM egress_unique WHERE hash=?", f.hash).Scan(&created); err != nil {
				t.Fatal(err)
			}
			exec("INSERT OR IGNORE INTO egress_first_backlog(source_id,hash) VALUES(?,?)", f.source, f.hash)
			if _, err := s.ResetEgress(ctx, 0); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "network_hold":
				exec(`INSERT INTO egress_network_results(identity,hash,candidate_hash,policy,state,reason,checked_at,valid_until,held,clean_rounds,last_finished,clean_until,last_adverse,summary)
				VALUES(?,?,'','','hosting','ads_hosting_exit',1,0,1,0,1,0,'{}','{}')`, f.identity, f.hash)
			case "operator_disabled":
				exec("INSERT INTO config_controls(id,action,created,expires) VALUES(?,'disabled',?,?)", f.identity, egress.Now(), egress.Now()+3600000)
			case "iran_guard":
				exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", f.identity)
			case "past_event":
				exec("INSERT INTO egress_events(hash,at,state,reason) VALUES(?,1,'UNKNOWN','fixture')", alias)
			case "settled_run":
				exec("UPDATE egress_run_members SET settled_at=1 WHERE hash=?", f.hash)
			case "busy_target":
				exec("UPDATE egress_jobs SET token='other-lease',lease_until=? WHERE hash=?", egress.Now()+120000, alias)
			case "withdrawn_source":
				commitProbeInputs(t, s, f.source, sourceURI(192))
			case "past_assessment":
				exec("INSERT INTO egress_settlements(hash,at,state) VALUES(?,1,'UNKNOWN')", f.hash)
			}
			err := s.CompleteEgress(ctx, missingFirstReport(old))
			if mode != "renamed" {
				if err != nil && err != ErrConflict {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE identity=? AND hash=?", f.identity, f.hash)
				pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE source_id=? AND hash=?", f.source, f.hash)
				return
			}
			if err != nil {
				t.Fatal("replacement transaction", err)
			}
			if err = s.CompleteEgress(ctx, missingFirstReport(old)); err != ErrConflict {
				t.Fatal("stale original lease", err)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE identity=? AND hash=? AND created=?", f.identity, alias, created)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE hash=? AND source_id=?", alias, f.source)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_run_members WHERE hash=? AND status='pending'", alias)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", f.hash)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM pragma_foreign_key_check")
			key, path := s.key, filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db")
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			s, err = Open(path, key)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			j := claim()
			if j.Hash != alias || j.Token == old.Token || j.Issue != "" || string(j.Raw) != raw {
				t.Fatal("replacement lease did not test actual alias")
			}
			if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash IN (?,?) AND first_completed=1", f.hash, alias)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_run_members WHERE hash=? AND status='completed'", alias)
			pendingCount(t, s.db, 1, "SELECT first_assessments FROM egress_metrics WHERE id=1")
			pendingCount(t, s.db, 1, "SELECT registered FROM egress_metrics WHERE id=1")
		})
	}
}

func TestMissingFirstDoesNotAlternateRepresentativesOnDiskFlaps(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	original := sourceURI(171)
	originalSource, _ := newExportSource(t, s, "original", original)
	alias := original + "-renamed"
	newExportSource(t, s, "alternative", alias)
	oldHash, newHash := egress.Hash([]byte(original)), egress.Hash([]byte(alias))
	remove := func(hash string) {
		t.Helper()
		if err := os.Remove(filepath.Join(s.vault.Directory(), hash+".blob")); err != nil {
			t.Fatal(err)
		}
	}
	finishMissing := func(hash string) {
		t.Helper()
		if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash); err != nil {
			t.Fatal(err)
		}
		j, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || j == nil || j.Hash != hash || j.Issue != "input_unavailable" {
			t.Fatal("unavailable first", err)
		}
		if err = s.CompleteEgress(ctx, missingFirstReport(j)); err != nil {
			t.Fatal(err)
		}
	}
	remove(oldHash)
	finishMissing(oldHash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE hash=?", newHash)
	ref, err := s.vault.Put(ctx, strings.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	s.vault.Release(ref.Hash)
	remove(newHash)
	finishMissing(newHash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE hash=?", newHash)
	// The original now returns in an actual successful source response.
	commitProbeInputs(t, s, originalSource, original)
	finishMissing(newHash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_unique WHERE hash=?", oldHash)
}
