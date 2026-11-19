package panel

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func pendingCount(t *testing.T, db databaseQuery, want int, query string, args ...any) {
	t.Helper()
	var got int
	if err := db.QueryRowContext(context.Background(), query, args...).Scan(&got); err != nil || got != want {
		t.Fatalf("%s: got %d, want %d, err=%v", query, got, want, err)
	}
}

func TestWithdrawnFirstAssessmentSurvivesRotationLeaseAndRestart(t *testing.T) {
	for _, staged := range []bool{false, true} {
		name := map[bool]string{false: "direct", true: "staged"}[staged]
		t.Run(name, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			source, _ := newExportSource(t, s, name, sourceURI(111))
			first, err := s.ClaimEgress(ctx)
			if err != nil || first == nil {
				t.Fatal("first lease", err)
			}
			// The new committed generation withdraws an identity already in flight.
			job := claimOne(t, s, source)
			result := acquisitionResult(t, s, sourceURI(112))
			if staged {
				if _, err = s.StageBatch(ctx, job, result.Items); err != nil {
					t.Fatal(err)
				}
				result.Staged, result.Items = true, nil
			}
			if err = s.Complete(ctx, job, result, time.Now()); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE source_id=? AND hash=?", source, first.Hash)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM memberships WHERE raw_hash=?", first.Hash)
			if err = s.RenewEgress(ctx, *first); err != nil {
				t.Fatal("withdrawal fenced a valid lease", err)
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
			present, err := freezeEgress(ctx, reopened.read(ctx))
			if err != nil {
				t.Fatal(err)
			}
			pendingCount(t, present, 1, "SELECT count(*) FROM egress_work WHERE hash=?", first.Hash)
			pendingCount(t, present, 0, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", first.Hash)
			if ref, err := reopened.Referenced(ctx, first.Hash); err != nil || !ref {
				t.Fatal("lost raw input", err)
			}
			// Expire only the old lease, then re-claim through the normal candidate selector.
			if _, err = reopened.db.Exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", first.Hash); err != nil {
				t.Fatal(err)
			}
			if _, err = reopened.db.Exec("UPDATE egress_jobs SET next_run=? WHERE hash!=?", time.Now().Add(time.Hour).UnixMilli(), first.Hash); err != nil {
				t.Fatal(err)
			}
			retry, err := reopened.ClaimEgressLane(ctx, "initial")
			if err != nil || retry == nil || retry.Hash != first.Hash || retry.Token == first.Token || retry.Issue != "" {
				t.Fatal("withdrawn job", retry != nil, err)
			}
			if err = reopened.RenewEgress(ctx, *first); err != ErrConflict {
				t.Fatal("obsolete lease", err)
			}
			negative := syntheticEgress(*retry)
			for i := range negative.Samples {
				negative.Samples[i].Source = egress.Hash([]byte("shared ordinary route"))
			}
			if err = reopened.CompleteEgress(ctx, egress.Completion{Job: *retry, Report: negative}); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_first_backlog")
			pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", first.Hash)
			pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_events WHERE hash=? AND definitive=1", first.Hash)
			fillExportSource(t, reopened, source, sourceURI(111))
			pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_work WHERE hash=?", first.Hash)
		})
	}
}

func TestWithdrawnFirstAssessmentHonorsOwnerAndIdentityDeletion(t *testing.T) {
	ctx := context.Background()
	for _, admin := range []string{"source-delete", "source-url", "config-delete", "delete-all", "exclude", "iran-block", "pause"} {
		t.Run(admin, func(t *testing.T) {
			s := testStore(t)
			one, _ := newExportSource(t, s, "one", sourceURI(113))
			two, _ := newExportSource(t, s, "two", sourceURI(113))
			var identity, hash string
			if err := s.db.QueryRow("SELECT identity,hash FROM egress_unique").Scan(&identity, &hash); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE artifacts SET expires=1"); err != nil {
				t.Fatal(err)
			}
			if err := s.Expire(ctx, time.Now()); err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_first_backlog")
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_work")
			switch admin {
			case "source-delete", "source-url":
				for n, id := range []string{one, two} {
					src, err := s.Get(ctx, id)
					if err != nil {
						t.Fatal(err)
					}
					if admin == "source-url" {
						src.URL += "/changed"
						_, err = s.Save(ctx, id, src.Revision, src.SourceInput)
					} else {
						err = s.Delete(ctx, id, src.Revision)
					}
					if err != nil {
						t.Fatal(err)
					}
					pendingCount(t, s.db, 1-n, "SELECT count(*) FROM egress_first_backlog")
					pendingCount(t, s.db, 1-n, "SELECT count(*) FROM egress_work")
				}
			case "config-delete", "delete-all":
				b := ConfigBatch{Action: "delete", IDs: []string{identity}}
				if admin == "delete-all" {
					b = ConfigBatch{Action: "delete", All: true}
				}
				if _, err := s.ManageConfigs(ctx, b); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_backlog")
			case "pause":
				if _, err := s.ManageConfigs(ctx, ConfigBatch{Action: "disable", IDs: []string{identity}}); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 2, "SELECT count(*) FROM egress_first_backlog")
			case "iran-block":
				if _, err := s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'BLOCKED',1)", identity); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
			case "exclude":
				if _, err := s.db.Exec("INSERT INTO input_exclusions VALUES(?,1,?,1)", identity, hash); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_work")
			}
			if job, err := s.ClaimEgress(ctx); err != nil || job != nil {
				t.Fatal("revoked or paused input was claimable", err)
			}
		})
	}
}

func TestFirstAssessmentMigrationPreservesEvidenceAndBackup(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "migration", sourceURI(114))
	first, err := s.ClaimEgress(ctx)
	if err != nil || first == nil {
		t.Fatal(err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *first, Report: syntheticEgress(*first)}); err != nil {
		t.Fatal(err)
	}
	// Recreate the actual schema-46 view and stored state before upgrading.
	_, err = s.db.Exec(`DROP TRIGGER egress_first_finished; DROP TRIGGER egress_first_source_replaced;
	DROP VIEW egress_inventory; DROP TABLE egress_first_backlog;
	CREATE VIEW egress_inventory AS SELECT j.* FROM egress_unique u JOIN egress_jobs j ON j.hash=u.hash
	WHERE j.state!='DELETED' AND NOT EXISTS(SELECT 1 FROM input_exclusions x WHERE x.identity=u.identity)
	AND NOT EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='BLOCKED')
	AND (EXISTS(SELECT 1 FROM memberships m WHERE m.artifact_id=u.identity) OR j.ever_accepted=1
	OR EXISTS(SELECT 1 FROM egress_iran_guard g WHERE g.identity=u.identity AND g.state='QUARANTINED'));
	PRAGMA user_version=46;`)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(t.TempDir(), "before.db")
	if _, err = s.db.Exec("VACUUM INTO ?", backup); err != nil {
		t.Fatal(err)
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
	if err = reopened.migrateV47(); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, reopened.db, 47, "PRAGMA user_version")
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", first.Hash)
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM egress_events WHERE hash=?", first.Hash)
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM memberships WHERE source_id=?", id)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM egress_first_backlog")
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM pragma_foreign_key_check")
	previous, err := sql.Open("sqlite", "file:"+backup+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer previous.Close()
	pendingCount(t, previous, 46, "PRAGMA user_version")
	pendingCount(t, previous, 0, "SELECT count(*) FROM sqlite_schema WHERE name='egress_first_backlog'")
	pendingCount(t, previous, 1, "SELECT count(*) FROM egress_export_eligible WHERE hash=?", first.Hash)
}
