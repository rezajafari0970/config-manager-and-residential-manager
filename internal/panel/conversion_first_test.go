package panel

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
)

func commitProbeInputs(t *testing.T, s *Store, id string, raws ...string) {
	t.Helper()
	j := claimOne(t, s, id)
	if err := s.Complete(context.Background(), j, acquisitionResult(t, s, raws...), time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestOrdinaryFirstProbeSurvivesNaturalWithdrawal(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(131)
	one, j := addConversion(t, s, raw)
	src := testSource()
	src.URL = "https://example.org/ordinary-second"
	two, err := s.Save(ctx, "", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, two, raw+"-alias")
	commitProbeInputs(t, s, one, sourceURI(132))
	commitProbeInputs(t, s, two, sourceURI(133))
	pendingCount(t, s.db, 2, "SELECT count(*) FROM conversion_first_backlog WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_inputs WHERE hash=?", j.Hash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_work_inputs WHERE hash=?", j.Hash)
	if err = s.RenewProbe(ctx, j); err != nil {
		t.Fatal("withdrawal revoked first lease", err)
	}
	temporary := conversionResult(j, 0, true)
	temporary.Core, temporary.Connection, temporary.Code = "blocked", "not_run", "probe_infrastructure_error"
	temporary.Candidate = nil
	if err = s.CompleteProbe(ctx, temporary); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 2, "SELECT count(*) FROM conversion_first_backlog WHERE hash=?", j.Hash)
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err = reopened.db.Exec("UPDATE conversion_jobs SET version=?,next_run=CASE WHEN hash=? THEN 0 ELSE 9999999999999 END", temporary.Version, j.Hash); err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.ClaimProbe(ctx)
	if err != nil || retry == nil || retry.Hash != j.Hash || string(retry.Raw) != raw {
		t.Fatal("first probe not restored", err)
	}
	if err = reopened.CompleteProbe(ctx, conversionResult(*retry, 0, true)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM conversion_first_backlog")
	pendingCount(t, reopened.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE hash=?", j.Hash)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM conversion_inputs WHERE hash=?", j.Hash)
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM conversion_work_inputs WHERE hash=?", j.Hash)
	// A newly withdrawn copy of the same identity has no second first assessment.
	commitProbeInputs(t, reopened, two, raw+"-again")
	commitProbeInputs(t, reopened, two, sourceURI(134))
	pendingCount(t, reopened.db, 0, "SELECT count(*) FROM conversion_first_backlog WHERE identity IN (SELECT identity FROM conversion_first_assessed)")
}

func TestOrdinaryFirstProbeOwnersRespectSafetyAndAdministration(t *testing.T) {
	for _, mode := range []string{"source-url", "source-deletion", "config-deletion", "quarantine", "source-disable", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			id, j := addConversion(t, s, sourceURI(135))
			if mode == "expiry" {
				if _, err := s.db.Exec("UPDATE artifacts SET expires=1"); err != nil {
					t.Fatal(err)
				}
				if err := s.Expire(ctx, time.Now()); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_inputs WHERE hash=?", j.Hash)
				return
			}
			commitProbeInputs(t, s, id, sourceURI(136))
			var ident string
			if err := s.db.QueryRow("SELECT identity FROM conversion_first_backlog WHERE hash=?", j.Hash).Scan(&ident); err != nil {
				t.Fatal(err)
			}
			src, err := s.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "source-url":
				src.URL += "/other"
				_, err = s.Save(ctx, id, src.Revision, src.SourceInput)
			case "source-deletion":
				err = s.Delete(ctx, id, src.Revision)
			case "config-deletion":
				_, err = s.ManageConfigs(ctx, ConfigBatch{Action: "delete", IDs: []string{ident}})
			case "quarantine":
				_, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", ident)
			case "source-disable":
				src.Enabled = false
				_, err = s.Save(ctx, id, src.Revision, src.SourceInput)
			}
			if err != nil {
				t.Fatal(err)
			}
			pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_inputs WHERE hash=?", j.Hash)
			if err = s.RenewProbe(ctx, j); err != ErrConflict {
				t.Fatal("invalidated job renewed", err)
			}
		})
	}
}

func TestOrdinaryFirstProbeRotatesSources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var sources []string
	for i, raws := range [][]string{{sourceURI(137), sourceURI(138), sourceURI(139)}, {sourceURI(140)}} {
		source := testSource()
		source.URL = "https://example.org/" + strings.Repeat("a", i+1)
		id, err := s.Save(ctx, "", 0, source)
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, id)
		commitProbeInputs(t, s, id, raws...)
	}
	if _, err := s.db.Exec("UPDATE conversion_schedule SET created=CASE WHEN hash IN(SELECT raw_hash FROM memberships WHERE source_id=?) THEN 1 ELSE 2 END", sources[0]); err != nil {
		t.Fatal(err)
	}
	claim := func() *probe.Job {
		t.Helper()
		j, err := s.ClaimProbe(ctx)
		if err != nil || j == nil {
			t.Fatal("missing first test", err)
		}
		return j
	}
	first := claim()
	pendingCount(t, s.db, 1, "SELECT count(*) FROM memberships WHERE source_id=? AND raw_hash=?", sources[0], first.Hash)
	second := claim()
	pendingCount(t, s.db, 1, "SELECT count(*) FROM memberships WHERE source_id=? AND raw_hash=?", sources[1], second.Hash)
}

func TestOrdinaryProbeSerializesUnpreparedSourceAliases(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	raw := sourceURI(141)
	first, leased := addConversion(t, s, raw)
	commitProbeInputs(t, s, first, sourceURI(142))
	src := testSource()
	src.URL = "https://example.org/returned-alias"
	id, err := s.Save(ctx, "", 0, src)
	if err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, id, raw+"-fresh")
	// Remove other due work, leaving only the alias and the live original lease.
	if _, err = s.db.Exec("UPDATE conversion_jobs SET next_run=9999999999999,version=? WHERE hash IN (SELECT raw_hash FROM memberships WHERE source_id=?)", conversionResult(leased, 0, true).Version, first); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimProbe(ctx)
	if err != nil || second != nil {
		t.Fatal("concurrent lease on an unprepared alias", err)
	}
	if err = s.RenewProbe(ctx, leased); err != nil {
		t.Fatal("new alias broke original lease", err)
	}
	if err = s.CompleteProbe(ctx, conversionResult(leased, 0, true)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog")
}
