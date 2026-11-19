package panel

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestIranCompletionInvalidatesOnlyBodiesContainingIdentity(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	stale, _ := newExportSource(t, s, "rotating", sourceURI(151))
	owner, _ := newExportSource(t, s, "guarded", sourceURI(151))
	unrelated, _ := newExportSource(t, s, "unrelated", sourceURI(152))
	// Both sources rotate after sharing a representation. The third keeps
	// its own earlier guard in persistent history.
	commitProbeInputs(t, s, stale, sourceURI(153))
	old := fixtureResult(t, s, sourceURI(152)).Items[0].Identity
	if _, err := s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", old); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, unrelated, sourceURI(154))
	guarded := fixtureResult(t, s, sourceURI(151)).Items[0]
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=CASE WHEN hash=? THEN 0 ELSE 9999999999999 END", guarded.Hash); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		if round == 1 {
			if _, err := s.db.Exec("UPDATE egress_iran_guard SET last_round=last_round-61000 WHERE identity=?", guarded.Identity); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", guarded.Hash); err != nil {
				t.Fatal(err)
			}
		}
		j, err := s.ClaimEgress(ctx)
		if err != nil || j == nil || j.Hash != guarded.Hash {
			t.Fatal("missing expected lease", err)
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: iranFixture(*j)}); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Response(ctx, owner); !errors.Is(err, ErrNotFound) {
			t.Fatal("guarded body accessible", round, err)
		}
		for _, clean := range []string{stale, unrelated} {
			if _, err = s.Response(ctx, clean); err != nil {
				t.Errorf("clean response lost in round %d: %v", round, err)
			}
		}
	}
}

func TestDeferredSourceCannotCacheGuardedBody(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprint(staged), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			id, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			if err = s.Complete(ctx, claimOne(t, s, id), cardinalityFixture(t, s, 64), now); err != nil {
				t.Fatal(err)
			}
			r := acquisitionResult(t, s, sourceURI(155), sourceURI(156))
			if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", r.Items[0].Identity); err != nil {
				t.Fatal(err)
			}
			j := claimOne(t, s, id)
			if staged {
				for _, item := range r.Items {
					if _, err = s.Stage(ctx, j, item); err != nil {
						t.Fatal(err)
					}
				}
				r.Staged = true
				r.Items = nil
			}
			if err = s.Complete(ctx, j, r, now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			got, err := s.Get(ctx, id)
			if err != nil || got.ConfigCount != 64 || got.ErrorCode != "source_count_drop_pending" {
				t.Fatal("lost source baseline", err)
			}
			if _, err = s.Response(ctx, id); !errors.Is(err, ErrNotFound) {
				t.Fatal("deferred body exposed before guard clearance", err)
			}
		})
	}
}

func TestGuardAppliedAfterDeferredBodyAndLegacyUpgrade(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			source, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			if err = s.Complete(ctx, claimOne(t, s, source), cardinalityFixture(t, s, 64), time.Now()); err != nil {
				t.Fatal(err)
			}
			small := acquisitionResult(t, s, sourceURI(157))
			if err = s.Complete(ctx, claimOne(t, s, source), small, time.Now()); err != nil {
				t.Fatal(err)
			}
			if ref, err := s.Response(ctx, source); err != nil || ref.Hash != small.Raw.Hash {
				t.Fatal("lost initial deferred response", err)
			}
			if legacy {
				if _, err = s.db.Exec("DROP TRIGGER response_inputs_replaced; DROP TABLE response_inputs; PRAGMA user_version=53"); err != nil {
					t.Fatal(err)
				}
				if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", small.Items[0].Identity); err != nil {
					t.Fatal(err)
				}
				if err = s.migrateV54(); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = s.db.Exec("UPDATE egress_jobs SET next_run=9999999999999 WHERE hash!=?", small.Items[0].Hash); err != nil {
					t.Fatal(err)
				}
				j, err := s.ClaimEgress(ctx)
				if err != nil || j == nil || j.Hash != small.Items[0].Hash {
					t.Fatal("missing deferred first", err)
				}
				if err = s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: iranFixture(*j)}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.Response(ctx, source); !errors.Is(err, ErrNotFound) {
				t.Fatal("guarded deferred cache survived", err)
			}
		})
	}
}
