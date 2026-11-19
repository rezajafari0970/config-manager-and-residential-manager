package panel

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestTransientSmallSourceQueuesNovelInputsWithoutReplacingInventory(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprint("staged=", staged), func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			source, err := s.Save(ctx, "", 0, testSource())
			if err != nil {
				t.Fatal(err)
			}
			large := cardinalityFixture(t, s, 32)
			held := acquisitionResult(t, s, sourceURI(8801), sourceURI(8802))
			first, forbidden := held.Items[0], held.Items[1]
			now := time.Now()
			apply := func(r collect.Result, at time.Time) {
				t.Helper()
				job := claimOne(t, s, source)
				if staged {
					for _, item := range r.Items {
						if _, e := s.Stage(ctx, job, item); e != nil {
							t.Fatal(e)
						}
					}
					r.Items = nil
					r.Staged = true
				}
				if err := s.Complete(ctx, job, r, at); err != nil {
					t.Fatal(err)
				}
			}
			apply(large, now)
			if _, err := s.db.Exec("INSERT INTO input_exclusions(identity,hash,at,manual) VALUES(?,?,?,1)", forbidden.Identity, forbidden.Hash, now.UnixMilli()); err != nil {
				t.Fatal(err)
			}
			apply(held, now.Add(time.Second))
			apply(large, now.Add(15*time.Second))
			pendingCount(t, s.db, 32, "SELECT count(*) FROM memberships WHERE source_id=?", source)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM memberships WHERE artifact_id=?", first.Identity)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_first_backlog WHERE source_id=? AND hash=?", source, first.Hash)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_unique WHERE identity=?", forbidden.Identity)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_inputs WHERE hash=?", first.Hash)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_inputs WHERE hash=?", first.Hash)
			pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_work_inputs WHERE hash=?", forbidden.Hash)
			if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=? WHERE hash!=?", time.Now().Add(time.Hour).UnixMilli(), first.Hash); err != nil {
				t.Fatal(err)
			}
			job, err := s.ClaimEgressLane(ctx, "initial")
			if err != nil || job == nil || job.Hash != first.Hash || job.Issue != "" {
				t.Fatal("held input not claimable", err)
			}
			r := syntheticEgress(*job)
			for i := range r.Samples {
				r.Samples[i].Source = egress.Hash([]byte("ordinary route"))
			}
			if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: r}); err != nil {
				t.Fatal(err)
			}
			apply(held, now.Add(30*time.Second))
			pendingCount(t, s.db, 0, "SELECT count(*) FROM egress_first_backlog WHERE hash=?", first.Hash)
			pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_jobs WHERE hash=? AND first_completed=1 AND attempts=1", first.Hash)
		})
	}
}
