package panel

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestOrdinaryFirstKeepsPlaceWhenSourceRenamesOldestOfSeven(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	source, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	// A pre-upgrade positive, captured with its original measurement timestamp.
	// Reopening and rotating sources must preserve that independent history.
	if _, err := s.db.Exec("INSERT INTO conversion_first_assessed VALUES(?,?,?,?)", strings.Repeat("1", 64), strings.Repeat("2", 64), convert.Version, 1234); err != nil {
		t.Fatal(err)
	}
	oldest := sourceURI(200)
	commitProbeInputs(t, s, source, oldest)
	time.Sleep(3 * time.Millisecond)
	generation := []string{oldest}
	for i := 201; i <= 206; i++ {
		generation = append(generation, sourceURI(i))
	}
	commitProbeInputs(t, s, source, generation...)
	time.Sleep(3 * time.Millisecond)
	generation[0] = oldest + "-remark-only"
	commitProbeInputs(t, s, source, generation...)
	var canonical string
	// Look up the cosmetic alias through its live source membership. A stale
	// original raw is neither a valid lease nor an output candidate here.
	newHash := repair.Digest([]byte(generation[0]))
	if err := s.db.QueryRow("SELECT artifact_id FROM memberships WHERE source_id=? AND raw_hash=?", source, newHash).Scan(&canonical); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog WHERE identity=?", canonical)
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_jobs WHERE hash=?", repair.Digest([]byte(oldest)))
	path, key := filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db"), s.key
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	job, err := s.ClaimProbe(ctx)
	if err != nil || job == nil || job.Hash != newHash || string(job.Raw) != generation[0] {
		t.Fatal("source rename pushed the oldest identity behind the six later inputs", err)
	}
	if err := s.CompleteProbe(ctx, conversionResult(*job, 0, false)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE identity=? AND hash=?", canonical, newHash)
	pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE hash=? AND tested=1234", strings.Repeat("2", 64))
}

func TestOrdinaryFirstClockCannotOwnAPolicyBlockedOrReplacedSource(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	source, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	a := sourceURI(220)
	commitProbeInputs(t, s, source, a)
	var identity string
	if err := s.db.QueryRow("SELECT artifact_id FROM memberships WHERE source_id=?", source).Scan(&identity); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, source, a+"-renamed", sourceURI(221))
	if _, err = s.db.Exec("INSERT INTO egress_iran_guard(identity,state,first_seen) VALUES(?,'QUARANTINED',1)", identity); err != nil {
		t.Fatal(err)
	}
	job, err := s.ClaimProbe(ctx)
	if err != nil || job == nil || string(job.Raw) != sourceURI(221) {
		t.Fatal("older blocked clock overrode current policy", err)
	}
	if err = s.CompleteProbe(ctx, conversionResult(*job, 0, false)); err != nil {
		t.Fatal(err)
	}
	previous, err := s.Get(ctx, source)
	if err != nil {
		t.Fatal(err)
	}
	previous.URL += "/new-owner"
	if _, err = s.Save(ctx, source, previous.Revision, previous.SourceInput); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM egress_iran_guard WHERE identity=?", identity); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog WHERE identity=?", identity)
	if job, err = s.ClaimProbe(ctx); err != nil || job != nil {
		t.Fatal("historical first age created work for a removed source", err)
	}
}

func TestOrdinaryFirstLeaseKeepsExactActiveRawAcrossDirectSourceRename(t *testing.T) {
	for _, staged := range []bool{false, true} {
		for _, priorPin := range []bool{false, true} {
			mode := map[bool]string{false: "direct", true: "staged"}[staged]
			if priorPin {
				mode += "-earlier-pin"
			}
			t.Run(mode, func(t *testing.T) {
				ctx := context.Background()
				s := testStore(t)
				source, err := s.Save(ctx, "", 0, testSource())
				if err != nil {
					t.Fatal(err)
				}
				initial, filler := sourceURI(222), sourceURI(225)
				generation := []string{initial}
				if priorPin {
					commitProbeInputs(t, s, source, initial+"-oldest-remark")
					commitProbeInputs(t, s, source, filler)
					generation = append(generation, filler)
				}
				commitProbeInputs(t, s, source, generation...)
				if _, err = s.db.Exec("UPDATE conversion_jobs SET next_run=9999999999999,version=? WHERE hash!=?", convert.Version, repair.Digest([]byte(initial))); err != nil {
					t.Fatal(err)
				}
				running, err := s.ClaimProbe(ctx)
				if err != nil || running == nil || string(running.Raw) != initial {
					t.Fatal("missing original lease", err)
				}
				if priorPin {
					pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_backlog WHERE hash!=?", running.Hash)
				}
				generation[0] = initial + "-new-display-name"
				collection := claimOne(t, s, source)
				next := acquisitionResult(t, s, generation...)
				if staged {
					if _, err := s.StageBatch(ctx, collection, next.Items); err != nil {
						t.Fatal(err)
					}
					next.Staged, next.Items = true, nil
				}
				concurrent := make(chan error, 1)
				go func() {
					second, err := s.ClaimProbe(ctx)
					if err == nil && second != nil {
						err = errors.New("duplicate grant concurrent with source replacement")
					}
					concurrent <- err
				}()
				err = s.Complete(ctx, collection, next, time.Now())
				if claimErr := <-concurrent; err != nil || claimErr != nil {
					t.Fatal("concurrent completion and claim", err, claimErr)
				}
				pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_inputs WHERE hash=?", running.Hash)
				pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_backlog WHERE hash=?", running.Hash)
				if err := s.RenewProbe(ctx, *running); err != nil {
					t.Fatalf("the active first probe lost its exact raw after a cosmetic rename: %v", err)
				}
				if second, err := s.ClaimProbe(ctx); err != nil || second != nil {
					t.Fatal("source rename allowed concurrent ordinary probes of the same identity", err)
				}
				if err := s.CompleteProbe(ctx, conversionResult(*running, 0, false)); err != nil {
					t.Fatal(err)
				}
				pendingCount(t, s.db, 1, "SELECT count(*) FROM conversion_first_assessed WHERE hash=?", running.Hash)
				pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog")
			})
		}
	}
}

func TestOrdinaryFirstExpiredRenamedLeaseYieldsToCurrentRaw(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	original := sourceURI(226)
	source, first := addConversion(t, s, original)
	renamed := original + "-fresh-remark"
	commitProbeInputs(t, s, source, renamed)
	if _, err := s.db.Exec("UPDATE conversion_jobs SET lease_until=1 WHERE hash=?", first.Hash); err != nil {
		t.Fatal(err)
	}
	if err := s.RenewProbe(ctx, first); !errors.Is(err, ErrConflict) {
		t.Fatal("revived expired lease", err)
	}
	next, err := s.ClaimProbe(ctx)
	if err != nil || next == nil || string(next.Raw) != renamed {
		t.Fatal("failed to retry current owned alias after an expired raw lease", err)
	}
	if err := s.CompleteProbe(ctx, conversionResult(first, 0, false)); !errors.Is(err, ErrConflict) {
		t.Fatal("accepted expired raw after a new current lease", err)
	}
	if err := s.CompleteProbe(ctx, conversionResult(*next, 0, false)); err != nil {
		t.Fatal(err)
	}
	pendingCount(t, s.db, 0, "SELECT count(*) FROM conversion_first_backlog")
}

func TestOrdinaryFirstRawRenameCannotErasePreviousGrantTime(t *testing.T) {
	ctx := context.Background()
	s := testStore(t)
	source, err := s.Save(ctx, "", 0, testSource())
	if err != nil {
		t.Fatal(err)
	}
	a, b := sourceURI(223), sourceURI(224)
	commitProbeInputs(t, s, source, a)
	time.Sleep(3 * time.Millisecond)
	commitProbeInputs(t, s, source, a, b)
	time.Sleep(3 * time.Millisecond)
	running, err := s.ClaimProbe(ctx)
	if err != nil || running == nil || string(running.Raw) != a {
		t.Fatal("missing the oldest raw", err)
	}
	failure := conversionResult(*running, 0, true)
	failure.Core, failure.Connection, failure.Code = "blocked", "not_run", "probe_infrastructure_error"
	failure.Candidate = nil
	if err := s.CompleteProbe(ctx, failure); err != nil {
		t.Fatal(err)
	}
	commitProbeInputs(t, s, source, a+"-rename-after-failed-grant", b)
	// Simulate the ordinary retry becoming due while the previously ungranted
	// identity is already waiting. Check ordering independently of wall time.
	if _, err = s.db.Exec("UPDATE conversion_jobs SET next_run=0"); err != nil {
		t.Fatal(err)
	}
	second, err := s.ClaimProbe(ctx)
	if err != nil || second == nil || string(second.Raw) != b {
		t.Fatal("renaming the previously granted raw let it overtake the ungranted input", err)
	}
}
