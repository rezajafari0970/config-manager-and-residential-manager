package panel

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestEgressClaimRankingLooksUpScopedHashes(t *testing.T) {
	s := testStore(t)
	// Keep this SQL on the same path as a real claim, including the nested
	// work view. SQLite can reorder the view's inner joins during flattening.
	query := "EXPLAIN QUERY PLAN " + egressClaimCandidates + "SELECT (" + egressRankedClaim("followup", 3) + ")"
	rows, err := s.db.Query(query, sql.Named("claim_now", egress.Now()))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	scopeScanned, jobLookup := false, false
	var plan []string
	for rows.Next() {
		var id, parent, aux int
		var detail string
		if err = rows.Scan(&id, &parent, &aux, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
		if strings.HasPrefix(detail, "SCAN c") && !strings.HasPrefix(detail, "SCAN claim_scope") {
			scopeScanned = true
		}
		if scopeScanned && strings.HasPrefix(detail, "SEARCH egress_jobs ") && strings.Contains(detail, "(hash=?)") {
			jobLookup = true
		}
		if strings.Contains(detail, "USING INDEX egress_due (paused=?)") {
			t.Fatalf("claim ranking scans the historical due index: %s", detail)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !jobLookup {
		t.Fatalf("expected a scoped hash lookup on egress_jobs: %v", plan)
	}
}

func TestEgressRunSnapshotSkipsArchivedJobs(t *testing.T) {
	s := testStore(t)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+insertEgressRunMembers, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, parent, unused int
		var op string
		if err = rows.Scan(&id, &parent, &unused, &op); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(op, "egress_tested (tested=?)") || strings.Contains(op, "egress_due (paused=?") || strings.HasPrefix(op, "SCAN j ") {
			t.Fatal("archive-wide job lookup inside cohort write", op)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}
