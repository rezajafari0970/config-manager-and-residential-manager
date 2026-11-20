package panel

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestFirstQueueSnapshotSeparatesWorkAndReportsObservedWindows(t *testing.T) {
	s := testStore(t)
	inputs := []string{}
	for n := 701; n < 709; n++ {
		inputs = append(inputs, sourceURI(n))
	}
	source, _ := newExportSource(t, s, "first-queue", inputs...)
	newExportSource(t, s, "other-owner", inputs[0], inputs[1])
	now := egress.Now()
	ctx := context.WithValue(context.Background(), readTimeKey{}, now)
	q, err := freezeEgress(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	h := func(i int) string { return egress.Hash([]byte(inputs[i])) }
	exec("UPDATE egress_first_arrivals SET queued_at=?", now-4000)
	exec("UPDATE egress_unique SET created=?", now-4000)
	exec("UPDATE egress_unique SET created=? WHERE hash=?", now-9000, h(2))
	exec("UPDATE egress_first_arrivals SET queued_at=? WHERE identity=(SELECT identity FROM egress_unique WHERE hash=?)", now-9000, h(2))
	exec("UPDATE egress_unique SET created=? WHERE hash=?", now-6000, h(1))
	exec("UPDATE egress_first_arrivals SET queued_at=? WHERE identity=(SELECT identity FROM egress_unique WHERE hash=?)", now-6000, h(1))
	exec("UPDATE egress_jobs SET token='worker',lease_until=? WHERE hash=?", now+1000, h(0))
	exec("UPDATE egress_jobs SET next_run=?,retry_streak=1 WHERE hash=?", now+20, h(2))
	exec("UPDATE egress_jobs SET paused=1 WHERE hash=?", h(3))
	exec("UPDATE egress_jobs SET state='DELETED',reason='manual_delete' WHERE hash=?", h(6))
	exec("UPDATE egress_jobs SET reason='ads_iran_quarantined' WHERE hash=?", h(7))
	for _, i := range []int{0, 1, 4, 5} {
		exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", source, h(i))
		exec("DELETE FROM memberships WHERE source_id=? AND raw_hash=?", source, h(i))
	}
	exec("UPDATE egress_jobs SET token='expired',lease_until=? WHERE hash=?", now, h(4))
	exec("UPDATE egress_jobs SET next_run=? WHERE hash=?", now+10000, h(5))
	exec("UPDATE metadata SET value=? WHERE key='egress-first-results-since'", now-30000)
	for _, row := range []struct {
		at    int64
		scope string
	}{
		{now - 30000, "current"}, {now, "withdrawn"}, {now, "historical"}, {now, ""},
		{now - 30001, "current"}, {now + 1, "withdrawn"}, {now - 300000, "current"},
	} {
		exec("INSERT INTO egress_events(hash,at,state,reason,first_result_scope) VALUES(?,?,'UNKNOWN','fixture',?)", egress.Hash([]byte("completed independent receipt")), row.at, row.scope)
	}
	get := func() firstAssessmentProgress {
		t.Helper()
		p, err := firstAssessmentState(ctx, q, now)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := get()
	c, w := p.Current, p.Withdrawn
	if c.Awaiting != 5 || c.SafetyReview != 1 || c.DelayedRecovery != 1 || c.OperatorExcluded != 1 || c.Ready != 1 || c.Running != 1 || c.Delayed != 1 || c.Paused != 1 || c.Excluded != 1 || c.OldestReadyAge != 6000 || c.OldestWaitingAge != 9000 {
		t.Fatalf("current %+v", c)
	}
	if w.Awaiting != 2 || w.Ready != 1 || w.Delayed != 1 || w.OldestReadyAge != 4000 {
		t.Fatalf("withdrawn %+v", w)
	}
	r := p.FirstResults5m
	if r.ObservedMS != 30000 || r.Current != 1 || r.Withdrawn != 2 || r.Historical != 1 || r.PerMinute != nil {
		t.Fatalf("partial window %+v", r)
	}
	exec("UPDATE metadata SET value=? WHERE key='egress-first-results-since'", now-900000)
	r = get().FirstResults5m
	if r.ObservedMS != 300000 || r.Current != 2 || r.Withdrawn != 2 || r.Historical != 1 || r.PerMinute == nil || *r.PerMinute != 0.8 {
		t.Fatalf("full window %+v", r)
	}
	exec("UPDATE egress_settings SET enabled=0")
	p = get()
	if p.Current.Paused != 3 || p.Current.Running != 1 || p.Withdrawn.Paused != 2 || p.Withdrawn.Ready != 0 {
		t.Fatal("disabled dispatch", p)
	}
}

func TestFirstResultEventScopesFirstCompletionOnly(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, _ := newExportSource(t, s, "result-scope", sourceURI(715), sourceURI(716))
	for i := range 2 {
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil {
			t.Fatalf("initial %d: %v, %v", i, job, err)
		}
		if i == 1 {
			if _, err = s.db.Exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", source, job.Hash); err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec("DELETE FROM memberships WHERE raw_hash=?", job.Hash); err != nil {
				t.Fatal(err)
			}
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec("UPDATE egress_jobs SET next_run=0"); err != nil {
		t.Fatal(err)
	}
	repeat, err := s.ClaimEgress(ctx)
	if err != nil || repeat == nil {
		t.Fatal(repeat, err)
	}
	if err = s.CompleteEgress(ctx, egress.Completion{Job: *repeat, Report: syntheticEgress(*repeat)}); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"current", "withdrawn", ""} {
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE first_result_scope=?", scope)
	}
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	reply := httptest.NewRecorder()
	egressModule{app}.state(reply, httptest.NewRequest("GET", "/api/egress?brief=1", nil))
	var body struct {
		Accounting struct {
			First firstAssessmentProgress `json:"first_assessment"`
		} `json:"accounting"`
	}
	if reply.Code != 200 {
		t.Fatal("state response", reply.Code, reply.Body.String())
	}
	if err = json.Unmarshal(reply.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	r := body.Accounting.First.FirstResults5m
	if r.Current != 1 || r.Withdrawn != 1 {
		t.Fatal("first completion counts in API", r)
	}
}

func TestFirstAssessmentQueueUsesRepresentativeLookups(t *testing.T) {
	s := testStore(t)
	rows, err := s.db.Query("EXPLAIN QUERY PLAN "+firstAssessmentQueueSQL, egress.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var a, b, c int
		var step string
		if err = rows.Scan(&a, &b, &c, &step); err != nil {
			t.Fatal(err)
		}
		plan += step + "\n"
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plan, "SCAN j ") || strings.Contains(plan, "SCAN u ") || !strings.Contains(plan, "SEARCH j USING INDEX") {
		t.Fatal("expected only indexed representative/job lookups", plan)
	}
}

func TestFirstAssessmentAPISeparatesHistoricalRecoveryPhases(t *testing.T) {
	s := testStore(t)
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	type snapshot struct {
		Archive *archiveRecoveryProgress `json:"archive_recovery"`
		First   firstAssessmentProgress  `json:"first_assessment"`
	}
	get := func() snapshot {
		t.Helper()
		reply := httptest.NewRecorder()
		egressModule{app}.state(reply, httptest.NewRequest("GET", "/api/egress?brief=1", nil))
		if reply.Code != 200 {
			t.Fatal(reply.Code, reply.Body.String())
		}
		var response struct {
			Accounting snapshot `json:"accounting"`
		}
		if err := json.Unmarshal(reply.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Accounting
	}
	if initial := get(); initial.Archive == nil || initial.Archive.Total != 0 {
		t.Fatal("empty cohort", initial)
	}
	// This fixture sets the maintained counters directly; the API read must
	// not discover or admit new identities while reporting any of these phases.
	for phase, total := range map[string]int{"waiting": 31, "active": 2, "promoted": 3, "completed": 4, "unavailable": 19, "paused": 5, "cancelled": 6} {
		if _, err = s.db.Exec("INSERT INTO egress_first_history_counts(phase,total) VALUES(?,?) ON CONFLICT(phase) DO UPDATE SET total=excluded.total", phase, total); err != nil {
			t.Fatal(err)
		}
	}
	state := get()
	want := archiveRecoveryProgress{Total: 70, Waiting: 31, Active: 2, Promoted: 3, Completed: 4, Unavailable: 19, Paused: 5, Cancelled: 6}
	if state.Archive == nil || *state.Archive != want || state.First.Current.Awaiting != 0 || state.First.Withdrawn.Awaiting != 0 {
		t.Fatalf("historical work mixed with normal queue: %+v", state)
	}
}

func TestFirstResultAttributionExcludesColdArchive(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	historical := historyInput(t, s, "receipt-history", 125)
	current := historyInput(t, s, "receipt-returned", 126)
	withdrawn := historyInput(t, s, "receipt-modern-pin", 127)
	exerciseHistoryUpgrade(t, s)
	commitProbeInputs(t, s, current.source, current.raw)
	if _, err := s.db.Exec("INSERT INTO egress_first_backlog(source_id,hash) VALUES(?,?)", withdrawn.source, withdrawn.hash); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{current.hash: "current", withdrawn.hash: "withdrawn"}
	for range 2 {
		job, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || job == nil {
			t.Fatal("first claim", job, err)
		}
		if job.Hash == historical.hash {
			t.Fatal("cold archive entered first queue")
		}
		if err = s.CompleteEgress(ctx, egress.Completion{Job: *job, Report: syntheticEgress(*job)}); err != nil {
			t.Fatal(err)
		}
		pendingCount(t, s.db, 1, "SELECT count(*) FROM egress_events WHERE hash=? AND first_result_scope=?", job.Hash, want[job.Hash])
		delete(want, job.Hash)
	}
	if len(want) != 0 {
		t.Fatal("missing first completions", want)
	}
	p, err := firstAssessmentState(ctx, s.db, egress.Now())
	if err != nil {
		t.Fatal(err)
	}
	r := p.FirstResults5m
	if r.Current != 1 || r.Withdrawn != 1 || r.Historical != 0 {
		t.Fatal("historical subset of withdrawn", r)
	}
}
