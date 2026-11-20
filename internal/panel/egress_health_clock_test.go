package panel

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
)

func TestResidentialHealthClockIndependentOfRouteRenewals(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "independent-maintenance", sourceURI(482))
	j, err := s.ClaimEgress(ctx)
	if err != nil || j == nil || j.HealthDue {
		t.Fatal("first admission", j, err)
	}
	hash := j.Hash
	complete := func(j *egress.Job) {
		t.Helper()
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); err != nil {
			t.Fatal(err)
		}
	}
	complete(j)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	field := func(q string) int64 {
		t.Helper()
		var value int64
		if err := s.db.QueryRow(q, hash).Scan(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	claim := func(health bool) *egress.Job {
		t.Helper()
		exec("UPDATE egress_jobs SET next_run=0 WHERE hash=?", hash)
		job, err := s.ClaimEgress(ctx)
		if err != nil || job == nil || job.Hash != hash || !job.Accepted || job.HealthDue != health {
			t.Fatal("wrong maintenance grant", job, err)
		}
		return job
	}
	clock := "SELECT checked_at FROM egress_health_clock WHERE hash=?"
	next := "SELECT next_run FROM egress_jobs WHERE hash=?"
	// A prior eight-minute route renewal with a fifteen-minute policy.
	base := egress.Now() - 8*60000
	exec("UPDATE egress_health_clock SET checked_at=? WHERE hash=?", base, hash)
	complete(claim(false))
	if field(clock) != base || field(next) != base+15*60000 {
		t.Fatal("route renewal postponed health deadline", field(clock), field(next))
	}
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	set := func(body string) {
		t.Helper()
		rr := httptest.NewRecorder()
		egressModule{app}.lifecycle(rr, httptest.NewRequest("POST", "/api/egress/lifecycle", strings.NewReader(body)))
		if rr.Code != 200 {
			t.Fatal(rr.Code, rr.Body.String())
		}
	}
	set(`{"revision":1,"health_minutes":1}`)
	if field(next) != base+60000 {
		t.Fatal("shortened health interval reset to most recent route", field(next))
	}
	expired := claim(true)
	exec("UPDATE egress_jobs SET lease_until=1 WHERE hash=?", hash)
	recovery := claim(true)
	if err := s.CompleteEgress(ctx, egress.Completion{Job: *expired, Report: syntheticEgress(*expired)}); err != ErrConflict {
		t.Fatal("expired grant updated health clock", err)
	}
	if field(clock) != base {
		t.Fatal("uncompleted grant changed maintenance clock")
	}
	complete(recovery)
	if field(clock) <= base || field(next) != field(clock)+60000 {
		t.Fatal("configured one-minute cycle not maintained", field(clock), field(next))
	}
	set(`{"revision":2,"health_minutes":60}`)
	if field(next) > field(clock)+egress.IranInterval {
		t.Fatal("long schedule extended already-issued proof")
	}
	complete(claim(false))
	if field(next) > field(clock)+egress.IranInterval || field("SELECT valid_until FROM egress_jobs WHERE hash=?") > egress.Now()+egress.IranInterval {
		t.Fatal("long schedule bypassed safety limit")
	}
}
