package panel

import (
	"context"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"testing"
	"time"
)

func TestRejectedResponseCannotAdvanceValidators(t *testing.T) {
	for _, state := range []string{"error", "empty", "invalid"} {
		t.Run(state, func(t *testing.T) {
			s := testStore(t)
			ctx := context.Background()
			id, _ := s.Save(ctx, "", 0, testSource())
			first := fixtureResult(t, s, sourceURI(1))
			j := claimOne(t, s, id)
			if e := s.Complete(ctx, j, first, time.Now()); e != nil {
				t.Fatal(e)
			}
			j = claimOne(t, s, id)
			if j.ETag == "" {
				t.Fatal("accepted validator missing")
			}
			bad := collect.Result{State: state, ErrorCode: "body_read_failed", HTTPStatus: 200, ETag: "new-unaccepted", Modified: "new-date"}
			if e := s.Complete(ctx, j, bad, time.Now()); e != nil {
				t.Fatal(e)
			}
			var next int64
			var reason string
			if e := s.db.QueryRow("SELECT next_run,refresh_reason FROM sources WHERE id=?", id).Scan(&next, &reason); e != nil {
				t.Fatal(e)
			}
			if reason != "incomplete_response" || next > time.Now().Add(6*time.Second).UnixNano() {
				t.Fatal("recovery not scheduled")
			}
			j = claimOne(t, s, id)
			if j.ETag != "" || j.Modified != "" {
				t.Fatal("failed body's validators escaped")
			}
			rows, e := s.Outputs(ctx, "", 0, true)
			if e != nil || len(rows) != 1 {
				t.Fatal("retained generation lost", e)
			}
		})
	}
}

func TestLargerRetentionNeverExtendsExistingDeadlines(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := s.Save(ctx, "", 0, testSource())
	if e := s.Complete(ctx, claimOne(t, s, id), fixtureResult(t, s, sourceURI(1)), time.Now()); e != nil {
		t.Fatal(e)
	}
	v, _ := s.Settings(ctx)
	old := map[string]int64{}
	for _, table := range []string{"artifacts", "responses"} {
		var expiry int64
		s.db.QueryRow("SELECT expires FROM " + table + " LIMIT 1").Scan(&expiry)
		old[table] = expiry
	}
	v.RetentionSeconds *= 2
	if e := s.SaveSettings(ctx, v); e != nil {
		t.Fatal(e)
	}
	for table, expiry := range old {
		var got int64
		s.db.QueryRow("SELECT expires FROM " + table + " LIMIT 1").Scan(&got)
		if got != expiry {
			t.Fatal("deadline extended", table)
		}
	}
	if e := s.Complete(ctx, claimOne(t, s, id), fixtureResult(t, s, sourceURI(2)), time.Now()); e != nil {
		t.Fatal(e)
	}
	var maxLife int64
	s.db.QueryRow("SELECT max(expires-created) FROM artifacts").Scan(&maxLife)
	if maxLife != v.RetentionSeconds*1000 {
		t.Fatal("new retention not applied to new input")
	}
}

func TestAbandonedClaimsCannotRevokeReplacements(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var token string
	id, _ := s.Save(ctx, "", 0, testSource())
	cj := claimOne(t, s, id)
	if e := s.Abandon(ctx, cj); e != nil {
		t.Fatal(e)
	}
	replacement := claimOne(t, s, id)
	s.Abandon(ctx, cj)
	s.db.QueryRow("SELECT lease_token FROM sources WHERE id=?", id).Scan(&token)
	if token != replacement.Token {
		t.Fatal("new collection lease revoked")
	}
}
