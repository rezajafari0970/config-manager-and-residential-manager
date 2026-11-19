package panel

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestExpiryFindsSharedOwnersAndResponseOnlySources(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, name := range []string{"active", "disabled", "fresh", "receipt", "shared"} {
		in := testSource()
		in.Name, in.URL = name, "https://example.invalid/"+name
		in.Enabled = name != "disabled"
		if _, err := s.Save(ctx, "", 0, in); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	future := now.Add(time.Hour)
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{"UPDATE sources SET state='updated',next_run=?", []any{future.UnixNano()}},
		{"UPDATE sources SET state='fetching',lease_token='current',lease_until=? WHERE name='active'", []any{future.UnixMilli()}},
		{"UPDATE sources SET next_run=1 WHERE name='shared'", nil},
		{"INSERT INTO artifacts(id,hash,kind,size,created,expires) VALUES('old','hash','vless',1,1,?),('new','newhash','vless',1,1,?)", []any{now.UnixMilli(), future.UnixMilli()}},
		{"INSERT INTO memberships SELECT s.id,a.id,1,a.hash,a.kind,a.size FROM sources s JOIN artifacts a ON a.id=CASE WHEN s.name='fresh' THEN 'new' ELSE 'old' END WHERE s.name!='receipt'", nil},
		{"INSERT INTO responses SELECT id,'raw',1,1,? FROM sources WHERE name IN ('shared','receipt')", []any{now.UnixMilli()}},
	} {
		if _, err = tx.ExecContext(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err = queueExpiredSources(ctx, tx, now); err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct {
		name, state, reason string
		due                 int64
	}{
		{"active", "fetching", "retention", now.UnixNano()},
		{"disabled", "updated", "", future.UnixNano()},
		{"fresh", "updated", "", future.UnixNano()},
		{"receipt", "queued", "retention", now.UnixNano()},
		{"shared", "queued", "retention", 1},
	} {
		var state, reason string
		var due int64
		if err := tx.QueryRowContext(ctx, "SELECT state,refresh_reason,next_run FROM sources WHERE name=?", want.name).Scan(&state, &reason, &due); err != nil {
			t.Fatal(err)
		}
		if state != want.state || reason != want.reason || due != want.due {
			t.Errorf("%s got %s, %s, %d", want.name, state, reason, due)
		}
	}
}

func BenchmarkQueueExpiredSources(b *testing.B) {
	ctx := context.Background()
	s, err := Open(filepath.Join(b.TempDir(), "data", "panel.db"), bytes.Repeat([]byte{7}, 32))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { s.Close() })
	for i := 0; i < 30; i++ {
		in := testSource()
		in.URL = fmt.Sprintf("https://example.invalid/expiry/%d", i)
		if _, err := s.Save(ctx, "", 0, in); err != nil {
			b.Fatal(err)
		}
	}
	now := time.Now()
	// 1,800 identities with two owners each, using the application's real indexes and triggers.
	_, err = s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM n WHERE i<1799)
	INSERT INTO artifacts(id,hash,kind,size,created,expires) SELECT printf('item-%04d',i),printf('hash-%04d',i),'vless',1,1,? FROM n`, now.Add(time.Hour).UnixMilli())
	if err != nil {
		b.Fatal(err)
	}
	_, err = s.db.Exec(`WITH ranked AS (SELECT id,row_number() OVER (ORDER BY id)-1 AS rank FROM sources)
	INSERT INTO memberships SELECT s.id,a.id,1,a.hash,a.kind,a.size FROM artifacts a JOIN ranked s
	ON CAST(substr(a.id,6) AS INTEGER)%30 IN (s.rank,(s.rank+15)%30)`)
	if err != nil {
		b.Fatal(err)
	}
	for _, expired := range []int{0, 5} {
		b.Run(fmt.Sprintf("expired_%d", expired), func(b *testing.B) {
			tx, err := s.db.BeginTx(ctx, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer tx.Rollback()
			if _, err = tx.Exec("UPDATE artifacts SET expires=? WHERE id IN (SELECT id FROM artifacts ORDER BY id LIMIT ?)", now.UnixMilli(), expired); err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := queueExpiredSources(ctx, tx, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
