package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestPreparedExportRefreshesRevokedSnapshotBeforePublishing(t *testing.T) {
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "template", true: "raw"}[raw], func(t *testing.T) { testExportRefresh(t, raw) })
	}
}

func testExportRefresh(t *testing.T, raw bool) {
	s := testStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	source, _ := newExportSource(t, s, "refresh", sourceURI(751), sourceURI(752))
	classifyFixture(t, s)
	rows, err := scopedPreparedEntries(ctx, s.reader(), source, "xray", "", "")
	if err != nil || len(rows) != 2 {
		t.Fatal(rows, err)
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE conversion_results SET valid_until=0 WHERE hash=?", rows[0].Hash); err != nil {
		t.Fatal(err)
	}
	// The WAL reader sees two healthy inputs; the serialized writer prevents
	// final admission until the revocation commits. No timing-only body hook.
	waits := s.db.Stats().WaitCount
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		request := httptest.NewRequest("GET", "/api/prepared/export?source="+source, nil).WithContext(ctx)
		if raw {
			request.SetPathValue("file", "raw.txt")
			app.networkRaw(rr, request, "cdn", "none")
		} else {
			app.preparedExport(rr, request)
		}
	}()
	for s.db.Stats().WaitCount == waits && ctx.Err() == nil {
		time.Sleep(time.Millisecond)
	}
	if ctx.Err() != nil {
		t.Fatal("export did not reach final admission")
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("snapshot refresh stalled")
	}
	if rr.Code != 200 || rr.Header().Get("X-Config-Count") != "1" {
		t.Fatal(rr.Code, rr.Header())
	}
	if raw {
		body, e := s.vault.Open(rows[1].Hash)
		if e != nil {
			t.Fatal(e)
		}
		want, e := io.ReadAll(body)
		body.Close()
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(rr.Body.Bytes(), append(want, '\n')) {
			t.Fatal("revoked raw published")
		}
		return
	}
	var profiles []json.RawMessage
	if json.Unmarshal(rr.Body.Bytes(), &profiles) != nil || len(profiles) != 1 || repair.Digest(profiles[0]) != rows[1].Candidate {
		t.Fatal("revoked or partial template published")
	}
}
