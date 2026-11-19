package panel

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/blob"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/collect"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/transient"
)

func TestReopenSanitizesExistingResponseArchives(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	a, b := sourceURI(161), sourceURI(162)
	mixed, _ := newExportSource(t, s, "mixed-response", a, b)
	pure, _ := newExportSource(t, s, "pure-response", sourceURI(163))
	clean, _ := newExportSource(t, s, "clean-response", sourceURI(164))
	stamp := time.Now().UnixMilli()
	storeResponse := func(id, raw string) blob.Ref {
		t.Helper()
		ref, err := s.vault.Put(ctx, strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer s.vault.Release(ref.Hash)
		if _, err = s.db.Exec("UPDATE responses SET hash=?,size=?,created=?,expires=? WHERE source_id=?", ref.Hash, ref.Size, stamp, stamp+3600000, id); err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec("UPDATE sources SET etag='tag',modified='date' WHERE id=?", id); err != nil {
			t.Fatal(err)
		}
		return ref
	}
	disabled := "custom://" + base64.RawURLEncoding.EncodeToString([]byte(`{"outbounds":[{"protocol":"hysteria2"}]}`))
	mixedRef := storeResponse(mixed, base64.StdEncoding.EncodeToString([]byte(a+"\n"+disabled+"\n"+b)))
	pureRef := storeResponse(pure, disabled)
	cleanRef := storeResponse(clean, base64.StdEncoding.EncodeToString([]byte(sourceURI(164))))
	key, path := s.key, filepath.Join(filepath.Dir(s.vault.Directory()), "panel.db")
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	active, err := s.Response(ctx, mixed)
	if err != nil || active.Hash == mixedRef.Hash {
		t.Fatal("mixed response still references the original", err)
	}
	r, err := s.vault.Open(active.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	f, p, err := transient.NewFile()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = io.Copy(f, r); err != nil {
		t.Fatal(err)
	}
	var records []string
	err = collect.NewRegistry().Extract(ctx, p, func(_ context.Context, item io.Reader, kind string) error {
		raw, e := io.ReadAll(item)
		if kind != "vless" {
			t.Errorf("unexpected restored record kind %s", kind)
		}
		records = append(records, strings.TrimSpace(string(raw)))
		return e
	})
	if err != nil || len(records) != 2 || records[0] != a || records[1] != b {
		t.Fatal("allowed records were not preserved for undo", len(records), err)
	}
	var etag, modified string
	var created, expires int64
	if err := s.db.QueryRow("SELECT etag,modified,r.created,r.expires FROM sources s JOIN responses r ON r.source_id=s.id WHERE s.id=?", mixed).Scan(&etag, &modified, &created, &expires); err != nil || etag != "tag" || modified != "date" || created != stamp || expires != stamp+3600000 {
		t.Fatal("mixed response lost its cache metadata", err)
	}
	if _, err := s.Response(ctx, pure); !errors.Is(err, ErrNotFound) {
		t.Fatal("pure prohibited response available", err)
	}
	source, err := s.Get(ctx, pure)
	if err != nil || source.ConfigCount != 1 {
		t.Fatal("earlier healthy member lost on cache cleanup", err)
	}
	if err := s.db.QueryRow("SELECT etag,modified FROM sources WHERE id=?", pure).Scan(&etag, &modified); err != nil || etag != "" || modified != "" {
		t.Fatal("pure response retained validators", err)
	}
	untouched, err := s.Response(ctx, clean)
	if err != nil || untouched != cleanRef {
		t.Fatal("allowed archive lost its original encoding", err)
	}
	for _, ref := range []blob.Ref{mixedRef, pureRef} {
		if used, err := s.Referenced(ctx, ref.Hash); err != nil || used {
			t.Fatal("old prohibited archive held for storage", err)
		}
	}
	if err := s.reconcileProtocolResponses(); err != nil {
		t.Fatal("second reconciliation failed", err)
	}
	again, err := s.Response(ctx, mixed)
	if err != nil || again != active {
		t.Fatal("archive normalization is not idempotent", err)
	}
}

func TestDisabledOnlyFetchDiscardsCachedResponse(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "discard-response", sourceURI(181))
	job := claimOne(t, s, id)
	result := collect.Result{State: "empty", ContentState: "empty", HTTPStatus: 200, ETag: "rejected", DiscardResponse: true}
	if err := s.Complete(ctx, job, result, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Response(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("previous original served for rejected response", err)
	}
}

func TestResponseSanitizerPreservesArchiveOnSpoolError(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	id, _ := newExportSource(t, s, "unavailable-spool", sourceURI(182))
	before, err := s.Response(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "absent"))
	if err := s.reconcileProtocolResponses(); err == nil {
		t.Fatal("expected unavailable spool")
	}
	after, err := s.Response(ctx, id)
	if err != nil || after != before {
		t.Fatal("recovery cleared a healthy archive", err)
	}
}
