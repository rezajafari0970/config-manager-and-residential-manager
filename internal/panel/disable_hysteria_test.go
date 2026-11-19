package panel

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

func TestDisableHysteriaReconcilesLegacySubscriptionsAndRetainedProfiles(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, _ := newExportSource(t, s, "mixed", sourceURI(33))
	good, _ := newExportSource(t, s, "old-template", sourceURI(42))
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := s.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(expected int, query string, args ...any) {
		t.Helper()
		var n int
		if err := s.db.QueryRow(query, args...).Scan(&n); err != nil || n != expected {
			t.Fatalf("%s: %d want %d, err=%v", query, n, expected, err)
		}
	}
	storeBlob := func(raw string) string {
		t.Helper()
		ref, err := s.vault.Put(ctx, strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		s.vault.Release(ref.Hash)
		return ref.Hash
	}
	legacy := func(raw, kind string, retained bool) string {
		t.Helper()
		h := storeBlob(raw)
		stamp := time.Now().UnixMilli()
		exec("INSERT INTO artifacts(id,hash,kind,size,created,expires) VALUES(?,?,?,?,?,?)", h, h, kind, len(raw), stamp, stamp+3600000)
		exec("INSERT INTO memberships VALUES(?,?,1,?,?,?)", source, h, h, kind, len(raw))
		exec("INSERT OR IGNORE INTO conversion_jobs(hash) VALUES(?)", h)
		exec("UPDATE egress_jobs SET token='old-lease',lease_until=?,ever_accepted=1,state='RESIDENTIAL',valid_until=? WHERE hash=?", stamp+60000, stamp+60000, h)
		if retained {
			exec("DELETE FROM artifacts WHERE id=?", h)
		}
		return h
	}
	uri := legacy("hy2://password@proxy.example:443", "hy2", false)
	// Historical fingerprints can have a different byte representative in
	// another source. That membership must keep its own Residential job.
	aliasSource := testSource()
	aliasSource.URL = "https://example.org/alias"
	aliasID, err := s.Save(ctx, "", 0, aliasSource)
	if err != nil {
		t.Fatal(err)
	}
	aliasRaw := sourceURI(43)
	aliasHash := storeBlob(aliasRaw)
	exec("INSERT INTO memberships VALUES(?,?,1,?,'vless',?)", aliasID, uri, aliasHash, len(aliasRaw))
	retained := legacy(`{"outbounds":[{"type":"hysteria","server":"relay.example"}]}`, "json", true)
	// A legacy template on an otherwise healthy input must be re-prepared
	// without detaching its input from the source.
	template := storeBlob(`{"outbounds":[{"protocol":"vless","streamSettings":{"network":"hysteria"}}]}`)
	exec("UPDATE conversion_results SET candidate_hash=? WHERE hash IN(SELECT raw_hash FROM memberships WHERE source_id=?)", template, good)
	exec("INSERT INTO network_rotation_state(scope,cycle) VALUES('test-scope',1)")
	exec("INSERT INTO network_rotation_queue VALUES('test-scope',1,?)", template)
	for i := 0; i < 2; i++ {
		if err := s.reconcileDisabledProtocols(); err != nil {
			t.Fatal(err)
		}
	}
	count(1, "SELECT count(*) FROM memberships WHERE source_id=?", source)
	count(1, "SELECT stored_count FROM sources WHERE id=?", source)
	count(1, "SELECT count(*) FROM conversion_results WHERE hash IN(SELECT raw_hash FROM memberships WHERE source_id=?)", source)
	count(0, "SELECT count(*) FROM conversion_jobs WHERE hash IN(?,?)", uri, retained)
	count(0, "SELECT count(*) FROM egress_inventory WHERE hash IN(?,?)", uri, retained)
	count(2, "SELECT count(*) FROM egress_jobs WHERE hash IN(?,?) AND paused=1 AND reason='protocol_disabled' AND token=''", uri, retained)
	count(1, "SELECT count(*) FROM conversion_inputs WHERE hash IN(SELECT raw_hash FROM memberships WHERE source_id=?)", good)
	count(0, "SELECT count(*) FROM conversion_results WHERE candidate_hash=?", template)
	count(0, "SELECT count(*) FROM network_rotation_queue WHERE candidate_hash=?", template)
	count(1, "SELECT count(*) FROM egress_unique WHERE identity=? AND hash=?", uri, aliasHash)
	count(1, "SELECT count(*) FROM artifacts WHERE id=? AND hash=?", uri, aliasHash)
	count(1, "SELECT count(*) FROM egress_work WHERE hash=?", aliasHash)
	count(0, "SELECT count(*) FROM input_exclusions")
}

func TestRestoredHysteriaCandidateIsWithheldAndRetired(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	source, _ := newExportSource(t, s, "restored", sourceURI(73))
	raw := `{"outbounds":[{"type":"hysteria2","server":"relay.example"}]}`
	hash := repair.Digest([]byte(raw))
	_, err := s.db.Exec("UPDATE conversion_results SET candidate_hash=? WHERE hash IN(SELECT raw_hash FROM memberships WHERE source_id=?)", hash, source)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.reconcileDisabledProtocols(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.unknownProtocolHashes.Load(hash); !ok {
		t.Fatal("missing candidate was not scheduled for admission on restore")
	}
	ref, err := s.vault.Put(ctx, strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.vault.Release(ref.Hash)
	if body, err := s.openExportBlob(hash); body != nil || err != ErrNotFound {
		t.Fatal("restored Hysteria candidate reached export", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		var count int
		if err = s.db.QueryRow("SELECT count(*) FROM conversion_results WHERE candidate_hash=?", hash).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("obsolete candidate remained eligible for rotation")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
