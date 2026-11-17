package panel

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"
)

func classifyFixture(t *testing.T, s *Store) {
	t.Helper()
	entries, e := s.Conversions(context.Background(), 0, true)
	if e != nil {
		t.Fatal(e)
	}
	for i, c := range entries {
		dc := "amazon"
		if i == len(entries)-1 {
			dc = "hetzner"
		}
		if e = s.saveNetwork(context.Background(), c.Hash, networkclass.Result{Datacenter: dc, CDN: "none", Reason: "fixture", Checked: time.Now().UnixMilli(), Expires: time.Now().Add(time.Hour).UnixMilli()}); e != nil {
			t.Fatal(e)
		}
	}
}
func TestNetworkExportsIsolationRoundsAndRevocation(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "network", sourceURI(10), sourceURI(11), sourceURI(12))
	classifyFixture(t, s)
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	h := app.Handler()
	aURL := app.networkURL("datacenter", "amazon", "next.json")
	bURL := app.networkURL("datacenter", "hetzner", "next.json")
	noneURL := app.networkURL("cdn", "none", "next.json")
	for _, u := range []string{aURL, bURL, noneURL} {
		if r := exportRequest(t, h, "HEAD", u); r.Code != 200 {
			t.Fatal(r.Code)
		}
	}
	var count int
	s.db.QueryRow("SELECT count(*) FROM network_rotation_state").Scan(&count)
	if count != 0 {
		t.Fatal("HEAD consumed round")
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		r := exportRequest(t, h, "GET", aURL)
		hash := r.Header().Get("X-Content-SHA256")
		if r.Code != 200 || seen[hash] {
			t.Fatal(r.Code, hash)
		}
		seen[hash] = true
	}
	b := exportRequest(t, h, "GET", bURL)
	if b.Code != 200 || seen[b.Header().Get("X-Content-SHA256")] {
		t.Fatal("cross provider", b.Code)
	}
	if r := exportRequest(t, h, "GET", noneURL); r.Code != 200 || r.Header().Get("X-Export-Cycle") != "1" {
		t.Fatal("coupled axes")
	}
	var global int64
	s.db.QueryRow("SELECT cycle FROM export_rotation_state WHERE scope='' ").Scan(&global)
	if global != 0 {
		t.Fatal("global rotation changed")
	}
	wrong := app.origin + "/subscription/network/datacenter/hetzner/" + s.digest("network-export-v1", "datacenter\x00amazon\x00next.json") + "/next.json"
	if exportRequest(t, h, "GET", wrong).Code != 404 {
		t.Fatal("cross-group token accepted")
	}
	item, e := s.prepareNetwork(ctx, "datacenter", "amazon")
	if e != nil || item == nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec("UPDATE network_classifications SET datacenter='hetzner' WHERE raw_hash=?", item.Conversion.Hash); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.claimNetwork(ctx, "datacenter", "amazon", item); e != nil || ok {
		t.Fatal("reclassification race", ok, e)
	}
	item, e = s.prepareNetwork(ctx, "datacenter", "hetzner")
	if e != nil || item == nil {
		t.Fatal(e)
	}
	if _, e = s.ManageConfigs(ctx, ConfigBatch{Action: "disable", IDs: []string{item.Conversion.ID}}); e != nil {
		t.Fatal(e)
	}
	if ok, e := s.claimNetwork(ctx, "datacenter", "hetzner", item); e != nil || ok {
		t.Fatal("disabled export", ok, e)
	}
	if _, e = s.db.Exec("UPDATE network_classifications SET expires=0"); e != nil {
		t.Fatal(e)
	}
	if exportRequest(t, h, "GET", aURL).Code != 204 {
		t.Fatal("stale group exported")
	}
	r := exportRequest(t, h, "GET", app.networkURL("datacenter", "unknown", "raw.txt"))
	if r.Code != 200 || r.Header().Get("X-Config-Count") != "2" {
		t.Fatal("unknown raw", r.Code, r.Header())
	}
}
func TestNetworkConcurrentRoundAndRawBytes(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "network", sourceURI(21), sourceURI(22), sourceURI(23))
	classifyFixture(t, s)
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	h := app.Handler()
	ctx, done, e := s.readSnapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	entries, e := networkEntries(ctx, s.read(ctx), "datacenter", "amazon")
	done()
	if e != nil {
		t.Fatal(e)
	}
	want := []byte{}
	for _, n := range entries {
		r, _ := s.vault.Open(n.Hash)
		var b bytes.Buffer
		b.ReadFrom(r)
		r.Close()
		want = append(want, b.Bytes()...)
		want = append(want, '\n')
	}
	r := exportRequest(t, h, "GET", app.networkURL("datacenter", "amazon", "raw.txt"))
	if r.Code != 200 || !bytes.Equal(want, r.Body.Bytes()) {
		t.Fatal("raw changed", r.Code)
	}
	var wg sync.WaitGroup
	hashes := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("GET", app.networkURL("datacenter", "amazon", "next.json"), nil))
			if rr.Code != 200 {
				hashes <- ""
				return
			}
			hashes <- rr.Header().Get("X-Content-SHA256")
		}()
	}
	wg.Wait()
	close(hashes)
	seen := map[string]bool{}
	for hash := range hashes {
		if hash == "" || seen[hash] {
			t.Fatal("duplicate concurrent claim", hash)
		}
		seen[hash] = true
	}
	var summary struct {
		Datacenters []networkGroup `json:"datacenters"`
		CDNs        []networkGroup `json:"cdns"`
		Total       int            `json:"total"`
	}
	r = exportRequest(t, h, "GET", app.origin+"/api/datacenter")
	if json.Unmarshal(r.Body.Bytes(), &summary) != nil || len(summary.Datacenters) != 11 || len(summary.CDNs) != 7 || summary.Total != 3 {
		t.Fatal(r.Body.String())
	}
}
func TestNetworkMigrationPreservesAllExistingData(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "migration", sourceURI(30))
	if _, e := s.db.Exec(`DROP TABLE network_rotation_queue;DROP TABLE network_rotation_state;DROP TABLE network_cache;DROP TABLE network_classifications;PRAGMA user_version=41`); e != nil {
		t.Fatal(e)
	}
	before := retainedSnapshot(t, s)
	for i := 0; i < 2; i++ {
		if e := s.migrateV42(); e != nil {
			t.Fatal(e)
		}
	}
	after := retainedSnapshot(t, s)
	for k, v := range before {
		if !reflect.DeepEqual(v, after[k]) {
			t.Fatal("changed existing table", k)
		}
	}
}

func TestNetworkRawAdmissionAllowsArrivalsButRejectsRevokedMembers(t *testing.T) {
	a := networkEntry{Conversion: Conversion{ID: "a", Hash: "raw-a"}}
	b := networkEntry{Conversion: Conversion{ID: "b", Hash: "raw-b"}}
	if !networkSnapshotCurrent([]networkEntry{a}, []networkEntry{a, b}) {
		t.Fatal("new arrival invalidated captured group")
	}
	if networkSnapshotCurrent([]networkEntry{a, b}, []networkEntry{b}) {
		t.Fatal("revoked member remained exportable")
	}
	changed := a
	changed.Hash = "replacement"
	if networkSnapshotCurrent([]networkEntry{a}, []networkEntry{changed}) {
		t.Fatal("raw replacement was not revalidated")
	}
}
