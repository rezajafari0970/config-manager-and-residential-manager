package panel

import (
	"context"
	"encoding/json"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/networkclass"
)

type familyResolver struct{}

func (familyResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("3.1.2.3"), netip.MustParseAddr("2606:4700::1")}, nil
}

func TestIPFamilyExportsReuseProofAndKeepGroupsIsolated(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	v6a := strings.Replace(sourceURI(210), "192.0.2.210", "[2001:db8::10]", 1)
	v6b := strings.Replace(sourceURI(211), "192.0.2.211", "[2001:db8::11]", 1)
	dual := strings.Replace(sourceURI(213), "192.0.2.213", "dual.test", 1)
	newExportSource(t, s, "family", v6a, v6b, sourceURI(212), dual)
	prepareAll(t, s)
	classifier := networkclass.New(nil)
	classifier.Resolver = familyResolver{}
	rows, err := s.Conversions(ctx, 0, true)
	if err != nil {
		t.Fatal(err)
	}
	var v6Hashes []string
	var dualHash string
	for _, c := range rows {
		body, e := s.vault.Open(c.Hash)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := io.ReadAll(body)
		body.Close()
		if e != nil {
			t.Fatal(e)
		}
		family := classifier.ClassifyFamily(ctx, raw)
		if family.ID == "ipv6" {
			v6Hashes = append(v6Hashes, c.Hash)
		} else if family.ID == "dual" {
			dualHash = c.Hash
		}
		err = s.saveNetwork(ctx, c.Hash, networkclass.Result{Datacenter: "amazon", CDN: "none", Family: family, Checked: time.Now().UnixMilli(), Expires: time.Now().Add(time.Hour).UnixMilli()})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(v6Hashes) != 2 || dualHash == "" {
		t.Fatal("fixture family mismatch", v6Hashes, dualHash)
	}
	before := retainedSnapshot(t, s)
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	url := func(group, file string) string { return app.networkURL("ip-family", group, file) }
	h := app.Handler()
	for file, want := range map[string]string{"raw.txt": "2", "configs.json": "2", "received.txt": "2", "native.jsonl": "0"} {
		r := exportRequest(t, h, "GET", url("ipv6", file))
		if r.Code != 200 || r.Header().Get("X-Config-Count") != want {
			t.Fatal(file, r.Code, r.Header())
		}
		if file == "raw.txt" && (!strings.Contains(r.Body.String(), v6a) || !strings.Contains(r.Body.String(), v6b) || strings.Contains(r.Body.String(), "192.0.2.1") || strings.Contains(r.Body.String(), "dual.test")) {
			t.Fatal("mixed address families in IPv6 raw")
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		if exportRequest(t, h, "HEAD", url("ipv6", "next.json")).Code != 200 {
			t.Fatal("invalid HEAD")
		}
		r := exportRequest(t, h, "GET", url("ipv6", "next.json"))
		key := r.Header().Get("X-Content-SHA256")
		if r.Code != 200 || seen[key] || !json.Valid(r.Body.Bytes()) {
			t.Fatal("rotation duplicated or failed", r.Code)
		}
		seen[key] = true
	}
	if r := exportRequest(t, h, "GET", app.networkURL("datacenter", "amazon", "next.json")); r.Code != 200 || r.Header().Get("X-Export-Cycle") != "1" {
		t.Fatal("family rotation changed datacenter rotation")
	}
	wrong := strings.Replace(url("ipv6", "raw.txt"), "/ipv6/", "/ipv4/", 1)
	if exportRequest(t, h, "GET", wrong).Code != 404 {
		t.Fatal("cross-family token accepted")
	}
	var summary struct {
		Families []networkGroup `json:"ip_families"`
	}
	r := exportRequest(t, h, "GET", app.origin+"/api/datacenter")
	if json.Unmarshal(r.Body.Bytes(), &summary) != nil || len(summary.Families) != 4 {
		t.Fatal(r.Body.String())
	}
	for _, g := range summary.Families {
		want := map[string]int{"ipv6": 2, "ipv4": 1, "dual": 1, "unknown": 0}[g.ID]
		if g.Inventory != want || g.Raw != want || g.Ready != want || g.Coverage.Tested != want {
			t.Fatal("family counters disagree", g)
		}
	}
	after := retainedSnapshot(t, s)
	for _, name := range []string{"conversion_jobs", "conversion_results", "conversion_evidence", "conversion_schedule", "egress_jobs"} {
		if !reflect.DeepEqual(before[name], after[name]) {
			t.Fatal("group export changed test state", name)
		}
	}
	if _, err = s.db.Exec("UPDATE network_classifications SET expires=0"); err != nil {
		t.Fatal(err)
	}
	if r = exportRequest(t, h, "GET", url("ipv6", "raw.txt")); r.Code != 200 || r.Header().Get("X-Config-Count") != "2" {
		t.Fatal("literal IPv6 depended on ASN freshness")
	}
	if _, err = s.db.Exec("UPDATE network_classifications SET evidence=json_set(evidence,'$.ip_family.expires',1) WHERE raw_hash=?", dualHash); err != nil {
		t.Fatal(err)
	}
	if exportRequest(t, h, "GET", url("dual", "next.json")).Code != 204 {
		t.Fatal("expired DNS published in dual group")
	}
	if _, err = s.db.Exec("UPDATE conversion_results SET valid_until=0 WHERE hash=?", v6Hashes[0]); err != nil {
		t.Fatal(err)
	}
	if r = exportRequest(t, h, "GET", url("ipv6", "raw.txt")); r.Header().Get("X-Config-Count") != "1" {
		t.Fatal("expired health published")
	}
	if r = exportRequest(t, h, "GET", url("ipv6", "received.txt")); r.Header().Get("X-Config-Count") != "2" {
		t.Fatal("diagnostic inventory omitted unverified input")
	}
}
