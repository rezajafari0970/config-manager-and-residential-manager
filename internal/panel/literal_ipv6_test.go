package panel

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLiteralIPv6ExportsIgnoreDNSMetadataAndReuseProof(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	v6a := strings.Replace(sourceURI(210), "192.0.2.210", "[2001:db8::10]", 1)
	v6b := strings.Replace(sourceURI(211), "192.0.2.211", "[2001:db8::11]", 1)
	domain := strings.Replace(sourceURI(213), "192.0.2.213", "ipv6.google.com", 1)
	newExportSource(t, s, "literal-ipv6", v6a, v6b, sourceURI(212), domain)
	prepareAll(t, s)
	classifyFixture(t, s)
	// Deliberately misleading retired DNS evidence must never add a domain.
	if _, err := s.db.Exec(`UPDATE network_classifications SET evidence='{"version":1,"addresses":[],"ip_family":{"id":"ipv6","reason":"dns_snapshot","expires":9999999999999}}'`); err != nil {
		t.Fatal(err)
	}
	before := retainedSnapshot(t, s)
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	h := app.Handler()
	url := func(file string) string { return app.networkURL("address", "ipv6", file) }
	for file, want := range map[string]string{"raw.txt": "2", "configs.json": "2", "received.txt": "2", "native.jsonl": "0"} {
		r := exportRequest(t, h, "GET", url(file))
		if r.Code != 200 || r.Header().Get("X-Config-Count") != want {
			t.Fatal(file, r.Code, r.Header())
		}
		if file == "raw.txt" && (!strings.Contains(r.Body.String(), v6a) || !strings.Contains(r.Body.String(), v6b) || strings.Contains(r.Body.String(), domain)) {
			t.Fatal("IPv6 raw membership mismatch")
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		if exportRequest(t, h, "HEAD", url("next.json")).Code != 200 {
			t.Fatal("HEAD failed")
		}
		r := exportRequest(t, h, "GET", url("next.json"))
		hash := r.Header().Get("X-Content-SHA256")
		if r.Code != 200 || seen[hash] || !json.Valid(r.Body.Bytes()) {
			t.Fatal("rotation failed", r.Code)
		}
		seen[hash] = true
	}
	for _, g := range []string{"ipv6", "ipv4", "dual", "unknown"} {
		if exportRequest(t, h, "GET", app.networkURL("ip-family", g, "raw.txt")).Code != 404 {
			t.Fatal("retired route still works", g)
		}
	}
	var summary map[string]json.RawMessage
	r := exportRequest(t, h, "GET", app.origin+"/api/datacenter")
	if json.Unmarshal(r.Body.Bytes(), &summary) != nil {
		t.Fatal("invalid summary")
	}
	if _, ok := summary["ip_families"]; ok {
		t.Fatal("retired groups present")
	}
	var group networkGroup
	if json.Unmarshal(summary["ipv6"], &group) != nil || group.Inventory != 2 || group.Raw != 2 || group.Ready != 2 {
		t.Fatal("literal counters", group)
	}
	after := retainedSnapshot(t, s)
	for _, name := range []string{"conversion_jobs", "conversion_results", "conversion_evidence", "conversion_schedule", "egress_jobs"} {
		if !reflect.DeepEqual(before[name], after[name]) {
			t.Fatal("read changed probe state", name)
		}
	}
	if _, err := s.db.Exec("DELETE FROM network_classifications"); err != nil {
		t.Fatal(err)
	}
	if r = exportRequest(t, h, "GET", url("raw.txt")); r.Header().Get("X-Config-Count") != "2" {
		t.Fatal("literal depended on provider data")
	}
	rows, err := s.networkEntries(ctx, s.reader(), "address", "ipv6")
	if err != nil || len(rows) != 2 {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE conversion_results SET valid_until=0 WHERE hash=?", rows[0].Hash); err != nil {
		t.Fatal(err)
	}
	if r = exportRequest(t, h, "GET", url("raw.txt")); r.Header().Get("X-Config-Count") != "1" {
		t.Fatal("health revocation ignored")
	}
}

func TestLiteralIPv6RetirementPreservesUnrelatedData(t *testing.T) {
	s := testStore(t)
	_, err := s.db.Exec(`INSERT INTO network_classifications VALUES('fixture','amazon','none','verified','{"version":1,"addresses":[{"ip":"192.0.2.1","asns":[16509]}],"ip_family":{"id":"ipv4"}}',1,2,3);
INSERT INTO network_rotation_state(scope) VALUES('ip-family/ipv6'),('datacenter/amazon');
INSERT INTO network_rotation_queue(scope,position,candidate_hash) VALUES('ip-family/ipv6',1,'retired'),('datacenter/amazon',1,'keep');
INSERT INTO prepared_rotation(scope,cursor) VALUES('/xray/true/ip-family/ipv6','retired'),('/xray/true/datacenter/amazon','keep');`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = s.removeRetiredIPFamilies(); err != nil {
			t.Fatal(err)
		}
	}
	var dc, cdn, reason, evidence string
	var checked, expires, next int
	if err = s.db.QueryRow("SELECT datacenter,cdn,reason,evidence,checked,expires,next_run FROM network_classifications WHERE raw_hash='fixture'").Scan(&dc, &cdn, &reason, &evidence, &checked, &expires, &next); err != nil {
		t.Fatal(err)
	}
	if dc != "amazon" || cdn != "none" || reason != "verified" || checked != 1 || expires != 2 || next != 3 || evidence != `[{"ip":"192.0.2.1","asns":[16509]}]` {
		t.Fatal("provider record changed", evidence)
	}
	for _, table := range []string{"network_rotation_state", "network_rotation_queue", "prepared_rotation"} {
		var count int
		if err = s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatal(table, count, err)
		}
	}
}
