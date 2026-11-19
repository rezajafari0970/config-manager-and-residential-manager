package panel

import (
	"context"
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"
	"net/http/httptest"
	"testing"
)

func TestEgressBriefPollingAndTargetedEvidence(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "brief", sourceURI(246), sourceURI(247))
	hash := ""
	for range 2 {
		j, _ := s.ClaimEgress(ctx)
		hash = j.Hash
		if e := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: syntheticEgress(*j)}); e != nil {
			t.Fatal(e)
		}
	}
	app, _ := NewServer(s, "http://127.0.0.1:18191")
	m := egressModule{app}
	request := func(path string) (int, int, map[string]any) {
		rr := httptest.NewRecorder()
		m.state(rr, httptest.NewRequest("GET", path, nil))
		var body map[string]any
		json.Unmarshal(rr.Body.Bytes(), &body)
		return rr.Code, rr.Body.Len(), body
	}
	code, full, _ := request("/api/egress")
	if code != 200 {
		t.Fatal(code)
	}
	code, brief, body := request("/api/egress?brief=1")
	if code != 200 || brief >= full/2 {
		t.Fatal(code, brief, full)
	}
	for _, v := range body["entries"].([]any) {
		report := v.(map[string]any)["report"].(map[string]any)
		if _, ok := report["samples"]; ok {
			t.Fatal("poll leaked heavy evidence")
		}
	}
	code, _, body = request("/api/egress?view=diagnostics&hash=" + hash)
	if code != 200 || len(body["entries"].([]any)) != 1 {
		t.Fatal(code, body)
	}
	entry := body["entries"].([]any)[0].(map[string]any)
	if entry["hash"] != hash || len(entry["report"].(map[string]any)["samples"].([]any)) == 0 {
		t.Fatal("targeted proof missing")
	}
	code, _, _ = request("/api/egress?hash=invalid")
	if code != 422 {
		t.Fatal(code)
	}
	for _, file := range []string{"configs.json", "configs.jsonl", "next.json", "raw.txt"} {
		rr := exportRequest(t, app.Handler(), "HEAD", app.origin+"/egress-subscription/"+s.digest("egress-export-v2", "all")+"/"+file)
		if rr.Code != 200 || rr.Header().Get("X-Country-Policy") != "any-observed-country-selected; 24h; GeoIP-estimate" {
			t.Fatal(file, rr.Code, rr.Header())
		}
	}
}

func TestResidentialPageSeparatesHostedAndUnattributedSplit(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	newExportSource(t, s, "exit-network-summary", sourceURI(241), sourceURI(242), sourceURI(243))
	for _, kind := range []string{"hosting", "unknown", "access"} {
		j, err := s.ClaimEgressLane(ctx, "initial")
		if err != nil || j == nil {
			t.Fatal(kind, err)
		}
		r := syntheticEgress(*j)
		for i := range r.Samples {
			sample := &r.Samples[i]
			if !sample.ActualAds {
				continue
			}
			switch kind {
			case "hosting":
				sample.Network.Kind = "hosting"
				sample.Network.Provider = "vultr"
				sample.Network.ASN = 20473
			case "unknown":
				sample.Network = nil
			}
		}
		if err := s.CompleteEgress(ctx, egress.Completion{Job: *j, Report: r}); err != nil {
			t.Fatal(err)
		}
	}
	app, err := NewServer(s, "http://127.0.0.1:18191")
	if err != nil {
		t.Fatal(err)
	}
	type entry struct {
		Decision struct {
			State     string
			Eligible  bool
			Published bool
			Reason    string
			Until     int64
			Qualified []string `json:"qualified_domains"`
		}
		Route struct {
			State     string
			Qualified bool  `json:"qualified_at_test"`
			Until     int64 `json:"valid_until"`
		} `json:"route_assessment"`
		ValidUntil  int64 `json:"valid_until"`
		State       string
		NetworkHeld bool `json:"network_held"`
		Published   bool
		Network     egress.NetworkVerdict
		LastAdverse egress.NetworkVerdict `json:"last_adverse"`
	}
	type response struct {
		Eligible   int
		Entries    []entry
		Counts     map[string]int
		Accounting struct{ Publication map[string]int }
	}
	var state response
	read := func(path string) {
		state = response{}
		t.Helper()
		rr := httptest.NewRecorder()
		egressModule{app}.state(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &state) != nil {
			t.Fatal(rr.Code, rr.Body.String())
		}
	}
	read("/api/egress?brief=1&view=diagnostics")
	p := state.Accounting.Publication
	if len(state.Entries) != 3 || state.Eligible != 2 || state.Counts["RESIDENTIAL"] != 2 || state.Counts["ADS_SPLIT"] != 1 ||
		p["route_verified"] != 3 || p["hosting"] != 1 || p["eligible_network_unattributed"] != 1 || p["network_unverified"] != 0 ||
		p["eligible"] != 2 || p["published"] != 2 || p["country_filtered"] != 0 {
		t.Fatal("network and route accounting confused", state)
	}
	byNetwork := map[string]entry{}
	for _, e := range state.Entries {
		byNetwork[e.Network.State] = e
	}
	h := byNetwork["hosting"]
	if !h.NetworkHeld || h.LastAdverse.Provider != "vultr" || h.LastAdverse.ASN != 20473 ||
		h.LastAdverse.Domain == "" || h.State != "ADS_SPLIT" || h.Published || !byNetwork["unknown"].Published ||
		h.Decision.State != "ADS_SPLIT" || h.Decision.Eligible || h.Decision.Reason != "ads_hosting_exit" ||
		h.Decision.Until != 0 || h.ValidUntil != 0 || len(h.Decision.Qualified) != 6 ||
		h.Route.State != "ADS_SPLIT" || !h.Route.Qualified || h.Route.Until == 0 {
		t.Fatal("missing hosting reason or false publication", byNetwork)
	}
	read("/api/egress?brief=1")
	if len(state.Entries) != 2 {
		t.Fatal("public list diverged", state.Entries)
	}
	for _, row := range state.Entries {
		if !row.Published || !row.Decision.Eligible || !row.Decision.Published || row.Decision.State != "RESIDENTIAL" ||
			row.Decision.Until != row.ValidUntil || row.ValidUntil != row.Route.Until || row.ValidUntil <= 0 || row.Decision.Reason == "ads_access_verified" {
			t.Fatal("expected the original route reason and deadline for admitted entries", row)
		}
	}
	if _, err := s.db.Exec("UPDATE egress_country_policy SET allowed='[]'"); err != nil {
		t.Fatal(err)
	}
	read("/api/egress?view=diagnostics")
	for _, row := range state.Entries {
		if row.Network.State != "hosting" && (!row.Decision.Eligible || row.Decision.Published || row.Published) {
			t.Fatal("selected country must only alter publication", row)
		}
	}
	// When every remaining qualifying route has confirmed hosting evidence,
	// the panel must explain a zero without attributing it to the country filter.
	if _, err := s.db.Exec("UPDATE egress_jobs SET paused=1 WHERE hash IN (SELECT hash FROM egress_network_results WHERE held=0)"); err != nil {
		t.Fatal(err)
	}
	read("/api/egress?brief=1")
	p = state.Accounting.Publication
	if len(state.Entries) != 0 || p["route_verified"] != 1 || p["hosting"] != 1 || p["eligible"] != 0 || p["published"] != 0 || p["country_filtered"] != 0 {
		t.Fatal("all hosted routes must be excluded with the hosting reason", p)
	}
	var base string
	if err := s.db.QueryRow("SELECT json_extract(j.decision,'$.state') FROM egress_jobs j JOIN egress_network_results n ON n.hash=j.hash WHERE n.state='hosting'").Scan(&base); err != nil || base != "RESIDENTIAL" {
		t.Fatal("presentation changed the stored route decision", base, err)
	}
}
