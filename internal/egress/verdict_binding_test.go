package egress

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestIndependentIRDisagreementFromCountryDriver(t *testing.T) {
	for _, mode := range []string{"independent", "earlier", "same_lineage", "stale", "non_ir", "replay", "out_of_wave"} {
		t.Run(mode, func(t *testing.T) {
			r, p, now := singleProfileFixture()
			var extra Sample
			for i := range r.Samples {
				s := &r.Samples[i]
				if s.ActualAds {
					profileGeo(s, "TW", now)
					if !strings.HasSuffix(s.Domain, "doubleclick.net") {
						extra = *s
					}
				}
			}
			// This is the exact status emitted by the worker with two independent
			// lookups and no majority. The qualifying profile has full TW coverage.
			profileGeo(&extra, "IE", now)
			extra.Geo.Status, extra.Geo.Country = "country_provider_disagreement", ""
			extra.Geo.Providers[0].Country = "IR"
			if mode != "replay" {
				extra.Nonce = Hash([]byte("additional Ads exchange"))[:32]
				extra.Connection = extra.Nonce
			}
			switch mode {
			case "same_lineage":
				extra.Geo.Providers[0].Lineage = extra.Geo.Providers[1].Lineage
			case "stale":
				extra.Geo.Providers[0].ReleasedAt = now - CountryDataAge
			case "non_ir":
				extra.Geo.Providers[0].Country = "FR"
			case "out_of_wave":
				extra.Wave = r.Waves + 1
			}
			if mode == "earlier" {
				earlier := r
				earlier.Core, earlier.CoreSHA = "xray-26.10.31", Cores["xray-26.10.31"]
				earlier.Samples, earlier.Waves = []Sample{extra}, 0
				r.Evidence = []Report{earlier}
			} else {
				r.Samples = append(r.Samples, extra)
			}
			d := Evaluate(r, p, r.Hash, now)
			g := Countries(r, d, now)
			wantConflict := mode == "independent" || mode == "earlier"
			if d.CountryConflict != wantConflict || (g.Status == "country_iran_conflict") != wantConflict || g.Complete == wantConflict || Iran(r, p, r.Hash, now) != nil {
				t.Fatalf("route=%s country=%s complete=%t conflict=%t", d.Reason, g.Status, g.Complete, d.CountryConflict)
			}
		})
	}
}

func TestIRObservationRequiresUniqueInRoundWave(t *testing.T) {
	for _, mode := range []string{"valid_earlier", "earlier_replay", "selected_replay", "negative_wave", "outside_wave"} {
		t.Run(mode, func(t *testing.T) {
			r, p, now := fixture()
			s := r.Samples[0]
			profileGeo(&s, "IR", now)
			switch mode {
			case "valid_earlier", "earlier_replay":
				part := r
				if mode == "valid_earlier" {
					s.Nonce = Hash([]byte("earlier"))[:32]
					s.Connection = s.Nonce
				}
				part.Waves, part.Samples = 0, []Sample{s}
				r.Evidence = []Report{part}
			case "selected_replay":
				r.Samples = append(r.Samples, s)
			case "negative_wave", "outside_wave":
				if mode == "negative_wave" {
					s.Wave = -1
				} else {
					s.Wave = r.Waves + 1
				}
				r.Samples[0] = s
			}
			if got := Iran(r, p, r.Hash, now) != nil; got != (mode == "valid_earlier") {
				t.Fatalf("confirmed Iran = %t", got)
			}
		})
	}
}

func TestNativeReceiptRequiresExactRuntimeAndNativeDriver(t *testing.T) {
	r, _, now := networkFixture()
	raw := []byte(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":10808}],"outbounds":[{"tag":"upstream","type":"trojan","server":"192.0.2.1","server_port":443,"password":"synthetic","tls":{"enabled":true,"server_name":"example.com"}}],"route":{"final":"upstream"}}`)
	p := Prepare(raw)
	if !p.Complete || p.Driver != "sing-box" {
		t.Fatal("native fixture")
	}
	for i, v := range p.Variants {
		r.Checks[i] = Check{Name: v.Name, Hash: v.Hash, RuntimeHash: v.Hash, Core: true}
	}
	r.Core, r.CoreSHA = NativeID, NativeSHA
	if d := Evaluate(r, p, r.Hash, now); !d.Eligible || !d.Network.Eligible {
		t.Fatalf("%s %s", d.Reason, d.Network.Reason)
	}
	// The same native object may arrive in a quoted or base64 envelope.
	framed := " \n" + string(raw) + "\t"
	quoted, _ := json.Marshal(framed)
	for _, envelope := range [][]byte{quoted, []byte("custom://" + base64.StdEncoding.EncodeToString(quoted))} {
		if actual := Prepare(envelope); actual.Driver != "sing-box" || len(actual.Variants) != 2 || string(actual.Variants[0].Config) != framed {
			t.Fatal("native raw envelope changed before launch")
		}
	}
	// A valid earlier full native attempt still contributes adverse evidence
	// when the selected attempt cannot bind its raw runtime.
	previous := cloneReceipt(r)
	for i := range previous.Samples {
		s := &previous.Samples[i]
		s.Nonce = Hash([]byte("earlier native" + s.Nonce))[:32]
		s.Connection = s.Nonce
		if s.ActualAds && s.Variant == "raw" {
			setHosting(s, 4)
			profileGeo(s, "IR", now)
		}
	}
	selected := cloneReceipt(r)
	selected.Checks[0].RuntimeHash = Hash([]byte("rewritten selected runtime"))
	selected.Evidence = []Report{previous}
	if d := Evaluate(selected, p, r.Hash, now); d.Eligible || !d.Network.BlocksResidential() || Iran(selected, p, r.Hash, now) == nil {
		t.Fatalf("earlier native attempt: route=%s network=%s", d.Reason, d.Network.Reason)
	}

	for _, mode := range []string{"wrong_runtime", "wrong_driver"} {
		t.Run(mode, func(t *testing.T) {
			bad := cloneReceipt(r)
			if mode == "wrong_runtime" {
				bad.Checks[0].RuntimeHash = Hash([]byte("other runtime"))
			} else {
				bad.Core, bad.CoreSHA = "xray-26.11.9", Cores["xray-26.11.9"]
			}
			for i := range bad.Samples {
				s := &bad.Samples[i]
				if s.ActualAds && s.Variant == "raw" {
					setHosting(s, 4)
					profileGeo(s, "IR", now)
				}
			}
			d := Evaluate(bad, p, r.Hash, now)
			if d.Eligible || d.Network.Eligible || d.Network.BlocksResidential() || Iran(bad, p, r.Hash, now) != nil {
				t.Fatalf("route=%s network=%s", d.Reason, d.Network.Reason)
			}
		})
	}
}

func TestWrappedJSONRetainsTheActualRawVariant(t *testing.T) {
	cfg := " \t" + `{"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"port":443,"address":"[2001:db8::1]","users":[{"id":"00000000-0000-4000-8000-000000000001","encryption":"none"}]}]},"streamSettings":{"security":"tls","tlsSettings":{"serverName":"example.com"}}}]}` + "\n"
	for _, scheme := range []string{"json", "custom", "httpcustom", "napsternet"} {
		p := Prepare([]byte(scheme + "://" + base64.RawURLEncoding.EncodeToString([]byte(cfg))))
		if !p.Complete || len(p.Variants) != 2 || string(p.Variants[0].Config) != cfg || p.Variants[0].Hash != Hash([]byte(cfg)) {
			t.Errorf("%s prepared=%s complete=%t", scheme, p.Code, p.Complete)
		}
	}
}

func TestUnpairedAdsEchoCannotReportSeparateRoute(t *testing.T) {
	r, p, now := fixture()
	for i := range r.Samples {
		if !r.Samples[i].ActualAds {
			r.Samples[i].Echo = false
		}
	}
	if d := Evaluate(r, p, r.Hash, now); d.Eligible || d.Route != "UNKNOWN" || len(d.Sources) == 0 {
		t.Fatal(d.Route, d.Eligible)
	}
}
