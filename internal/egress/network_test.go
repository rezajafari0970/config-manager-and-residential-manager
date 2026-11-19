package egress

import (
	"slices"
	"testing"
)

func networkFixture() (Report, Plan, int64) {
	r, p, now := fixture()
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.ActualAds {
			s.Code, s.FirstStatus = "ads_peer_reported", 200
			s.Network = &NetworkFact{Version: NetworkVersion, Kind: "access", Family: s.Family, Source: s.Source, Provider: "fixture-mobile", ASN: 64500, PrefixLen: 24, UsageSource: "operator-subscriber-pool", OriginSource: "ripe-ris", Dataset: Hash([]byte("fixture revision")), CheckedAt: now, ValidUntil: now + EvidenceTTL}
		}
	}
	return r, p, now
}

func setHosting(s *Sample, family int) {
	fact := *s.Network
	s.Network = &fact
	s.Family, fact.Family = family, family
	s.Source = Hash([]byte("observed-hosting-source"))
	fact.Source, fact.Kind, fact.Provider, fact.ASN = s.Source, "hosting", "vultr", 20473
	fact.UsageSource = "vultr-geofeed"
	if family == 6 {
		fact.PrefixLen = 48
	}
}

func TestExitNetworkSeparateFromRouteAndOrdinaryHealth(t *testing.T) {
	r, p, now := networkFixture()
	r.Samples[0].Network.ValidUntil = now + 9000
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || !d.Network.Eligible || d.Network.State != "access" || d.Network.Until != now+9000 || d.Network.DomainsObserved != len(Domains) {
		t.Fatal(d.Network)
	}
	r.Samples[0].Network = nil
	d = Evaluate(r, p, r.Hash, now)
	if !d.Eligible || d.Network.BlocksResidential() || d.Network.Eligible || d.Network.Reason != "ads_network_evidence_incomplete" || d.Network.Domain != r.Samples[0].Domain {
		t.Fatal(d.Network)
	}
	for i := range r.Samples {
		r.Samples[i].Network = nil
	}
	d = Evaluate(r, p, r.Hash, now)
	if !d.Eligible || d.Network.BlocksResidential() || d.Network.State != "unknown" || d.Network.Eligible {
		t.Fatal("legacy split-route must pass without an access claim", d.Network)
	}
}

func TestVultrWithSplitControlsAndMixedTemplateIPv6(t *testing.T) {
	r, p, now := networkFixture()
	for i := range r.Samples {
		if r.Samples[i].ActualAds {
			setHosting(&r.Samples[i], 4)
		}
	}
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || !d.Network.BlocksResidential() || d.Network.Eligible || d.Network.State != "hosting" || d.Network.Provider != "vultr" || d.Network.ASN != 20473 {
		t.Fatal(d.Network)
	}
	r, p, now = networkFixture()
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Variant == "template" && s.Domain == "securepubads.g.doubleclick.net" && s.Wave == 3 {
			setHosting(s, 6)
		}
	}
	d = Evaluate(r, p, r.Hash, now)
	want := SharedNetwork{NetworkFlow{"securepubads.g.doubleclick.net", "template", 6}, "vultr", 20473}
	if d.Network.BlocksResidential() || d.Network.Eligible || d.Network.Reason != "ads_hosting_route_unresolved" || !slices.Contains(d.Network.UnresolvedHosting, want) || len(d.Network.Families) != 2 || !d.Eligible || !slices.Equal(d.QualifiedProfiles, []string{profiles[1].ID}) {
		t.Fatal(d.Network)
	}
}

func TestNetworkEvidenceIntegrity(t *testing.T) {
	for name, mutate := range map[string]func(*Sample, int64){
		"wrong_hmac":                 func(s *Sample, now int64) { s.Network.Source = Hash([]byte("control")) },
		"family":                     func(s *Sample, now int64) { s.Network.Family = 6 },
		"prefix_length":              func(s *Sample, now int64) { s.Network.PrefixLen = 64 },
		"same_lineage":               func(s *Sample, now int64) { s.Network.OriginSource = s.Network.UsageSource },
		"expired":                    func(s *Sample, now int64) { s.Network.ValidUntil = now },
		"future":                     func(s *Sample, now int64) { s.Network.CheckedAt += 3000 },
		"no_dataset":                 func(s *Sample, now int64) { s.Network.Dataset = "" },
		"excessive_lifetime":         func(s *Sample, now int64) { s.Network.ValidUntil++ },
		"unobserved":                 func(s *Sample, now int64) { s.Code = "control_echo" },
		"unsuccessful_first_request": func(s *Sample, now int64) { s.FirstStatus = 500 },
		"uncorroborated_fact":        func(s *Sample, now int64) { s.Network.Kind = "unknown" },
		"conflicting_registration":   func(s *Sample, now int64) { s.Network.ASN = 64499 },
	} {
		t.Run(name, func(t *testing.T) {
			r, p, now := networkFixture()
			mutate(&r.Samples[0], now)
			d := Evaluate(r, p, r.Hash, now)
			if !d.Eligible || d.Network.Eligible || d.Network.State != "unknown" {
				t.Fatal(d.Network)
			}
		})
	}
}

func TestLegacyProfileRestoredWithOnlyObservedHostingVeto(t *testing.T) {
	r, p, now := networkFixture()
	// Fail the second bootstrap asset. The first profile still passes route and delivery.
	for i := range r.Delivery {
		r.Delivery[i].Assets[1].HTTPStatus = 403
	}
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || len(d.QualifiedProfiles) != 1 || !d.Network.Eligible || d.Network.BlocksResidential() {
		t.Fatal(d.Network, d.QualifiedProfiles)
	}
	for i := range r.Samples {
		r.Samples[i].Network = nil
	}
	d = Evaluate(r, p, r.Hash, now)
	if !d.Eligible || len(d.QualifiedProfiles) != 1 || d.Network.BlocksResidential() || d.Network.State != "unknown" {
		t.Fatal(d.Network, d.QualifiedProfiles)
	}
	// The failing second profile still vetoes when repeated paired Ads connections have a
	// verified separated datacenter exit. Failure to classify all other peers changes nothing.
	domain := r.Delivery[0].Assets[1].Domain
	populated, _, _ := networkFixture()
	var found bool
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Domain == domain && s.Variant == "template" && s.Wave >= 2 {
			s.Network = populated.Samples[i].Network
			s.Network.CheckedAt = now
			s.Network.ValidUntil = now + EvidenceTTL
			setHosting(s, 4)
			found = true
		}
	}
	d = Evaluate(r, p, r.Hash, now)
	if !found || !d.Eligible || len(d.QualifiedProfiles) != 1 || !d.Network.BlocksResidential() || d.Network.Domain != domain {
		t.Fatal(d.Network, d.QualifiedProfiles)
	}
	for i := range r.Delivery {
		r.Delivery[i].Assets[0].HTTPStatus = 403
	}
	d = Evaluate(r, p, r.Hash, now)
	if d.Eligible || !d.Network.BlocksResidential() {
		t.Fatal("original delivery requirement or independent DC veto lost", d.Network)
	}
}

func TestClearanceRequiresEveryPreviouslyObservedHostingFlow(t *testing.T) {
	r, p, now := networkFixture()
	first := NetworkFlow{Domains[0], "raw", 4}
	second := NetworkFlow{Domains[1], "template", 6}
	third := NetworkFlow{Domains[2], "raw", 4}
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Domain == first.Domain && s.Variant == first.Variant || s.Domain == second.Domain && s.Variant == second.Variant {
			family := 4
			if s.Domain == second.Domain {
				family = 6
			}
			setHosting(s, family)
		}
	}
	for _, sample := range r.Samples {
		if sample.Variant == second.Variant && (sample.Domain == "www.google.com" || sample.Domain == "api.ipify.org") {
			sample.Family, sample.Source = 6, Hash([]byte("fixture ordinary IPv6"))
			sample.Nonce = Hash([]byte("v6" + sample.Connection))[:32]
			sample.Connection = sample.Nonce
			r.Samples = append(r.Samples, sample)
		}
	}
	adverse := Evaluate(r, p, r.Hash, now).Network
	if !adverse.BlocksResidential() || len(adverse.HostingFlows) != 2 || !slices.Contains(adverse.HostingFlows, first) || !slices.Contains(adverse.HostingFlows, second) {
		t.Fatal(adverse)
	}
	r, p, now = networkFixture()
	known := Evaluate(r, p, r.Hash, now).Network
	if known.ClearsHosting(adverse) {
		t.Fatal("IPv4 access cleared an observed IPv6 datacenter exit")
	}
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Domain == second.Domain && s.Variant == second.Variant {
			s.Family, s.Network.Family = 6, 6
			s.Source = Hash([]byte("fixture-v6-access"))
			s.Network.Source = s.Source
		}
		if s.Domain == third.Domain && s.Variant == third.Variant {
			s.Network = nil
		}
	}
	known = Evaluate(r, p, r.Hash, now).Network
	if known.State != "unknown" || known.ClearanceUntil <= now || !known.ClearsHosting(adverse) {
		t.Fatal("unrelated unknown wrongly blocked scoped recovery", known)
	}
	legacy := NetworkVerdict{Version: NetworkVersion, State: "hosting", Domain: second.Domain, Variant: second.Variant, Family: 6}
	if !known.ClearsHosting(legacy) {
		t.Fatal("legacy specific adverse flow lost", known)
	}
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Domain == first.Domain && s.Variant == first.Variant && s.Wave == 1 {
			s.Network = nil
		}
	}
	known = Evaluate(r, p, r.Hash, now).Network
	if known.ClearsHosting(adverse) || !known.ClearsHosting(legacy) {
		t.Fatal("incomplete current attribution cleared same flow", known)
	}
}

func TestKnownHostingCanRecoverOnDifferentUnclassifiedOrigin(t *testing.T) {
	previous := NetworkVerdict{Version: NetworkVersion, State: "mixed", Domain: Domains[0], Variant: "raw", Family: 4, ASN: 20473, HostingASNs: []uint32{20473, 20474}}
	for name, tc := range map[string]struct {
		change func(*Sample)
		clear  bool
	}{
		"different observed origin": {nil, true},
		"private origin":            {func(s *Sample) { s.Network.ASN = 4200000000 }, false},
		"rotating unrelated origins": {func(s *Sample) {
			if s.Wave == 2 {
				s.Network.ASN = 3334
				s.Source = Hash([]byte("other endpoint"))
				s.Network.Source = s.Source
			}
		}, true},
		"rotation also containing prior hosting ASN": {func(s *Sample) {
			if s.Wave == 2 {
				s.Network.ASN = 20473
				s.Source = Hash([]byte("old exit"))
				s.Network.Source = s.Source
			}
		}, false},
		"first adverse origin":                   {func(s *Sample) { s.Network.ASN = 20473 }, false},
		"another previously adverse origin":      {func(s *Sample) { s.Network.ASN = 20474 }, false},
		"complete hosting feeds not established": {func(s *Sample) { s.Network.OriginOutsideHosting = false }, false},
		"unbound source":                         {func(s *Sample) { s.Network.Source = Hash([]byte("unrelated IP")) }, false},
		"snapshot unavailable":                   {func(s *Sample) { s.Network.Reason = "network_snapshot_unavailable" }, false},
		"stale dataset":                          {func(s *Sample) { s.Network.ValidUntil = s.At }, false},
		"unrecognised origin source":             {func(s *Sample) { s.Network.OriginSource = "ip-label" }, false},
		"competing kind":                         {func(s *Sample) { s.Network.Kind = "hosting" }, false},
		"unpaired selected waves": {func(s *Sample) {
			if s.Wave > 1 {
				s.Network = nil
			}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			r, p, now := networkFixture()
			for i := range r.Samples {
				s := &r.Samples[i]
				if !s.ActualAds {
					continue
				}
				// A usage miss remains unknown even if a trusted live snapshot can exclude
				// its observed origin from all the maintained hosting networks.
				s.Network.Kind, s.Network.Provider, s.Network.UsageSource = "unknown", "", ""
				s.Network.Reason, s.Network.OriginOutsideHosting = "network_usage_unverified", true
				s.Network.ASN = 3333
				if tc.change != nil {
					tc.change(s)
				}
			}
			d := Evaluate(r, p, r.Hash, now)
			if !d.Eligible || d.Network.BlocksResidential() || d.Network.Eligible || d.Network.State != "unknown" || d.Network.ClearsHosting(previous) != tc.clear {
				t.Fatal(d.Network)
			}
		})
	}
}

func TestNetworkCannotBorrowSelectedProofFromEarlierCore(t *testing.T) {
	r, p, now := networkFixture()
	part := cloneReceipt(r)
	for i := range part.Samples {
		s := &part.Samples[i]
		s.Nonce = Hash([]byte("earlier" + s.Connection))[:32]
		s.Connection = s.Nonce
	}
	r.Core, r.CoreSHA = NativeID, NativeSHA // Wrong driver for this Xray plan.
	r.Evidence = []Report{part}
	d := Evaluate(r, p, r.Hash, now)
	if d.Eligible || d.Network.Eligible || d.Network.Reason != "ads_network_route_unqualified" {
		t.Fatal(d.Reason, d.Network)
	}
}

func TestUnknownNetworkReasonIsBoundAndAllowlisted(t *testing.T) {
	r, p, now := networkFixture()
	unknown := r.Samples[0].Network
	unknown.Kind, unknown.Reason = "unknown", "network_usage_unverified"
	if d := Evaluate(r, p, r.Hash, now); d.Network.Detail != unknown.Reason || d.Network.Eligible {
		t.Fatal(d.Network)
	}
	unknown.Reason = "provider-controlled text"
	if d := Evaluate(r, p, r.Hash, now); d.Network.Detail != "" || d.Network.Eligible {
		t.Fatal(d.Network)
	}
}

func TestOneReplayedHostingConnectionCannotDisappearBehindTwoCleanWaves(t *testing.T) {
	r, p, now := networkFixture()
	setHosting(&r.Samples[0], 4)
	// The legacy route can still find two clean, paired, independent waves
	// even though both copies of the first nonce are discarded.
	r.Samples = append(r.Samples, r.Samples[0])
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || d.Network.State != "unknown" || d.Network.Eligible || d.Network.Domain != r.Samples[0].Domain {
		t.Fatal(d.Network)
	}
}

func TestNetworkEarlierAttemptVetoAndUnboundControl(t *testing.T) {
	r, p, now := networkFixture()
	part := r
	part.Checks, part.Samples, part.Waves = r.Checks[:1], nil, 0
	for _, s := range r.Samples {
		if s.Variant != "raw" || s.Wave > 2 {
			continue
		}
		if s.Domain == Domains[0] {
			setHosting(&s, 4)
		} else if s.Domain != "www.google.com" && s.Domain != "api.ipify.org" {
			continue
		}
		s.Nonce = Hash([]byte("earlier" + s.Connection))[:32]
		s.Connection = s.Nonce
		part.Samples = append(part.Samples, s)
	}
	r.Evidence = []Report{part}
	decide := func() NetworkVerdict { return Evaluate(r, p, r.Hash, now).Network }
	if n := decide(); n.Eligible || n.State != "mixed" {
		t.Fatal("partial earlier attempt hidden", n)
	}
	for _, change := range []func(*Report){
		func(a *Report) { a.CoreSHA = "unverified" },
		func(a *Report) { a.Hash = "another-job" },
		func(a *Report) { a.Samples[0].Domain = "www.google.com" },
		func(a *Report) { a.Samples[0].Domain = "unregistered.example" },
		func(a *Report) { a.Samples[0].TLS = false },
		func(a *Report) { a.Core, a.CoreSHA = NativeID, NativeSHA },
	} {
		r.Evidence[0] = cloneReceipt(part)
		change(&r.Evidence[0])
		if n := decide(); n.BlocksResidential() {
			t.Fatal("unbound or control observation established a datacenter hold", n)
		}
	}
}

func TestUnresolvedHostingCannotQualifyItsOwnProfile(t *testing.T) {
	r, p, now := networkFixture()
	for i := range r.Samples {
		s := &r.Samples[i]
		// Leave the other waves intact, so the base route and delivery
		// qualify independently of the ambiguous IPv6 hosting claim.
		if s.Wave == 1 && s.Variant == "raw" && (s.Domain == profiles[0].Domains[0] || s.Domain == profiles[1].Domains[0]) {
			setHosting(s, 6)
		}
	}
	d := Evaluate(r, p, r.Hash, now)
	if d.Network.Policy != NetworkPolicyVersion || d.Eligible || d.Negative || d.Until != 0 || d.State != "UNKNOWN" || d.Reason != "ads_hosting_route_unresolved" || d.Network.BlocksResidential() || len(d.QualifiedProfiles) != 0 || len(d.Network.UnresolvedHosting) != 2 {
		t.Fatal(d.State, d.Reason, d.QualifiedProfiles, d.Network)
	}
}

func TestSharedDatacenterWithoutQualifiedProfile(t *testing.T) {
	r, p, now := networkFixture()
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.ActualAds {
			setHosting(s, 4)
			s.Source = Hash([]byte("1.1.1.1"))
			s.Network.Source = s.Source
		}
	}
	d := Evaluate(r, p, r.Hash, now)
	if !d.Negative || d.State != "NO_SPLIT" || d.Network.BlocksResidential() || !d.Network.SharedHostingOnly() || len(d.Network.SharedHosting) != len(Domains)*2 {
		t.Fatal(d.State, d.Reason, d.Network)
	}
}

func TestHostingAttributionNeverCombinesDifferentAttemptsOrOrigins(t *testing.T) {
	for _, mode := range []string{"wave", "attempt", "provider", "asn", "variant", "domain"} {
		t.Run(mode, func(t *testing.T) {
			r, p, now := networkFixture()
			part := r
			part.Samples = nil
			for i := range r.Samples {
				s := &r.Samples[i]
				if s.Wave > 2 || s.Variant != "raw" {
					continue
				}
				if s.Domain == Domains[0] {
					setHosting(s, 4)
					if s.Wave == 2 {
						switch mode {
						case "wave":
							s.Wave = 1
						case "attempt":
							sCopy := *s
							part.Samples = append(part.Samples, sCopy)
							s.Network = nil
							s.Nonce = Hash([]byte("replace" + s.Connection))[:32]
							s.Connection = s.Nonce
						case "provider":
							s.Network.Provider = "other"
						case "asn":
							s.Network.ASN++
						case "variant":
							s.Variant = "template"
						case "domain":
							s.Domain = Domains[1]
						}
					}
				} else if mode == "attempt" && (s.Domain == "www.google.com" || s.Domain == "api.ipify.org") {
					c := *s
					c.Nonce = Hash([]byte("previous" + c.Connection))[:32]
					c.Connection = c.Nonce
					part.Samples = append(part.Samples, c)
				}
			}
			if mode == "attempt" {
				r.Evidence = []Report{part}
			}
			d := Evaluate(r, p, r.Hash, now)
			if d.Network.BlocksResidential() || len(d.Network.UnresolvedHosting) == 0 {
				t.Fatal("hosting observations combined outside a repeated, bound flow", d.Network)
			}
		})
	}
}
