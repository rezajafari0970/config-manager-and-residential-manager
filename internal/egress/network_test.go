package egress

import "testing"

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
	if !d.Eligible || d.Network.Eligible || d.Network.Reason != "ads_network_evidence_incomplete" || d.Network.Domain != r.Samples[0].Domain {
		t.Fatal(d.Network)
	}
	for i := range r.Samples {
		r.Samples[i].Network = nil
	}
	d = Evaluate(r, p, r.Hash, now)
	if !d.Eligible || d.Network.State != "unknown" || d.Network.Eligible {
		t.Fatal("legacy route evidence published or misclassified", d.Network)
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
	if !d.Eligible || d.Network.Eligible || d.Network.State != "hosting" || d.Network.Provider != "vultr" || d.Network.ASN != 20473 {
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
	if d.Network.Eligible || d.Network.Reason != "ads_mixed_exit" || d.Network.Domain != "securepubads.g.doubleclick.net" || d.Network.Variant != "template" || d.Network.Family != 6 || len(d.Network.Families) != 2 {
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

func TestExitNetworkNeedsBothProfilesAndExactAdDelivery(t *testing.T) {
	r, p, now := networkFixture()
	for i := range r.Delivery {
		r.Delivery[i].Assets[1].HTTPStatus = 403
	}
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || d.Network.Eligible || d.Network.Reason != "ads_network_coverage_incomplete" {
		t.Fatal(d.Network)
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
	if d.Network.Eligible || d.Network.Reason != "ads_network_coverage_incomplete" {
		t.Fatal(d.Network)
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
	s := r.Samples[0]
	setHosting(&s, 4)
	s.Nonce = Hash([]byte("previous-core-specific-connection"))[:32]
	s.Connection = s.Nonce
	part := r
	part.Checks, part.Samples, part.Waves = r.Checks[:1], []Sample{s}, 0
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
		if n := decide(); !n.Eligible {
			t.Fatal("unbound or control evidence suppressed a proven network", n)
		}
	}
}
