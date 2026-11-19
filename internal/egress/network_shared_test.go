package egress

import (
	"slices"
	"testing"
)

// DoubleClick separates from the ordinary controls. The other category uses
// the same AWS exit on its Ads connections as on its ordinary controls.
func sharedHostingFixture() (Report, Plan, int64) {
	r, p, now := networkFixture()
	for i := range r.Samples {
		s := &r.Samples[i]
		if !s.ActualAds {
			continue
		}
		if slices.Contains(profiles[0].Domains, s.Domain) {
			s.Network = nil
			continue
		}
		s.Source = Hash([]byte("1.1.1.1"))
		s.Network.Source = s.Source
		s.Network.Kind, s.Network.Provider, s.Network.ASN = "hosting", "aws", 16509
	}
	return r, p, now
}

func TestHostingOnOrdinaryPathOfOtherProfile(t *testing.T) {
	r, p, now := sharedHostingFixture()
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || !slices.Equal(d.QualifiedProfiles, []string{profiles[0].ID}) || !d.Network.SharedHostingOnly() || d.Network.BlocksResidential() || d.Network.State != "unknown" || len(d.Network.SharedHosting) != len(profiles[1].Domains)*2 {
		t.Fatal(d.QualifiedProfiles, d.Network)
	}
	for _, flow := range d.Network.SharedHosting {
		if flow.Provider != "aws" || flow.ASN != 16509 || !slices.Contains(profiles[1].Domains, flow.Domain) || !slices.Contains(d.Network.SharedFlows, flow.NetworkFlow) {
			t.Fatal(flow)
		}
	}
	// A remaining authentic differing wave on this very same flow prevents
	// earlier equal waves from hiding a split hosting observation.
	for i := range r.Samples {
		s := &r.Samples[i]
		if s.Domain == profiles[1].Domains[0] && s.Variant == "raw" && s.Wave == 3 {
			s.Source = Hash([]byte("distinct-AWS-exit"))
			s.Network.Source = s.Source
		}
	}
	d = Evaluate(r, p, r.Hash, now)
	if !d.Eligible || !d.Network.BlocksResidential() || d.Network.SharedHostingOnly() || d.Network.Domain != profiles[1].Domains[0] || !slices.Contains(d.Network.HostingASNs, uint32(16509)) {
		t.Fatal(d.Network)
	}
}

func TestSharedPathControlBindingAndMissingWave(t *testing.T) {
	for name, mode := range map[string]string{"stable missing wave": "stable", "rotating controls": "rotating", "incomplete control exchange": "incomplete", "wrong variant": "variant", "wrong family": "family", "different attempt": "attempt", "in-wave different source": "conflict"} {
		t.Run(name, func(t *testing.T) {
			r, p, now := sharedHostingFixture()
			ad := r.Samples[0]
			ad.Domain, ad.Family, ad.Wave = profiles[1].Domains[0], 6, 1
			ad.Nonce = Hash([]byte("v6 AWS ad"))[:32]
			ad.Connection = ad.Nonce
			ad.Source = Hash([]byte("AWS v6"))
			ad.Network = &NetworkFact{Version: NetworkVersion, Kind: "hosting", Provider: "aws", ASN: 16509, Family: 6, PrefixLen: 48, Source: ad.Source, UsageSource: "aws-geofeed", OriginSource: "ripe-ris", Dataset: Hash([]byte("revision")), CheckedAt: now, ValidUntil: now + EvidenceTTL}
			r.Samples = append(r.Samples, ad)
			var controls []Sample
			for wave := 2; wave <= 3; wave++ {
				c := ad
				c.Domain, c.ActualAds, c.Network, c.Wave = "www.google.com", false, nil, wave
				c.Nonce = Hash([]byte(name + string(rune('0'+wave))))[:32]
				c.Connection = c.Nonce
				switch mode {
				case "rotating":
					if wave == 3 {
						c.Source = Hash([]byte("another v6"))
					}
				case "incomplete":
					c.ResponseComplete = false
				case "variant":
					c.Variant = "template"
				case "family":
					c.Family = 4
				}
				controls = append(controls, c)
			}
			if mode == "conflict" {
				c := controls[0]
				c.Wave = 1
				c.Nonce = Hash([]byte("wrong same-wave control"))[:32]
				c.Connection = c.Nonce
				c.Source = Hash([]byte("changed ordinary v6"))
				controls = append(controls, c)
			}
			if mode == "attempt" {
				part := r
				part.Samples = controls
				r.Evidence = []Report{part}
			} else {
				r.Samples = append(r.Samples, controls...)
			}
			d := Evaluate(r, p, r.Hash, now)
			if !d.Eligible || d.Network.BlocksResidential() != (mode != "stable") || d.Network.SharedHostingOnly() != (mode == "stable") {
				t.Fatal(d.Network)
			}
		})
	}
}
