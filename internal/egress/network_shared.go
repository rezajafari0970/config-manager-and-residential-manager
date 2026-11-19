package egress

import "slices"

// SharedNetwork records an attributed datacenter on the ordinary path of an
// Ads domain outside the selected route profile. Keep it available for audit.
type SharedNetwork struct {
	NetworkFlow
	Provider string `json:"provider"`
	ASN      uint32 `json:"asn"`
}

func (n NetworkVerdict) SharedHostingOnly() bool {
	return n.Version == NetworkVersion && len(n.SharedHosting) > 0 && !n.BlocksResidential()
}

type ordinaryControl struct {
	sources      map[int][]string
	stableSource string
	rotating     bool
}

func (c *ordinaryControl) matches(wave int, source string) bool {
	if sameWave := c.sources[wave]; len(sameWave) > 0 {
		return slices.Contains(sameWave, source)
	}
	return !c.rotating && len(c.sources) >= 2 && c.stableSource == source
}

func observedExchange(s Sample) bool {
	return s.ResponseComplete && s.RequestBytes > 0 && s.RequestBytes <= 32768 && s.ResponseBytes > 0 && s.ResponseBytes <= 131072
}

// A shared-path exception must be demonstrated within the same core attempt,
// variant and IP family. A control missing in one wave is usable only if its
// source is identical across at least two authenticated waves in this attempt.
func ordinarySharedFlows(r Report, valid map[string]bool, connections map[string]int, route Decision) map[NetworkFlow]bool {
	if !route.Eligible || route.CountryConflict || len(route.QualifiedDomains) == 0 || r.Waves < 2 || r.Waves > 3 {
		return nil
	}
	controls := map[NetworkFlow]*ordinaryControl{}
	for _, s := range r.Samples {
		t, ok := targetFor(s.Domain)
		if !ok || t.Role != "control" || !t.Required || s.ActualAds || !valid[s.Variant] || !routeValid(s, r) || connections[s.Connection] != 1 || !observedExchange(s) {
			continue
		}
		key := NetworkFlow{s.Domain, s.Variant, s.Family}
		c := controls[key]
		if c == nil {
			c = &ordinaryControl{sources: map[int][]string{}, stableSource: s.Source}
			controls[key] = c
		}
		c.sources[s.Wave] = append(c.sources[s.Wave], s.Source)
		c.rotating = c.rotating || c.stableSource != s.Source
	}
	shared := map[NetworkFlow]bool{}
	for _, s := range r.Samples {
		t, ok := targetFor(s.Domain)
		if !ok || t.Role != "ads" || !s.ActualAds || !valid[s.Variant] || !validSource(s, r) || slices.Contains(route.QualifiedDomains, s.Domain) {
			continue
		}
		key := NetworkFlow{s.Domain, s.Variant, s.Family}
		if allMatched, observed := shared[key]; observed && !allMatched {
			continue
		}
		matched := false
		if routeValid(s, r) && connections[s.Connection] == 1 && verifiedAdsExchange(s) {
			for _, domain := range ControlDomains {
				c := controls[NetworkFlow{domain, s.Variant, s.Family}]
				if c != nil && c.matches(s.Wave, s.Source) {
					matched = true
					break
				}
			}
		}
		shared[key] = matched
	}
	return shared
}

func verifiedAdsExchange(s Sample) bool {
	return s.Code == "ads_peer_reported" && s.FirstStatus >= 200 && s.FirstStatus < 500 && observedExchange(s)
}
