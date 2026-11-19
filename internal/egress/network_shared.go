package egress

import "slices"

// SharedNetwork records the provider and origin observed on an Ads flow for
// comparison with ordinary controls, without retaining the reflected address.
type SharedNetwork struct {
	NetworkFlow
	Provider string `json:"provider"`
	ASN      uint32 `json:"asn"`
}

func (n NetworkVerdict) SharedHostingOnly() bool {
	return n.Version == NetworkVersion && len(n.SharedHosting) > 0 && len(n.UnresolvedHosting) == 0 && !n.BlocksResidential()
}

type ordinaryControl struct {
	sources  map[int][]string
	observed map[string]bool
	group    string
}

type pathAttribution int

const (
	pathUnresolved pathAttribution = iota
	pathShared
	pathSeparated
)

func observedExchange(s Sample) bool {
	return s.ResponseComplete && s.RequestBytes > 0 && s.RequestBytes <= 32768 && s.ResponseBytes > 0 && s.ResponseBytes <= 131072
}

// Controls belong to the same driver attempt. A different variant or address
// family can traverse a different outbound even on a single proxy.
type ordinaryControls map[NetworkFlow]*ordinaryControl

func readOrdinaryControls(r Report, valid map[string]bool, connections map[string]int) ordinaryControls {
	controls := ordinaryControls{}
	for _, s := range r.Samples {
		t, ok := targetFor(s.Domain)
		if !ok || t.Role != "control" || (!t.Required && t.WhenAdsFamily != s.Family) || s.ActualAds || !valid[s.Variant] || !routeValid(s, r) || connections[s.Connection] != 1 || !observedExchange(s) {
			continue
		}
		key := NetworkFlow{s.Domain, s.Variant, s.Family}
		c := controls[key]
		if c == nil {
			c = &ordinaryControl{sources: map[int][]string{}, observed: map[string]bool{}, group: t.Group}
			controls[key] = c
		}
		c.sources[s.Wave] = append(c.sources[s.Wave], s.Source)
		c.observed[s.Source] = true
	}
	return controls
}

func (controls ordinaryControls) path(s Sample) pathAttribution {
	google, independent, crossWaveMatch := false, false, false
	for key, c := range controls {
		if key.Variant != s.Variant || key.Family != s.Family {
			continue
		}
		inWave := c.sources[s.Wave]
		stable := len(c.observed) == 1 && len(c.sources) >= 2
		if c.observed[s.Source] {
			if slices.Contains(inWave, s.Source) || len(inWave) == 0 && stable {
				return pathShared
			}
			crossWaveMatch = true
		} else if stable && len(inWave) > 0 {
			if c.group == "google-search" {
				google = true
			} else {
				independent = true
			}
		}
	}
	if google && independent && !crossWaveMatch {
		return pathSeparated
	}
	return pathUnresolved
}

func verifiedAdsExchange(s Sample) bool {
	return s.Code == "ads_peer_reported" && s.FirstStatus >= 200 && s.FirstStatus < 500 && observedExchange(s)
}
