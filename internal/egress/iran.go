package egress

// Iran is a deny signal, independent of split-route qualification and payload
// health. Missing observations never manufacture a country or a clean result.
const IranVersion = "ads-iran.v2"
const IranInterval = int64(600000)
const IranSpacing = int64(60000)

type IranObservation struct {
	Version string        `json:"version"`
	Hash    string        `json:"hash"`
	Domain  string        `json:"domain"`
	Variant string        `json:"variant"`
	At      int64         `json:"at"`
	Country CountryResult `json:"country"`
}

func Iran(r Report, p Plan, hash string, now int64) *IranObservation {
	return findIranSignal(r, p, hash, now, false)
}

// A disagreement can withhold publication without creating a confirmed guard hit.
func IranCountryConflict(r Report, p Plan, hash string, now int64) bool {
	return findIranSignal(r, p, hash, now, true) != nil
}

func findIranSignal(r Report, p Plan, hash string, now int64, conflict bool) *IranObservation {
	if !boundRound(r, hash, now) || len(r.Evidence) > 4 {
		return nil
	}
	connections := connectionCounts(r)
	if x := iranSignal(r, p, now, connections, conflict); x != nil {
		return x
	}
	for _, part := range r.Evidence {
		part, ok := resolveAttemptSamples(r, part)
		if !ok || len(part.Evidence) != 0 || !boundRound(part, hash, now) || part.Started < r.Started || part.Finished > r.Finished {
			continue
		}
		if x := iranSignal(part, p, now, connections, conflict); x != nil {
			return x
		}
	}
	return nil
}

func iranSignal(r Report, p Plan, now int64, connections map[string]int, conflict bool) *IranObservation {
	if r.ResourcePressure || r.Waves < 1 || r.Waves > 3 || !boundCore(p.Driver, r.Core, r.CoreSHA) || len(r.Checks) > 2 {
		return nil
	}
	// A successful observation in either exact variant is sufficient.
	valid := map[string]bool{}
	for _, c := range r.Checks {
		if _, duplicate := valid[c.Name]; duplicate {
			return nil
		}
		valid[c.Name] = false
		for _, v := range p.Variants {
			if c.Name == v.Name && boundCheck(c, v.Hash) && Hash(v.Config) == v.Hash {
				valid[c.Name] = true
			}
		}
	}
	for _, s := range r.Samples {
		if !valid[s.Variant] || !s.Geo.mentionsIran() || !countrySample(s, r, connections) {
			continue
		}
		one := r
		one.Samples = []Sample{s}
		country := observedCountries(one, r.Finished+IranInterval, now)
		if conflict && country.Status == "country_iran_conflict" || !conflict && country.Complete && len(country.Countries) == 1 && country.Countries[0] == "IR" {
			return &IranObservation{IranVersion, r.Hash, s.Domain, s.Variant, s.At, country}
		}
	}
	return nil
}

// Samples are serialized once. A selected-attempt reference may reuse them only
// with exactly matching core/check bindings; its pressure flag stays independent.
func resolveAttemptSamples(r, part Report) (Report, bool) {
	if !part.SelectedSamples {
		// Legacy attempt summaries carry bounded wave labels on each sample
		// but omit the count. The worker never schedules more than three.
		if part.Waves == 0 {
			part.Waves = 3
		}
		return part, true
	}
	if len(part.Samples) != 0 || part.Core != r.Core || part.CoreSHA != r.CoreSHA || part.Hash != r.Hash || part.Version != r.Version || len(part.Checks) != len(r.Checks) {
		return part, false
	}
	for i, c := range part.Checks {
		if c != r.Checks[i] {
			return part, false
		}
	}
	if part.Waves != 0 && part.Waves != r.Waves {
		return part, false
	}
	part.Samples, part.Waves = r.Samples, r.Waves
	return part, true
}
