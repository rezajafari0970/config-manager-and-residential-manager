package egress

// MaxCompletionBytes is the private HTTP completion envelope limit. The helper
// can return frames up to this bound before the worker encodes its completion.
const MaxCompletionBytes = 4 << 20

// ValidReportShape checks the job binding and bounded structure before either
// the worker or the API accepts a report. Verdicts validate the observations.
func ValidReportShape(r Report, hash string) bool {
	if r.Hash != hash || r.Version != Version || len(r.Samples) > 256 || len(r.Attempts) > 8 ||
		len(r.Checks) > 2 || len(r.Health) > 3 || len(r.Evidence) > 4 || len(r.Delivery) > 3 {
		return false
	}
	for _, part := range r.Evidence {
		if part.Hash != hash || part.Version != Version || len(part.Evidence) != 0 ||
			len(part.Samples) > 256 || len(part.Checks) > 2 || len(part.Health) > 3 || len(part.Delivery) > 3 {
			return false
		}
	}
	return true
}

// ValidDriverReply checks the reply to one exchange before the worker stops
// its bounded repair loop. A preflight or core failure can have no samples.
func ValidDriverReply(r Report, p Plan, hash string, started, now int64) bool {
	if !ValidReportShape(r, hash) || r.Started != started || r.Finished < started || r.Finished > now+2000 || r.Code == "" || len(r.Attempts) == 0 {
		return false
	}
	for _, a := range r.Attempts {
		if a.Core == "" || a.Code == "" {
			return false
		}
	}
	return ValidAssessment(r, p)
}

// ValidAssessment protects completion at the store as well as the worker.
// Older clients can omit the outer code and transport attempts. A measurement
// then needs a bound observation, which can be a failed request or a health
// check. Explicit preflight and infrastructure failures can be payload-free.
func ValidAssessment(r Report, p Plan) bool {
	switch r.Code {
	case "":
		if hasBoundObservation(r, p) {
			return true
		}
		for _, part := range r.Evidence {
			if part.Started >= r.Started && part.Finished <= r.Finished && hasBoundObservation(part, p) {
				return true
			}
		}
		return false
	case "driver_unavailable":
		return len(p.Variants) != 2
	case "measured":
	default:
		return true
	}
	if len(p.Variants) != 2 || len(r.Checks) != 2 || !boundCore(p.Driver, r.Core, r.CoreSHA) {
		return false
	}

	for i, v := range p.Variants {
		if r.Checks[i].Name != v.Name || !boundCheck(r.Checks[i], v.Hash) {
			return false
		}
		if !variantObserved(r, v.Name, true) {
			return false
		}
	}
	return true
}

func hasBoundObservation(r Report, p Plan) bool {
	if len(p.Variants) != 2 || !boundCore(p.Driver, r.Core, r.CoreSHA) {
		return false
	}
	for _, check := range r.Checks {
		for _, v := range p.Variants {
			if check.Name == v.Name && boundCheck(check, v.Hash) && variantObserved(r, v.Name, false) {
				return true
			}
		}
	}
	return false
}

func variantObserved(r Report, name string, routeOnly bool) bool {
	inRound := func(variant string, at int64) bool {
		return variant == name && at >= r.Started && at <= r.Finished+2000
	}
	for _, s := range r.Samples {
		if inRound(s.Variant, s.At) && s.Domain != "" && (s.Code != "" || s.Echo) && s.Wave > 0 && s.Wave <= r.Waves {
			return true
		}
	}
	if !routeOnly {
		for _, d := range r.Delivery {
			if inRound(d.Variant, d.At) && !d.HostControl && d.Version == DeliveryVersion && len(d.Assets) != 0 {
				return true
			}
		}
		for _, h := range r.Health {
			if inRound(h.Variant, h.At) && !h.HostControl && h.Version == HealthVersion && len(h.Providers) != 0 {
				return true
			}
		}
	}
	return false
}
