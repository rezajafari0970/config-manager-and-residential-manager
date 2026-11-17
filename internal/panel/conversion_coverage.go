package panel

// Coverage is an exclusive partition of canonical inputs. Prepared syntax,
// attempted tests, and currently publishable connectivity are different counts.
type ConversionCoverage struct {
	Total            int `json:"total"`
	Ready            int `json:"ready"`
	Queued           int `json:"queued"`
	Running          int `json:"running"`
	Structural       int `json:"structural"`
	ConnectionFailed int `json:"connection_failed"`
	Environment      int `json:"environment"`
	Expired          int `json:"expired"`
	Tested           int `json:"tested"`
	CorePassed       int `json:"core_passed"`
}

func (c Conversion) Healthy(now int64) bool {
	return c.Current && c.Core == "passed" && c.Connection == "passed" && c.ValidUntil > now && validDigest(c.CandidateHash)
}
func (c Conversion) coverageState(now int64) string {
	if c.Healthy(now) {
		return "ready"
	}
	if c.State == "running" {
		return "running"
	}
	if !c.Prepared && c.PreparationCode != "" && c.PreparationCode != "original_blob_unavailable" {
		return "structural"
	}
	if !c.Current || c.State == "queued" {
		return "queued"
	}
	if c.Connection == "passed" && c.ValidUntil <= now {
		return "expired"
	}
	switch c.Code {
	case "ipv6_relay_unavailable", "ipv6_endpoint_capacity", "ipv6_only_probe_pending", "ipv6_route_unavailable", "probe_infrastructure_error", "probe_preparation_failed", "client_core_infrastructure_error", "client_core_asset_missing", "missing_runtime_asset", "probe_resource_or_signal_failure", "original_blob_unavailable", "candidate_blob_unavailable", "probe_job_timeout":
		return "environment"
	}
	if c.Core == "failed" || c.Core == "not_run" {
		return "structural"
	}
	if c.Core == "blocked" {
		return "environment"
	}
	return "connection_failed"
}
func (v *ConversionCoverage) Add(c Conversion, now int64) {
	v.Total++
	if c.Current && c.Tested > 0 && (c.Core == "passed" || c.Core == "failed") {
		v.Tested++
	}
	if c.Current && c.Core == "passed" {
		v.CorePassed++
	}
	switch c.coverageState(now) {
	case "ready":
		v.Ready++
	case "queued":
		v.Queued++
	case "running":
		v.Running++
	case "structural":
		v.Structural++
	case "expired":
		v.Expired++
	case "environment":
		v.Environment++
	default:
		v.ConnectionFailed++
	}
}
