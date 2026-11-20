package panel

import (
	"encoding/json"
	"net/http"
	"slices"
)

// The panel needs the outcomes of the fixed service tests. Driver metadata,
// endpoint addresses, credentials and complete config identities stay private.
type sideReview struct {
	Form     string            `json:"form,omitempty"`
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Finished int64             `json:"finished"`
	Reason   string            `json:"reason"`
	Checks   map[string]string `json:"checks"`
	Measured int               `json:"measured"`
	Coverage string            `json:"coverage"`
}

func (m sideOutputModule) reviews(w http.ResponseWriter, r *http.Request) {
	rows, err := m.s.store.reader().QueryContext(r.Context(), `SELECT substr(identity,1,12),state,finished,code,evidence
		FROM side_jobs WHERE finished>0 ORDER BY finished DESC,identity LIMIT 20`)
	if err != nil {
		failure(w, err)
		return
	}
	defer rows.Close()
	reviews := make([]sideReview, 0, 20)
	for rows.Next() {
		var v sideReview
		var code string
		var evidence []byte
		if err := rows.Scan(&v.ID, &v.State, &v.Finished, &code, &evidence); err != nil {
			failure(w, err)
			return
		}
		v.Reason = sideReviewReason(code, v.State)
		var record map[string]string
		if err := json.Unmarshal(evidence, &record); err != nil {
			failure(w, err)
			return
		}
		v.Form, v.Checks = sideReviewChecks(record)
		v.Measured, v.Coverage = sideReviewCoverage(v.Checks, record["side_version"], v.State, v.Reason)
		reviews = append(reviews, v)
	}
	if err := rows.Err(); err != nil {
		failure(w, err)
		return
	}
	respond(w, http.StatusOK, reviews)
}

// A template can pass every check while its original delivery form fails.
// Never label the passing template's observations as the raw result.
func sideReviewChecks(record map[string]string) (string, map[string]string) {
	form, prefix := "template", ""
	if record["raw_checks"] == "failed" {
		form, prefix = "raw", "raw_"
	} else if record["raw_checks"] == "passed" {
		form = "both"
	}
	checks := make(map[string]string, len(sideServices))
	for _, service := range sideServices {
		checks[service] = sideObservation(record[prefix+service])
	}
	return form, checks
}

func sideObservation(value string) string {
	if slices.Contains(sideMeasuredOutcomes, value) || value == "not_run" || value == "side_driver_unavailable" {
		return value
	}
	return "unrecorded"
}

func sideReviewCoverage(checks map[string]string, version, state, reason string) (int, string) {
	measured := 0
	for _, outcome := range checks {
		if slices.Contains(sideMeasuredOutcomes, outcome) {
			measured++
		}
	}
	switch {
	case measured == len(sideServices):
		return measured, "complete"
	case version == "side_v1" && measured > 0:
		return measured, "legacy_partial"
	case measured > 0:
		return measured, "partial"
	case state == "inconclusive":
		return 0, "infrastructure"
	case reason == "side_checks_failed" || reason == "no_verified_profile" || version != "":
		return 0, "unrecorded"
	default:
		return 0, "no_session"
	}
}

func sideReviewReason(code, state string) string {
	switch code {
	case "passed", "side_checks_failed", "side_raw_unverified", "side_driver_unavailable", "side_provider_unavailable", "worker_lease_exhausted", "probe_job_timeout",
		"reality_authentication_rejected", "unsupported_protocol", "original_blob_unavailable", "input_unavailable", "connection_timeout",
		"client_core_incompatible", "client_core_validation_timeout", "endpoint_dns_failed", "sandbox_preflight_failed",
		"client_vless_encryption_required", "client_trojan_tls_required", "runtime_start_failed", "protocol_disabled",
		"probe_socks_contract_missing", "nonpublic_endpoint_blocked", "core_rejected",
		"nonloopback_listener_not_qualified", "listener_port_conflict", "direct_route_not_qualified", "direct_default_not_qualified",
		"native_path_unsupported", "native_route_unqualified", "client_core_infrastructure_error", "missing_runtime_asset",
		"probe_resource_or_signal_failure", "unsupported_protocol_or_transport", "unsupported_transport", "invalid_uuid",
		"no_proxy_endpoint", "invalid_proxy_endpoint", "core_schema_mismatch", "core_parse_failure":
		return code
	}
	if state == "inconclusive" {
		return "probe_infrastructure_error"
	}
	return "no_verified_profile"
}
