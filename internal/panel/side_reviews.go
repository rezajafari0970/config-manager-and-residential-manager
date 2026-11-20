package panel

import (
	"encoding/json"
	"net/http"
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
	switch value {
	case "passed", "not_run", "warp_not_active", "provider_unavailable", "side_driver_unavailable", "timeout",
		"transport_failed", "unverified_connection", "unexpected_http_status", "unexpected_content", "incomplete_response", "incomplete_upload":
		return value
	default:
		return "unrecorded"
	}
}

func sideReviewReason(code, state string) string {
	switch code {
	case "passed", "side_checks_failed", "side_raw_unverified", "side_driver_unavailable", "side_provider_unavailable", "worker_lease_exhausted", "probe_job_timeout",
		"reality_authentication_rejected", "unsupported_protocol", "original_blob_unavailable", "input_unavailable", "connection_timeout",
		"client_core_incompatible", "client_core_validation_timeout", "endpoint_dns_failed", "sandbox_preflight_failed":
		return code
	}
	if state == "inconclusive" {
		return "probe_infrastructure_error"
	}
	return "no_verified_profile"
}
