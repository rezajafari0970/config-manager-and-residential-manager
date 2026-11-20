package panel

import (
	"net/http"
	"time"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/native"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/side"
)

// Only registered on the local protected worker socket.
func (s *Store) registerPrivateSide(mux *http.ServeMux) {
	// Readiness never issues a lease. When resources are saturated this lets
	// the supervisor advertise demand for the shared budget only for real work.
	mux.HandleFunc("POST /side/ready", func(w http.ResponseWriter, r *http.Request) {
		ready, err := s.SideReady(r.Context())
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, http.StatusOK, ready)
	})
	mux.HandleFunc("POST /side/claim", func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.ProbeSettings(r.Context())
		if err != nil {
			failure(w, err)
			return
		}
		j, err := s.ClaimSide(r.Context())
		if err != nil {
			failure(w, err)
			return
		}
		if j == nil {
			respond(w, 200, nil)
			return
		}
		respond(w, 200, probe.Job{Identity: j.Identity, Hash: j.Hash, Token: j.Token, Kind: j.Kind,
			Raw: j.Raw, Issue: j.Issue, Settings: settings})
	})
	mux.HandleFunc("POST /side/renew", func(w http.ResponseWriter, r *http.Request) {
		var j probe.Job
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if decode(r, &j) != nil {
			failure(w, ErrInvalid)
			return
		}
		if err := s.RenewSide(r.Context(), SideJob{Identity: j.Identity, Hash: j.Hash, Token: j.Token}); err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, true)
	})
	mux.HandleFunc("POST /side/complete", func(w http.ResponseWriter, r *http.Request) {
		var v probe.Result
		r.Body = http.MaxBytesReader(w, r.Body, 2*repair.MaxBytes+65536)
		if decode(r, &v) != nil || v.Version != convert.Version || !safeCode(v.Code) {
			failure(w, ErrInvalid)
			return
		}
		if v.Code == "passed" && !sideRuntimeVerified(v) {
			failure(w, ErrInvalid)
			return
		}
		job := SideJob{Identity: v.Identity, Hash: v.Hash, Token: v.Token}
		var err error
		if sideInfrastructure(v) {
			err = s.DeferSide(r.Context(), job, v.Code, v.Evidence)
		} else {
			err = s.CompleteSide(r.Context(), SideResult{Identity: v.Identity, Hash: v.Hash, Token: v.Token,
				Code: v.Code, Evidence: v.Evidence, Candidate: v.Candidate})
		}
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, true)
	})
	mux.HandleFunc("POST /side/status", s.admitWorker(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v probe.WorkerStatus
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if decode(r, &v) != nil || !safeCode(v.Status) || (v.Code != "" && !safeCode(v.Code)) ||
			v.Version != convert.Version || v.Active < 0 || v.Active > side.MaxWorkers {
			failure(w, ErrInvalid)
			return
		}
		_, err := s.db.ExecContext(r.Context(), `UPDATE side_worker SET status=?,code=?,version=?,active=?,heartbeat=? WHERE id=1`,
			v.Status, v.Code, v.Version, v.Active, time.Now().UnixMilli())
		if err != nil {
			failure(w, err)
			return
		}
		respond(w, 200, true)
	})).ServeHTTP)
}

func sideRuntimeVerified(v probe.Result) bool {
	if v.Core != "passed" || v.Connection != "passed" || v.EndpointsPassed != len(sideServices) ||
		!validDigest(v.SHA256) || v.RuntimeSHA256 != v.SHA256 || v.SHA256 != v.Evidence["candidate_sha256"] {
		return false
	}
	switch v.Evidence["engine"] {
	case "xray":
		return v.Engine != "sing-box" && v.CoreSHA256 == probe.CoreSHA256 && v.Evidence["bundled_core"] == "passed" &&
			v.Evidence["target_core"] == "passed" && v.Evidence["app_import_contract"] == "passed"
	case "sing-box":
		return v.Engine == "sing-box" && v.CoreSHA256 == native.NativeSHA && v.Evidence["native_core"] == "passed" &&
			v.Evidence["runtime_core"] == "sing_box_1_14_4"
	default:
		return false
	}
}

func sideInfrastructure(v probe.Result) bool {
	switch v.Code {
	case "side_driver_unavailable", "side_provider_unavailable", "probe_infrastructure_error", "probe_job_timeout",
		"input_unavailable", "original_blob_unavailable", "sandbox_preflight_failed", "preparation_recovered",
		"client_core_infrastructure_error", "client_core_validation_timeout", "client_core_asset_missing",
		"missing_runtime_asset", "probe_resource_or_signal_failure", "ipv6_relay_unavailable", "ipv6_endpoint_capacity",
		"endpoint_dns_failed", "probe_preparation_failed", "core_validation_timeout", "ipv6_only_probe_pending",
		"outbound_driver_pending":
		return true
	}
	return false
}
