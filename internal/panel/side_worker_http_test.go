package panel

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/convert"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
)

func TestSidePrivateRPCRequiresAuthenticatedRuntimeReceipt(t *testing.T) {
	s := testStore(t)
	newExportSource(t, s, "private-side", sourceURI(111))
	h := s.PrivateProbeHandler()
	post := func(path string, v any, status int) []byte {
		t.Helper()
		body, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/side/"+path, bytes.NewReader(body)))
		if w.Code != status {
			t.Fatalf("%s returned %d, want %d", path, w.Code, status)
		}
		return w.Body.Bytes()
	}
	if a, b := post("ready", nil, 200), post("ready", nil, 200); string(bytes.TrimSpace(a)) != "true" || !bytes.Equal(a, b) {
		t.Fatal("readiness consumed eligible Side work")
	}
	var j probe.Job
	if err := json.Unmarshal(post("claim", nil, 200), &j); err != nil || j.Identity == "" {
		t.Fatal("no Side job on private socket", err)
	}
	key := probe.Job{Identity: j.Identity, Hash: j.Hash, Token: j.Token}
	post("renew", key, 200)
	result := sidePass(t, &SideJob{Identity: j.Identity, Hash: j.Hash, Token: j.Token, Raw: j.Raw, Kind: j.Kind})
	hash := result.Evidence["candidate_sha256"]
	v := probe.Result{Identity: j.Identity, Hash: j.Hash, Token: j.Token, Version: convert.Version,
		CoreSHA256: probe.CoreSHA256, Candidate: result.Candidate, Attempt: probe.Attempt{Code: "passed",
			Core: "passed", Connection: "passed", SHA256: hash, RuntimeSHA256: hash,
			EndpointsPassed: len(sideServices), Evidence: result.Evidence}}
	v.Evidence["engine"] = "xray"
	v.Evidence["bundled_core"] = "passed"
	v.Evidence["target_core"] = "passed"
	v.Evidence["app_import_contract"] = "passed"
	v.RuntimeSHA256 = j.Hash
	post("complete", v, 422)
	v.RuntimeSHA256 = hash
	post("complete", v, 200)
	post("complete", v, 200)
	post("renew", key, 409)
	if r := post("ready", nil, 200); string(bytes.TrimSpace(r)) != "false" {
		t.Fatal("settled work advertised memory demand")
	}
	if got := post("claim", nil, 200); !bytes.Equal(bytes.TrimSpace(got), []byte("null")) {
		t.Fatal("settled identity received another Side grant")
	}
}

func TestSideWorkerDefersProviderAndCoreOutages(t *testing.T) {
	for _, code := range []string{"side_driver_unavailable", "side_provider_unavailable", "client_core_infrastructure_error", "probe_job_timeout"} {
		if !sideInfrastructure(probe.Result{Attempt: probe.Attempt{Code: code}}) {
			t.Fatal("infrastructure loss classified as service rejection", code)
		}
	}
}

func TestSideReviewSeparatesRawFailureFromPassingTemplate(t *testing.T) {
	form, checks := sideReviewChecks(map[string]string{"raw_checks": "failed", "warp": "passed", "raw_warp": "warp_not_active", "upload": "passed"})
	if form != "raw" || checks["warp"] != "warp_not_active" || checks["upload"] != "unrecorded" {
		t.Fatal("raw rejection displayed as a passed template")
	}
}
