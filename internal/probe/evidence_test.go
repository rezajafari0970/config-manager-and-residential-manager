package probe

import "testing"

func TestAuthenticatedHTTP3IsIndependentQUICEvidence(t *testing.T) {
	e := map[string]string{}
	for _, k := range []string{"https", "dns_tcp", "dns_udp", "doh_cloudflare", "doh_google", "target_core", "bundled_core", "app_import_contract"} {
		e[k] = "passed"
	}
	e["quic_vn"] = "failed"
	if VerifiedEvidence(e) {
		t.Fatal("missing QUIC evidence accepted")
	}
	e["http3"] = "passed"
	if !VerifiedEvidence(e) {
		t.Fatal("actual HTTP3 ignored because VN was unavailable")
	}
	e["dns_udp"] = "failed"
	if VerifiedEvidence(e) {
		t.Fatal("HTTP3 hid failed DNS")
	}
}
