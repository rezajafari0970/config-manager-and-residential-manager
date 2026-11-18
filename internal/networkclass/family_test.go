package networkclass

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestAddressFamiliesUseOnlyEntryEndpoints(t *testing.T) {
	c, calls := fixture()
	c.Resolver = resolver{
		"dual.test": {netip.MustParseAddr("3.1.2.3"), netip.MustParseAddr("2606:4700::1")},
		"v6.test":   {netip.MustParseAddr("2606:4700::1")},
	}
	jsonV6 := `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"2606:4700::1"}]}}]}`
	for _, tc := range []struct{ name, raw, want, reason string }{
		{"v6_literal", string(raw("[2606:4700::1]")), "ipv6", "literal_endpoints"},
		{"v4_literal", string(raw("3.1.2.3")), "ipv4", "literal_endpoints"},
		{"mapped_v4", string(raw("[::ffff:3.1.2.3]")), "ipv4", "literal_endpoints"},
		{"v6_dns", string(raw("v6.test")), "ipv6", "dns_snapshot"},
		{"dual_dns", string(raw("dual.test")), "dual", "dns_snapshot"},
		{"missing_dns", string(raw("missing.test")), "unknown", "dns_unresolved"},
		{"json_v6", jsonV6, "ipv6", "literal_endpoints"},
		{"json_envelope", "json://" + base64.RawURLEncoding.EncodeToString([]byte(jsonV6)), "ipv6", "literal_endpoints"},
		{"hysteria1", "hysteria://[2606:4700::1]:443?peer=3.1.2.3", "ipv6", "literal_endpoints"},
		{"hysteria2_native", `{"outbounds":[{"type":"hysteria2","server":"2606:4700::1"},{"type":"direct"}]}`, "ipv6", "literal_endpoints"},
		{"wireguard_xray", `{"outbounds":[{"protocol":"wireguard","settings":{"address":["10.0.0.2/32"],"peers":[{"endpoint":"[2606:4700::1]:443"}]}}]}`, "ipv6", "literal_endpoints"},
		{"wireguard_native", `{"endpoints":[{"type":"wireguard","address":["10.0.0.2/32"],"peers":[{"server":"2606:4700::1","server_port":443}]}]}`, "ipv6", "literal_endpoints"},
		{"multiple_families", `{"outbounds":[{"type":"hysteria2","server":"2606:4700::1"},{"type":"trojan","server":"3.1.2.3"}]}`, "dual", "literal_endpoints"},
		{"dns_inbound_and_sni_ignored", `{"dns":{"servers":["2606:4700::1111"]},"inbounds":[{"listen":"::"}],"outbounds":[{"type":"trojan","server":"3.1.2.3","tls":{"server_name":"2606:4700::1"}}]}`, "ipv4", "literal_endpoints"},
		{"partial_resolution", `{"outbounds":[{"type":"trojan","server":"2606:4700::1"},{"type":"trojan","server":"missing.test"}]}`, "unknown", "dns_unresolved"},
		{"chained", `{"outbounds":[{"type":"trojan","server":"2606:4700::1","detour":"other"}]}`, "unknown", "endpoint_unresolved"},
		{"unsupported", "not-a-config", "unknown", "endpoint_unresolved"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := c.ClassifyFamily(context.Background(), []byte(tc.raw))
			if f.ID != tc.want || f.Reason != tc.reason || f.Current(time.Now().UnixMilli()) != tc.want {
				t.Fatal(f)
			}
			if f.Reason == "dns_snapshot" && f.Current(f.Expires) != "unknown" {
				t.Fatal("expired DNS retained its family")
			}
			if f.Reason == "literal_endpoints" && f.Current(time.Now().Add(48*time.Hour).UnixMilli()) != tc.want {
				t.Fatal("immutable literal family expired")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("family classification fetched ASN/CDN data")
	}
}

func TestAddressFamilySurvivesProviderFailure(t *testing.T) {
	c, _ := fixture()
	for _, f := range Feeds {
		c.put(context.Background(), "feed/"+f.ID, Record{})
	}
	r := c.Classify(context.Background(), raw("[2606:4700::1]"))
	if r.Datacenter != "unknown" || r.Family.ID != "ipv6" || strings.Contains(r.Family.Reason, "dns") {
		t.Fatal(r)
	}
}
