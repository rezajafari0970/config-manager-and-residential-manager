package networkclass

import (
	"encoding/base64"
	"testing"
)

func TestLiteralIPv6ConfiguredAddressOnly(t *testing.T) {
	cases := []struct {
		name, raw string
		want      bool
	}{
		{"vless", "vless://bad-id@[2001:db8::1]:443?security=none", true},
		{"ipv4", "vless://id@192.0.2.1:443?sni=2001:db8::1#ipv6", false},
		{"domain_even_with_aaaa", "vless://id@ipv6.google.com:443", false},
		{"placeholder_is_not_ip", "vless://id@ipv6:446", false},
		{"mapped_v4", "vless://id@[::ffff:192.0.2.1]:443", false},
		{"invalid", "vless://id@[2001:db8::zz]:443", false},
		{"vmess", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"2001:db8::2","port":"443","id":"bad"}`)), true},
		{"vmess_domain", "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"ipv6.google.com","sni":"2001:db8::2"}`)), false},
		{"hysteria1", "hysteria://[2001:db8::1]:443?auth=x", true},
		{"hysteria2", "hy2://key@[2001:db8::1]:443", true},
		{"ss", "ss://YWVzLTEyOC1nY206eA@[2001:db8::1]:8388", true},
		{"wg", "wireguard://key@[2001:db8::1]:51820", true},
		{"xray", `{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"2001:db8::1"}]}}]}`, true},
		{"native", `{"outbounds":[{"type":"hysteria2","server":"2001:db8::1"}]}`, true},
		{"native_wg", `{"endpoints":[{"type":"wireguard","address":["10.0.0.1/32"],"peers":[{"server":"2001:db8::1"}]}]}`, true},
		{"wg_interface_is_not_server", `{"outbounds":[{"protocol":"wireguard","settings":{"address":["2001:db8::1/128"],"peers":[{"endpoint":"192.0.2.1:51820"}]}}]}`, false},
		{"wg_peer", `{"outbounds":[{"protocol":"wireguard","settings":{"address":["10.0.0.1/32"],"peers":[{"endpoint":"[2001:db8::1]:51820"}]}}]}`, true},
		{"dns_inbound_sni_ignored", `{"dns":{"servers":["2001:db8::1"]},"inbounds":[{"listen":"::"}],"outbounds":[{"type":"vless","server":"example.com","tls":{"server_name":"2001:db8::1"}}]}`, false},
		{"mixed_profile", `{"outbounds":[{"type":"vless","server":"2001:db8::1"},{"type":"trojan","server":"192.0.2.1"}]}`, false},
		{"json_envelope", "json://" + base64.StdEncoding.EncodeToString([]byte(`{"outbounds":[{"type":"vless","server":"2001:db8::1"}]}`)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LiteralIPv6([]byte(c.raw)); got != c.want {
				t.Fatalf("got %v want %v", got, c.want)
			}
		})
	}
	if ValidGroup("ip-family", "ipv6") || ValidGroup("address", "ipv4") || !ValidGroup("address", "ipv6") {
		t.Fatal("retired scope accepted")
	}
}
