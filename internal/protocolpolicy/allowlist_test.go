package protocolpolicy

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestMainProtocolsRequirePositiveIdentification(t *testing.T) {
	b64 := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
	ok := []string{
		"vless://id@example.com:443?type=quic",
		"trojan://passwd@example.com:443", "ss://YWVzLTEyOC1nY206YWJj@example.com:443", "wg://x@example.com:51820",
		"vmess://" + b64(`{"v":2,"add":"example.com","id":"a","port":443,"net":"tcp","type":"http"}`) + "#display",
		`{"inbounds":[{"type":"socks"},{"type":"tun"}],"outbounds":[{"type":"selector"},{"type":"urltest"},{"type":"direct"},{"type":"block"},{"type":"dns"}],"endpoints":[{"type":"wireguard","peers":[{"address":"host"}]}]}`,
		`{"outbound":{"protocol":"vless"},"outboundDetour":[{"protocol":"freedom"},{"protocol":"loopback"},{"protocol":"blackhole"}],"inbound":{"protocol":"http"}}`,
		"httpcustom://" + url.PathEscape(`{"outbounds":[{"protocol":"shadowsocks"}]}`),
		"[Interface]\nPrivateKey = foo\n[Peer]\nEndpoint = example.com:51820",
	}
	for _, s := range ok {
		v, err := DisabledReader("", strings.NewReader(s))
		if Disabled("", []byte(s)) || err != nil || v {
			t.Errorf("blocked %q %v", s, err)
		}
	}
	hidden := `{"outbounds":[{"protocol":"vless"}],"outboundDetour":[{"protocol":"hysteria2"}]}`
	for _, s := range []string{
		`{"outbounds":[{"protocol":"vless"}],"nested":{"client":{"outbounds":[{"protocol":"hysteria2"}]}}}`,
		`{"outbounds":[{"protocol":"trojan"}],"nested":{"client":{"hy2Settings":{"password":"secret"}}}}`,
		hidden, "custom://" + b64(hidden), "json://" + b64("httpcustom://"+b64(hidden)),
		"tuic://id:pw@example.com", "socks5://id@example.com", "ssr://abcd", "ssh://example.com", "http://example.com",
		"vless://id@host\nhy2://example.com", "vless://id@host?type=tcp&type=hysteria", "opaque", "json://" + b64("opaque"),
		`{"outbounds":[{"protocol":"socks"},{"protocol":"vless"}]}`,
		`{"inbounds":[{"protocol":"trojan"}],"outbounds":[{"protocol":"freedom"}]}`,
		`{"outbounds":[{"protocol":"vless"}],"outbounds":[{"protocol":"freedom"}]}`,
		`{"outbounds":[{"protocol":"vless"}],"config":"httpcustom://` + b64(hidden) + `"}`,
		`{"outbounds":[{"type":"vless"}],"endpoints":[{"type":"tailscale"}]}`,
		`{"outbounds":[{"protocol":"vless"},{"tag":"unknown"}]}`,
		`{"add":"example.com","id":"id","outbounds":[{"protocol":"blackhole"}]}`,
		"vmess://" + b64(`{"add":"e","id":"x","net":"ws","type":"tuic"}`),
		"vmess://" + b64(`{"add":"e","id":"x","outbounds":[{"protocol":"freedom"}]}`),
		`{"outbounds":[{"protocol":"vless"}]}{"outbound":{"protocol":"hysteria"}}`,
		"[Interface]\nPrivateKey=x\n[Peer]\nhy2://example.com?fm=foo",
	} {
		v, err := DisabledReader("", strings.NewReader(s))
		if !Disabled("", []byte(s)) || err != nil || !v {
			t.Errorf("unblocked %q %v", s, err)
		}
	}
}
