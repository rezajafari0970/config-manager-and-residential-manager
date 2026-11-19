package protocolpolicy

import (
	"encoding/base64"
	"io"
	"net/url"
	"strings"
	"testing"
)

func TestHysteriaPolicyAcrossRepresentations(t *testing.T) {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	mixed := `{"outbounds":[{"protocol":"vmess"},{"protocol":"hyStEria","settings":{"version":2}}]}`
	late := `{"remarks":"` + strings.Repeat("x", 2*1024*1024) + `","outbounds":[{"type":"hy2"}]}`
	for _, raw := range []string{
		" hy://host:443 ", "HYSTERIA1://host", "HY1://host", "hy2://host", "HYSTERIA2://host",
		mixed, late, `{"outbounds":[{"type":"hysteria2"}]}`, `{"proxies":[{"type":"hysteria"}]}`,
		`{"outbound":{"protocol":"hysteria"}}`,
		`{"outbounds":[{"settings":{"address":"host",},"protocol":"hysteria"}]}`,
		`{"outbounds":[{"protocol":"vless","streamSettings":{"network":"hysteria"}}]}`,
		`{"outbounds":[{"protocol":"vless","streamSettings":{"method":"HY2"}}]}`,
		`{"streamSettings":{"network":"xhttp","xhttpSettings":{"extra":{"downloadSettings":{"network":"hysteria"}}}}}`,
		`{"outbounds":[{"typ\u0065":"\u0068\u0079\u0032"}]}`,
		"vless://user@host?type=%68ysteria", "vmess://" + b64(`{"net":"hysteria","ps":"local"}`),
		"json://" + b64(mixed), "custom://" + url.PathEscape(mixed), "napsternet://" + b64("json://"+b64(mixed)),
		`["vless://u@host", "hy2://host"]`,
	} {
		fromReader, err := DisabledReader("", strings.NewReader(raw))
		if err != nil || !fromReader || !Disabled("", []byte(raw)) {
			t.Errorf("missed disabled record %.90q (reader=%v, err=%v)", raw, fromReader, err)
		}
	}
	for _, raw := range []string{
		"vless://user@host?type=tcp#hy2", "trojan://hysteria@hy2.example:443",
		"vless://user@host?path=hysteria", "wireguard://key@host:2000",
		"vmess://" + b64(`{"net":"ws","ps":"hysteria2"}`),
		`{"remarks":"hysteria2","outbounds":[{"protocol":"trojan","tag":"hy","streamSettings":{"network":"tcp","hysteriaSettings":{"version":2}}}]}`,
		`{"outbounds":[{"protocol":"vless","streamSettings":{"wsSettings":{"headers":{"type":"hysteria"}}}}],"routing":{"rules":[{"outboundTag":"hy2"}]}}`,
		`{"outbounds":[{"protocol":"shadowsocks","settings":{"method":"hysteria"}}]}`,
	} {
		found, err := DisabledReader("", strings.NewReader(raw))
		if err != nil || found || Disabled("", []byte(raw)) {
			t.Errorf("false positive %.90q (reader=%v, err=%v)", raw, found, err)
		}
	}
	if found, err := DisabledReader("hY1", io.LimitReader(nil, 0)); err != nil || !found {
		t.Fatalf("explicit kind lost: %v %v", found, err)
	}
}
