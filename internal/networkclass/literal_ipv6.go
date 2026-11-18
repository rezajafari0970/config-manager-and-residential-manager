package networkclass

import (
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"net/url"
	"strings"
)

var IPv6 = Group{"ipv6", "IPv6 — آدرس مستقیم"}

// LiteralIPv6 examines configured server addresses only. It performs no DNS,
// ASN or connectivity request, and never infers IPv6 from a name or SNI.
func LiteralIPv6(raw []byte) bool {
	if len(raw) > 4<<20 {
		return false
	}
	s := strings.TrimSpace(string(raw))
	u, err := url.Parse(s)
	if err == nil {
		switch strings.ToLower(u.Scheme) {
		case "vless", "trojan", "hysteria", "hy", "hysteria2", "hy2", "tuic", "wireguard", "wg", "socks", "socks5", "ss":
			if u.Scheme == "ss" && u.User == nil && !strings.ContainsAny(u.Host, ":[") {
				break // Legacy whole-URI base64 uses the existing SS decoder below.
			}
			if u.Hostname() != "" {
				return literal6(u.Hostname())
			}
		case "vmess":
			payload := strings.SplitN(s, "://", 2)[1]
			for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
				b, e := enc.DecodeString(payload)
				if e != nil {
					continue
				}
				var v struct {
					Address string `json:"add"`
				}
				if json.Unmarshal(b, &v) == nil {
					return literal6(v.Address)
				}
			}
		}
	}
	// JSON/json:// and remaining supported envelopes use the existing endpoint
	// drivers. Multiple proxy destinations must all have literal IPv6 addresses.
	hosts, err := Endpoints(raw)
	if err != nil || len(hosts) == 0 {
		return false
	}
	for _, host := range hosts {
		if !literal6(host) {
			return false
		}
	}
	return true
}

func literal6(host string) bool {
	ip, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(host), "[]"))
	return err == nil && ip.Is6() && !ip.Is4In6() && ip.Zone() == ""
}
