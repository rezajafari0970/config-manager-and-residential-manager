package networkclass

import (
	"context"
	"net/netip"
	"time"
)

var IPFamilies = []Group{{"ipv6", "IPv6"}, {"dual", "IPv4 + IPv6 — دوپشته"}, {"ipv4", "IPv4"}, {"unknown", "نسخهٔ IP نامشخص"}}

// AddressFamily describes configured entry destinations, not the client's
// chosen socket, proxy exit, DNS server, SNI or ability to carry IPv6 traffic.
type AddressFamily struct {
	ID      string `json:"id"`
	Reason  string `json:"reason"`
	Expires int64  `json:"expires"` // Zero only for immutable literal endpoints.
}

func (f AddressFamily) Current(now int64) string {
	if !ValidGroup("ip-family", f.ID) || f.ID == "unknown" {
		return "unknown"
	}
	if f.Reason == "literal_endpoints" || f.Reason == "dns_snapshot" && f.Expires > now {
		return f.ID
	}
	return "unknown"
}

func (c *Classifier) ClassifyFamily(ctx context.Context, raw []byte) AddressFamily {
	hosts, err := Endpoints(raw)
	if err != nil {
		return AddressFamily{ID: "unknown", Reason: "endpoint_unresolved", Expires: time.Now().Add(time.Minute).UnixMilli()}
	}
	return c.classifyFamilyHosts(ctx, hosts)
}

func (c *Classifier) classifyFamilyHosts(ctx context.Context, hosts []string) AddressFamily {
	f := AddressFamily{ID: "unknown", Reason: "literal_endpoints"}
	v4, v6 := false, false
	for _, host := range hosts {
		ips, until, err := c.addresses(ctx, host)
		if err != nil || len(ips) == 0 {
			return AddressFamily{ID: "unknown", Reason: "dns_unresolved", Expires: time.Now().Add(30 * time.Second).UnixMilli()}
		}
		if _, err := netip.ParseAddr(host); err != nil {
			f.Reason = "dns_snapshot"
			if f.Expires == 0 || until < f.Expires {
				f.Expires = until
			}
		}
		for _, ip := range ips {
			if !ip.IsValid() || ip.Zone() != "" {
				return AddressFamily{ID: "unknown", Reason: "ambiguous_address", Expires: time.Now().Add(time.Minute).UnixMilli()}
			}
			ip = ip.Unmap()
			v4 = v4 || ip.Is4()
			v6 = v6 || ip.Is6()
		}
	}
	switch {
	case v4 && v6:
		f.ID = "dual"
	case v6:
		f.ID = "ipv6"
	case v4:
		f.ID = "ipv4"
	}
	return f
}
