// Package networkclass classifies the observable entry network, never a hidden
// origin or proxy exit. Drivers are replaceable and failures fail to unknown.
package networkclass

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var Datacenters = []Group{{"amazon", "Amazon AWS"}, {"hetzner", "Hetzner"}, {"digitalocean", "DigitalOcean"}, {"ovh", "OVHcloud"}, {"google", "Google Cloud"}, {"microsoft", "Microsoft Azure"}, {"oracle", "Oracle Cloud"}, {"vultr", "Vultr"}, {"linode", "Akamai Linode"}, {"scaleway", "Scaleway"}, {"unknown", "ناشناس"}}
var CDNs = []Group{{"cloudflare", "Cloudflare"}, {"cloudfront", "Amazon CloudFront"}, {"fastly", "Fastly"}, {"bunny", "Bunny.net"}, {"arvan", "ArvanCloud"}, {"none", "Non-CDN — CDN شناخته‌شده یافت نشد"}, {"unknown", "CDN نامشخص"}}
var providers = map[int]string{16509: "amazon", 14618: "amazon", 8987: "amazon", 24940: "hetzner", 213230: "hetzner", 212317: "hetzner", 215859: "hetzner", 14061: "digitalocean", 16276: "ovh", 396982: "google", 8075: "microsoft", 31898: "oracle", 20473: "vultr", 63949: "linode", 12876: "scaleway"}

// Networks that may host CDN edges outside the five positive-match feeds.
// They cannot be positively labeled Non-CDN just because a feed did not match.
var cdnASNs = map[int]bool{13335: true, 54113: true, 20940: true, 16625: true, 199524: true, 202306: true, 205718: true, 203020: true, 60068: true, 209242: true}

func ValidGroup(axis, id string) bool {
	list := Datacenters
	if axis == "cdn" {
		list = CDNs
	} else if axis == "ip-family" {
		list = IPFamilies
	} else if axis != "datacenter" {
		return false
	}
	for _, g := range list {
		if g.ID == id {
			return true
		}
	}
	return false
}

type Result struct {
	Family     AddressFamily `json:"ip_family"`
	Datacenter string        `json:"datacenter"`
	CDN        string        `json:"cdn"`
	Reason     string        `json:"reason"`
	Evidence   []Evidence    `json:"evidence"`
	Checked    int64         `json:"checked"`
	Expires    int64         `json:"expires"`
}
type Evidence struct {
	IP     string `json:"ip"`
	Prefix string `json:"prefix,omitempty"`
	ASNs   []int  `json:"asns,omitempty"`
	CDN    string `json:"cdn,omitempty"`
}
type Record struct {
	Data    json.RawMessage `json:"data"`
	Expires int64           `json:"expires"`
	Refresh int64           `json:"refresh"`
}
type Cache interface {
	Get(context.Context, string) (Record, error)
	Put(context.Context, string, Record) error
}
type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Classifier struct {
	Cache    Cache
	HTTP     *http.Client
	Resolver Resolver
	mu       sync.Mutex
	memory   map[string]Record
}

func New(cache Cache) *Classifier {
	return &Classifier{Cache: cache, HTTP: &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 2 || r.URL.Scheme != "https" || r.URL.Host != via[0].URL.Host {
			return errors.New("untrusted redirect")
		}
		return nil
	}}, Resolver: net.DefaultResolver, memory: map[string]Record{}}
}
func (c *Classifier) get(ctx context.Context, key string) Record {
	c.mu.Lock()
	r, ok := c.memory[key]
	c.mu.Unlock()
	if ok {
		return r
	}
	if c.Cache != nil {
		r, _ = c.Cache.Get(ctx, key)
	}
	return r
}
func (c *Classifier) put(ctx context.Context, key string, r Record) {
	c.mu.Lock()
	if len(c.memory) >= 4096 {
		c.memory = map[string]Record{}
	}
	c.memory[key] = r
	c.mu.Unlock()
	if c.Cache != nil {
		_ = c.Cache.Put(ctx, key, r)
	}
}
func (c *Classifier) fetch(ctx context.Context, url string) ([]byte, error) {
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return nil, e
	}
	req.Header.Set("User-Agent", "ConfigManager-Network/1")
	res, e := c.HTTP.Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("feed unavailable")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, 16<<20+1))
	if len(b) > 16<<20 {
		return nil, errors.New("feed size limit")
	}
	return b, e
}

type Feed struct {
	ID     string
	URLs   []string
	Format string
}

var Feeds = []Feed{
	{"cloudflare", []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"}, "text"},
	{"cloudfront", []string{"https://ip-ranges.amazonaws.com/ip-ranges.json"}, "aws"},
	{"fastly", []string{"https://api.fastly.com/public-ip-list"}, "fastly"},
	{"bunny", []string{"https://api.bunny.net/system/edgeserverlist", "https://api.bunny.net/system/edgeserverlist/ipv6"}, "array"},
	{"arvan", []string{"https://www.arvancloud.ir/fa/ips.txt"}, "text"},
}

var CloudFeeds = []Feed{{"google-cloud", []string{"https://www.gstatic.com/ipranges/cloud.json"}, "google"}}

func AllFeeds() []Feed { return append(append([]Feed{}, Feeds...), CloudFeeds...) }
func ParseFeed(format string, b []byte) ([]string, error) {
	var values []string
	switch format {
	case "text":
		values = strings.Fields(string(b))
	case "array":
		if e := json.Unmarshal(b, &values); e != nil {
			return nil, e
		}
	case "fastly":
		var v struct {
			V4 []string `json:"addresses"`
			V6 []string `json:"ipv6_addresses"`
		}
		if e := json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		values = append(v.V4, v.V6...)
	case "google":
		var v struct {
			Prefixes []struct {
				V4      string `json:"ipv4Prefix"`
				V6      string `json:"ipv6Prefix"`
				Service string `json:"service"`
			} `json:"prefixes"`
		}
		if e := json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		for _, p := range v.Prefixes {
			if p.Service == "Google Cloud" {
				if p.V4 != "" {
					values = append(values, p.V4)
				}
				if p.V6 != "" {
					values = append(values, p.V6)
				}
			}
		}
	case "aws":
		var v struct {
			V4 []struct {
				Prefix  string `json:"ip_prefix"`
				Service string `json:"service"`
			} `json:"prefixes"`
			V6 []struct {
				Prefix  string `json:"ipv6_prefix"`
				Service string `json:"service"`
			} `json:"ipv6_prefixes"`
		}
		if e := json.Unmarshal(b, &v); e != nil {
			return nil, e
		}
		for _, p := range v.V4 {
			if p.Service == "CLOUDFRONT" {
				values = append(values, p.Prefix)
			}
		}
		for _, p := range v.V6 {
			if p.Service == "CLOUDFRONT" {
				values = append(values, p.Prefix)
			}
		}
	default:
		return nil, errors.New("unknown feed driver")
	}
	if len(values) == 0 || len(values) > 100000 {
		return nil, errors.New("empty or oversized feed")
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		p, e := netip.ParsePrefix(v)
		if e != nil {
			ip, err := netip.ParseAddr(v)
			if err != nil {
				return nil, errors.New("invalid edge prefix")
			}
			p = netip.PrefixFrom(ip, ip.BitLen())
		}
		if p.Bits() < 8 || !Public(p.Addr()) {
			return nil, errors.New("unsafe edge prefix")
		}
		out = append(out, p.Masked().String())
	}
	return out, nil
}

// Refresh keeps a bounded last-good snapshot on transient failures. Failed or
// expired feeds never turn into an authoritative empty list.
func (c *Classifier) Refresh(ctx context.Context) {
	for _, f := range AllFeeds() {
		if ctx.Err() != nil {
			return
		}
		key := "feed/" + f.ID
		r := c.get(ctx, key)
		now := time.Now()
		if r.Refresh > now.UnixMilli() {
			continue
		}
		values := []string{}
		ok := true
		for _, url := range f.URLs {
			b, e := c.fetch(ctx, url)
			if e != nil {
				ok = false
				break
			}
			v, e := ParseFeed(f.Format, b)
			if e != nil {
				ok = false
				break
			}
			values = append(values, v...)
		}
		r.Refresh = now.Add(5 * time.Minute).UnixMilli()
		if ok {
			r.Data, _ = json.Marshal(values)
			r.Expires = now.Add(24 * time.Hour).UnixMilli()
			r.Refresh = now.Add(6 * time.Hour).UnixMilli()
		}
		c.put(ctx, key, r)
	}
}
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, s := range []string{"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32", "2001::/32", "2002::/16", "64:ff9b::/96"} {
		if netip.MustParsePrefix(s).Contains(ip) {
			return false
		}
	}
	return true
}
func (c *Classifier) addresses(ctx context.Context, host string) ([]netip.Addr, int64, error) {
	if ip, e := netip.ParseAddr(host); e == nil {
		return []netip.Addr{ip.Unmap()}, time.Now().Add(time.Hour).UnixMilli(), nil
	}
	key := "dns/" + host
	r := c.get(ctx, key)
	now := time.Now()
	if r.Expires > now.UnixMilli() {
		var ips []netip.Addr
		if json.Unmarshal(r.Data, &ips) == nil && len(ips) > 0 {
			return ips, r.Expires, nil
		}
		return nil, 0, errors.New("DNS unavailable")
	}
	sub, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ips, e := c.Resolver.LookupNetIP(sub, "ip", host)
	ttl := 5 * time.Minute
	if e != nil || len(ips) == 0 || len(ips) > 32 {
		ips = nil
		ttl = 30 * time.Second
		e = errors.New("DNS unavailable")
	}
	r.Data, _ = json.Marshal(ips)
	r.Expires = now.Add(ttl).UnixMilli()
	c.put(ctx, key, r)
	return ips, r.Expires, e
}
func (c *Classifier) asn(ctx context.Context, ip netip.Addr) (Evidence, int64, error) {
	key := "asn/" + ip.String()
	r := c.get(ctx, key)
	now := time.Now()
	if r.Expires <= now.UnixMilli() {
		b, e := c.fetch(ctx, "https://stat.ripe.net/data/network-info/data.json?resource="+ip.String())
		var body struct {
			Status string `json:"status"`
			Data   struct {
				ASNs   []string `json:"asns"`
				Prefix string   `json:"prefix"`
			} `json:"data"`
		}
		ev := Evidence{IP: ip.String()}
		ok := e == nil && json.Unmarshal(b, &body) == nil && body.Status == "ok"
		p, err := netip.ParsePrefix(body.Data.Prefix)
		ok = ok && err == nil && p.Contains(ip) && len(body.Data.ASNs) > 0 && len(body.Data.ASNs) <= 16
		if ok {
			ev.Prefix = p.String()
			for _, a := range body.Data.ASNs {
				n, e := strconv.Atoi(a)
				if e != nil || n < 1 {
					ok = false
					break
				}
				ev.ASNs = append(ev.ASNs, n)
			}
		}
		ttl := time.Minute
		if ok {
			ttl = 6 * time.Hour
			r.Data, _ = json.Marshal(ev)
		} else {
			r.Data = nil
		}
		r.Expires = now.Add(ttl).UnixMilli()
		c.put(ctx, key, r)
	}
	var ev Evidence
	if json.Unmarshal(r.Data, &ev) != nil || len(ev.ASNs) == 0 {
		return ev, r.Expires, errors.New("ASN unavailable")
	}
	return ev, r.Expires, nil
}
func (c *Classifier) Classify(ctx context.Context, raw []byte) Result {
	now := time.Now()
	r := Result{Datacenter: "unknown", CDN: "unknown", Reason: "endpoint_unresolved", Checked: now.UnixMilli(), Expires: now.Add(time.Minute).UnixMilli(), Evidence: []Evidence{}}
	hosts, e := Endpoints(raw)
	if e != nil {
		r.Family = AddressFamily{ID: "unknown", Reason: "endpoint_unresolved", Expires: r.Expires}
		return r
	}
	// Address family uses the same cached DNS answers, independently of ASN/CDN
	// feed availability. Literal families do not expire with provider metadata.
	r.Family = c.classifyFamilyHosts(ctx, hosts)
	r.Expires = now.Add(time.Hour).UnixMilli()
	allFeeds := true
	prefixes := map[string][]netip.Prefix{}
	for _, f := range Feeds {
		rec := c.get(ctx, "feed/"+f.ID)
		if rec.Expires <= now.UnixMilli() {
			allFeeds = false
			continue
		}
		r.Expires = min(r.Expires, rec.Expires)
		var vals []string
		if json.Unmarshal(rec.Data, &vals) != nil || len(vals) == 0 {
			allFeeds = false
			continue
		}
		for _, v := range vals {
			p, e := netip.ParsePrefix(v)
			if e == nil {
				prefixes[f.ID] = append(prefixes[f.ID], p)
			}
		}
	}
	dc, cdn := "", ""
	seen := map[netip.Addr]bool{}
	for _, host := range hosts {
		ips, until, err := c.addresses(ctx, host)
		if err != nil {
			r.Reason = "dns_unresolved"
			r.Expires = now.Add(time.Minute).UnixMilli()
			return r
		}
		r.Expires = min(r.Expires, until)
		for _, ip := range ips {
			ip = ip.Unmap()
			if seen[ip] {
				continue
			}
			seen[ip] = true
			if !Public(ip) || len(seen) > 64 {
				r.Reason = "nonpublic_or_complex_endpoint"
				return r
			}
			edge := ""
			for id, ps := range prefixes {
				for _, p := range ps {
					if p.Contains(ip) {
						if edge != "" && edge != id {
							r.Reason = "conflicting_cdn_evidence"
							return r
						}
						edge = id
						break
					}
				}
			}
			ev := Evidence{IP: ip.String(), CDN: edge}
			d, n := "unknown", "unknown"
			if edge != "" {
				n = edge
			} else {
				v, expiry, err := c.asn(ctx, ip)
				r.Expires = min(r.Expires, expiry)
				if err == nil {
					ev = v
					d = ""
					possibleCDN := false
					for _, a := range ev.ASNs {
						provider := providers[a]
						if a == 396982 || a == 19527 || a == 139070 || a == 15169 {
							provider = ""
							rec := c.get(ctx, "feed/google-cloud")
							if rec.Expires > now.UnixMilli() {
								var ps []string
								if json.Unmarshal(rec.Data, &ps) == nil {
									for _, v := range ps {
										p, err := netip.ParsePrefix(v)
										if err == nil && p.Contains(ip) {
											provider = "google"
											r.Expires = min(r.Expires, rec.Expires)
											break
										}
									}
								}
							}
						}
						if provider == "" {
							provider = "unknown"
						}
						if d == "" {
							d = provider
						} else if d != provider {
							d = "unknown"
						}
						possibleCDN = possibleCDN || cdnASNs[a]
					}
					if !allFeeds || possibleCDN {
						d = "unknown"
					}
					if allFeeds && d != "unknown" && !possibleCDN {
						n = "none"
					}
				}
			}
			r.Evidence = append(r.Evidence, ev)
			if dc == "" {
				dc = d
			} else if dc != d {
				dc = "unknown"
			}
			if cdn == "" {
				cdn = n
			} else if cdn != n {
				cdn = "unknown"
			}
		}
	}
	if len(seen) == 0 {
		return r
	}
	r.Datacenter = dc
	r.CDN = cdn
	r.Reason = "entry_network_snapshot"
	if cdn != "none" && cdn != "unknown" {
		r.Datacenter = "unknown"
		r.Reason = "cdn_origin_hidden"
	}
	sort.Slice(r.Evidence, func(i, j int) bool { return r.Evidence[i].IP < r.Evidence[j].IP })
	return r
}
