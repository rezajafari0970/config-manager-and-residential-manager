package networkclass

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type resolver map[string][]netip.Addr

func (r resolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	ips := r[host]
	if len(ips) == 0 {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	return ips, nil
}
func raw(host string) []byte {
	return []byte("vless://11111111-1111-4111-8111-111111111111@" + host + ":443?type=ws&security=tls&sni=amazon.com&host=cloudflare.com#Hetzner")
}
func fixture() (*Classifier, *atomic.Int64) {
	c := New(nil)
	c.Resolver = resolver{"mixed.test": {netip.MustParseAddr("3.1.2.3"), netip.MustParseAddr("5.9.1.2")}, "v6.test": {netip.MustParseAddr("2606:4700::1")}}
	n := new(atomic.Int64)
	c.HTTP = &http.Client{Transport: transport(func(r *http.Request) (*http.Response, error) {
		n.Add(1)
		ip := r.URL.Query().Get("resource")
		asn, prefix := "16509", "3.0.0.0/8"
		switch {
		case strings.HasPrefix(ip, "5."):
			asn, prefix = "24940", "5.0.0.0/8"
		case strings.HasPrefix(ip, "8."):
			asn, prefix = "15169", "8.0.0.0/8"
		}
		b := fmt.Sprintf(`{"status":"ok","data":{"asns":["%s"],"prefix":"%s"}}`, asn, prefix)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(b)), Header: make(http.Header)}, nil
	})}
	for _, f := range Feeds {
		values := []string{"9.9.9.9/32"}
		if f.ID == "cloudflare" {
			values = []string{"104.16.0.0/12", "2606:4700::/32"}
		}
		b, _ := json.Marshal(values)
		c.put(context.Background(), "feed/"+f.ID, Record{Data: b, Expires: time.Now().Add(time.Hour).UnixMilli(), Refresh: time.Now().Add(time.Hour).UnixMilli()})
	}
	return c, n
}
func TestEvidenceIsolationAndCache(t *testing.T) {
	c, n := fixture()
	ctx := context.Background()
	for _, tc := range []struct{ host, dc, cdn string }{{"3.1.2.3", "amazon", "none"}, {"5.9.1.2", "hetzner", "none"}, {"mixed.test", "unknown", "none"}, {"8.8.8.8", "unknown", "unknown"}, {"104.16.1.1", "unknown", "cloudflare"}, {"v6.test", "unknown", "cloudflare"}, {"missing.test", "unknown", "unknown"}, {"127.0.0.1", "unknown", "unknown"}} {
		r := c.Classify(ctx, raw(tc.host))
		if r.Datacenter != tc.dc || r.CDN != tc.cdn {
			t.Errorf("%s: %+v", tc.host, r)
		}
	}
	before := n.Load()
	c.Classify(ctx, raw("3.1.2.3"))
	if n.Load() != before {
		t.Fatal("uncached ASN request")
	}
}
func TestStaleAndConflictingEvidenceFailsClosed(t *testing.T) {
	c, _ := fixture()
	ctx := context.Background()
	c.put(ctx, "feed/cloudflare", Record{})
	r := c.Classify(ctx, raw("3.1.2.3"))
	if r.CDN != "unknown" {
		t.Fatal(r)
	}
	c, _ = fixture()
	c.HTTP = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"ok","data":{"asns":["16509","24940"],"prefix":"3.0.0.0/8"}}`))}, nil
	})}
	r = c.Classify(ctx, raw("3.1.2.3"))
	if r.Datacenter != "unknown" {
		t.Fatal(r)
	}
}
func TestEndpointDriversAndSpoofing(t *testing.T) {
	tests := []struct {
		raw  string
		host string
		ok   bool
	}{
		{string(raw("3.1.2.3")), "3.1.2.3", true},
		{`vmess://` + base64.StdEncoding.EncodeToString([]byte(`{"v":"2","add":"5.9.1.2","port":"443","id":"11111111-1111-4111-8111-111111111111","net":"ws","host":"cloudflare.com","tls":"tls"}`)), "5.9.1.2", true},
		{`hysteria://3.1.2.3:443?peer=cloudflare.com`, "3.1.2.3", true},
		{`{"dns":{"servers":["1.1.1.1"]},"outbounds":[{"type":"hysteria2","server":"5.9.1.2"},{"type":"direct"}]}`, "5.9.1.2", true},
		{`{"outbounds":[{"protocol":"wireguard","settings":{"peers":[{"endpoint":"[2606:4700::1]:443"}]}}]}`, "2606:4700::1", true},
		{`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"3.1.2.3"}]},"streamSettings":{"sockopt":{"dialerProxy":"other"}}}]}`, "", false},
		{`{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"3.1.2.3"}]},"streamSettings":{"xhttpSettings":{"extra":{"downloadSettings":{"address":"5.9.1.2"}}}}}]}`, "", false},
	}
	for _, tc := range tests {
		hosts, e := Endpoints([]byte(tc.raw))
		if (e == nil) != tc.ok || tc.ok && (len(hosts) != 1 || hosts[0] != tc.host) {
			t.Fatal(tc, hosts, e)
		}
	}
}
func TestOfficialFeedParsers(t *testing.T) {
	p, e := ParseFeed("aws", []byte(`{"prefixes":[{"ip_prefix":"3.0.0.0/8","service":"AMAZON"},{"ip_prefix":"13.32.0.0/15","service":"CLOUDFRONT"},{"ip_prefix":"1.0.0.0/8","service":"CLOUDFRONT_ORIGIN_FACING"}],"ipv6_prefixes":[{"ipv6_prefix":"2600:9000::/28","service":"CLOUDFRONT"}]}`))
	if e != nil || len(p) != 2 || p[0] != "13.32.0.0/15" {
		t.Fatal(p, e)
	}
	for _, input := range []string{"", "<html>down</html>", "0.0.0.0/0", "127.0.0.1/32"} {
		if _, e = ParseFeed("text", []byte(input)); e == nil {
			t.Fatal("invalid feed accepted")
		}
	}
}

func TestGoogleCloudRequiresServicePrefixAndGoogleASN(t *testing.T) {
	c, _ := fixture()
	ctx := context.Background()
	c.HTTP = &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"status":"ok","data":{"asns":["19527"],"prefix":"34.0.0.0/20"}}`))}, nil
	})}
	p, e := ParseFeed("google", []byte(`{"prefixes":[{"ipv4Prefix":"34.0.0.0/20","service":"Google Cloud"},{"ipv4Prefix":"8.8.8.0/24","service":"Google"}]}`))
	if e != nil || len(p) != 1 {
		t.Fatal(p, e)
	}
	b, _ := json.Marshal(p)
	c.put(ctx, "feed/google-cloud", Record{Data: b, Expires: time.Now().Add(time.Hour).UnixMilli()})
	if r := c.Classify(ctx, raw("34.0.0.1")); r.Datacenter != "google" {
		t.Fatal(r)
	}
	c.put(ctx, "feed/google-cloud", Record{})
	if r := c.Classify(ctx, raw("34.0.0.1")); r.Datacenter != "unknown" {
		t.Fatal("expired cloud source", r)
	}
}
