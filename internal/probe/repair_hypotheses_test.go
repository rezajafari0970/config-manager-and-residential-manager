package probe

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestMisplacedVMessSecurityRequiresIndependentHypotheses(t *testing.T) {
	raw := []byte("vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"192.0.2.1","port":443,"id":"synthetic","net":"ws","tls":"auto","scy":"aes-128-gcm","sni":"example.com"}`)))
	original := bytes.Clone(raw)
	p := Prepare(raw)
	if p.Code != "prepared" || p.RawIssue != AmbiguousVMessTransport || len(p.Candidates) != 2 || !bytes.Equal(raw, original) {
		t.Fatal(p.Code)
	}
	for i, c := range p.Candidates {
		if !c.RequiresConnection || !strings.Contains(c.Rule, "hypothesis") {
			t.Fatal("unearned repair")
		}
		var m M
		json.Unmarshal(c.Config, &m)
		in := m["inbounds"].([]any)
		if len(in) != 1 {
			t.Fatal("diagnostic listener count")
		}
		socks := in[0].(M)
		if socks["listen"] != "127.0.0.1" || socks["protocol"] != "socks" || socks["port"] != float64(10808) || socks["settings"].(M)["auth"] != "noauth" {
			t.Fatal("incompatible diagnostic listener")
		}
		ob := m["outbounds"].([]any)[0].(M)
		if ob["settings"].(M)["security"] != "aes-128-gcm" || ob["settings"].(M)["id"] != "synthetic" {
			t.Fatal("credentials/cipher changed")
		}
		want := []string{"tls", "none"}[i]
		if ob["streamSettings"].(M)["security"] != want {
			t.Fatal("TLS hypothesis lost")
		}
	}
}
func TestDecodeNestedJSONEnvelopeAndDepth(t *testing.T) {
	original := []byte(`{"outbounds":[{"protocol":"trojan","settings":{"password":"exact-secret"}}]}`)
	quoted, _ := json.Marshal(string(original))
	wrapped := []byte("json://" + base64.StdEncoding.EncodeToString(quoted))
	b, e := DecodeEnvelope(wrapped)
	if e != nil || !bytes.Equal(b, original) {
		t.Fatal("quoted base64 JSON", e)
	}
	b = original
	for i := 0; i < 8; i++ {
		b = []byte(base64.StdEncoding.EncodeToString(b))
	}
	if _, e = DecodeEnvelope(b); e == nil {
		t.Fatal("unbounded nested decoder")
	}
	if _, e = DecodeEnvelope([]byte("json://not-an-encrypted-key")); e == nil {
		t.Fatal("unknown encryption guessed")
	}
}
