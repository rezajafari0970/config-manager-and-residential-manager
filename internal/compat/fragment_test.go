package compat

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestFragmentRelayPreservesMaskAndLogicalRoundTrip(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "httpupgrade", "grpc", "xhttp"} {
		m := root(t)
		stream := m["outbounds"].([]any)[0].(M)["streamSettings"].(M)
		stream["network"] = network
		mask := M{"tcp": []any{M{"type": "fragment", "settings": M{"packets": "1-1", "lengths": []any{"1"}, "delays": []any{"4"}, "maxSplit": "355"}}}}
		stream["finalmask"] = mask
		before, _ := json.Marshal(mask)
		if _, err := Wrap(m); err != nil {
			t.Fatal(network, err)
		}
		after, _ := json.Marshal(stream["finalmask"])
		if !bytes.Equal(before, after) {
			t.Fatal("mask changed")
		}
		first, _ := json.Marshal(m)
		if _, err := Wrap(m); err != nil {
			t.Fatal(err)
		}
		second, _ := json.Marshal(m)
		if !bytes.Equal(first, second) {
			t.Fatal("not idempotent")
		}
		if _, err := Logical(m); err != nil {
			t.Fatal(err)
		}
		ep, _ := getEndpoint(m["outbounds"].([]any)[0].(M))
		if ep.host != "203.0.113.81" || ep.port != 24443 {
			t.Fatal("destination changed")
		}
		after, _ = json.Marshal(stream["finalmask"])
		if !bytes.Equal(before, after) {
			t.Fatal("logical mask changed")
		}
	}
}

func TestUnknownMaskAndDestinationOverridesStillRequireDriver(t *testing.T) {
	for _, mask := range []any{nil, M{"tcp": []any{M{"type": "xdns"}}}, M{"udp": []any{}}, M{"future": true}} {
		m := root(t)
		m["outbounds"].([]any)[0].(M)["streamSettings"].(M)["finalmask"] = mask
		if _, err := Wrap(m); err == nil {
			t.Fatal("unknown mask accepted")
		}
	}
	for _, key := range []string{"address", "port"} {
		m := root(t)
		m["outbounds"].([]any)[0].(M)["streamSettings"].(M)[key] = "override"
		if _, err := Wrap(m); err == nil {
			t.Fatal("override lost")
		}
	}
}

func TestEmptyHTTPHostRepairPreservesExplicitHost(t *testing.T) {
	for _, value := range []any{nil, []any{}, []any{"keep.example"}} {
		m := root(t)
		headers := m["outbounds"].([]any)[0].(M)["streamSettings"].(M)["tcpSettings"].(M)["header"].(M)["request"].(M)["headers"].(M)
		headers["Host"] = value
		_, err := Wrap(m)
		if err != nil {
			t.Fatal(err)
		}
		if list, ok := value.([]any); ok && len(list) > 0 {
			if headers["Host"].([]any)[0] != "keep.example" {
				t.Fatal("explicit host changed")
			}
		} else if _, ok := headers["Host"]; ok {
			t.Fatal("absent host retained")
		}
	}
}
