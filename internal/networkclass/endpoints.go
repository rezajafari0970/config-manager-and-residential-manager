package networkclass

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
)

// Endpoints reads transport destinations, never display names, TLS SNI, Host,
// DNS or routing destinations. Chained/unsupported transports fail closed.
func Endpoints(raw []byte) ([]string, error) {
	if len(raw) > 4<<20 {
		return nil, errors.New("oversized endpoint")
	}
	if protocolpolicy.Disabled("", raw) {
		return nil, errors.New(protocolpolicy.Code)
	}
	s := strings.TrimSpace(string(raw))
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "json://") {
		v := s[7:]
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if b, e := enc.DecodeString(v); e == nil {
				s = string(b)
				raw = b
				break
			}
		}
	}
	var root map[string]any
	if json.Unmarshal([]byte(s), &root) != nil {
		p := probe.Prepare(raw)
		if len(p.Candidates) == 0 {
			return nil, errors.New("unsupported endpoint")
		}
		if e := json.Unmarshal(p.Candidates[0].Config, &root); e != nil {
			return nil, e
		}
	}
	endpoints := map[string]bool{}
	bad := false
	add := func(v any) {
		h, ok := v.(string)
		h = strings.TrimSpace(h)
		if !ok || h == "" {
			bad = true
			return
		}
		if strings.ContainsAny(h, " /\\\t\r\n") {
			bad = true
			return
		}
		endpoints[strings.Trim(h, "[]")] = true
	}
	obs, ok := root["outbounds"].([]any)
	if native, yes := root["endpoints"].([]any); yes {
		obs = append(append([]any{}, obs...), native...)
		ok = true
	}
	if !ok {
		if _, ok := root["server"].(string); ok {
			obs = []any{root}
		} else {
			return nil, errors.New("missing outbounds")
		}
	}
	for _, v := range obs {
		ob, ok := v.(map[string]any)
		if !ok {
			bad = true
			continue
		}
		proto, _ := ob["protocol"].(string)
		if proto == "" {
			proto, _ = ob["type"].(string)
		}
		switch proto {
		case "freedom", "blackhole", "dns", "direct", "block":
			continue
		}
		if !protocolpolicy.AllowedProtocol(proto) {
			bad = true
			continue
		}
		if ob["proxySettings"] != nil || ob["detour"] != nil {
			bad = true
			continue
		}
		st, _ := ob["streamSettings"].(map[string]any)
		sock, _ := st["sockopt"].(map[string]any)
		if sock["dialerProxy"] != nil {
			bad = true
			continue
		}
		for _, key := range []string{"xhttpSettings", "splithttpSettings"} {
			x, _ := st[key].(map[string]any)
			extra, _ := x["extra"].(map[string]any)
			if x["downloadSettings"] != nil || extra["downloadSettings"] != nil {
				bad = true
			}
		}
		if server, ok := ob["server"]; ok {
			add(server)
			continue
		}
		if proto == "wireguard" && ob["type"] == "wireguard" {
			peers, ok := ob["peers"].([]any)
			if !ok || len(peers) == 0 {
				bad = true
			}
			for _, peer := range peers {
				p, _ := peer.(map[string]any)
				add(p["server"])
			}
			continue
		}
		settings, _ := ob["settings"].(map[string]any)
		found := false
		if address, ok := settings["address"]; ok && proto != "wireguard" {
			add(address)
			found = true
		}
		for _, key := range []string{"vnext", "servers"} {
			items, _ := settings[key].([]any)
			for _, item := range items {
				m, _ := item.(map[string]any)
				add(m["address"])
				found = true
			}
		}
		peers, _ := settings["peers"].([]any)
		for _, item := range peers {
			m, _ := item.(map[string]any)
			ep, _ := m["endpoint"].(string)
			h, _, e := net.SplitHostPort(ep)
			if e != nil {
				bad = true
			} else {
				add(h)
			}
			found = true
		}
		if !found {
			bad = true
		}
	}
	if bad || len(endpoints) == 0 || len(endpoints) > 16 {
		return nil, errors.New("ambiguous transport")
	}
	out := []string{}
	for h := range endpoints {
		out = append(out, h)
	}
	sort.Strings(out)
	return out, nil
}
