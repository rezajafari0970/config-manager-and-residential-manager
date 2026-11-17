package native

import (
	"encoding/json"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
	"net"
	"strconv"
	"strings"
)

func wireguard(raw []byte) (probe.Plan, bool) {
	s := strings.ToLower(strings.TrimSpace(string(raw)))
	if !strings.HasPrefix(s, "wireguard://") && !strings.HasPrefix(s, "wg://") && !strings.HasPrefix(s, "[interface]") {
		return probe.Plan{}, false
	}
	p := probe.Prepare(raw)
	p.Target = NativeID
	if len(p.Candidates) == 0 {
		return p, true
	}
	var root map[string]any
	json.Unmarshal(p.Candidates[0].Config, &root)
	obs, _ := root["outbounds"].([]any)
	if len(obs) != 1 {
		p.Code = "wireguard_native_mapping_unsupported"
		p.Candidates = nil
		return p, true
	}
	ob := obs[0].(map[string]any)
	settings := ob["settings"].(map[string]any)
	if ob["streamSettings"] != nil {
		p.Code = "wireguard_native_finalmask_unsupported"
		p.Candidates = nil
		return p, true
	}
	endpoint := map[string]any{"type": "wireguard", "tag": "proxy", "system": false, "name": "", "address": settings["address"], "private_key": settings["secretKey"], "workers": 1}
	if v := settings["mtu"]; v != nil {
		endpoint["mtu"] = v
	}
	peers := []any{}
	for _, v := range settings["peers"].([]any) {
		old := v.(map[string]any)
		host, port, e := net.SplitHostPort(old["endpoint"].(string))
		if e != nil {
			p.Code = "wireguard_endpoint_invalid"
			p.Candidates = nil
			return p, true
		}
		n, _ := strconv.Atoi(port)
		peer := map[string]any{"address": host, "port": n, "public_key": old["publicKey"], "allowed_ips": []string{"0.0.0.0/0", "::/0"}}
		for from, to := range map[string]string{"preSharedKey": "pre_shared_key", "allowedIPs": "allowed_ips", "keepAlive": "persistent_keepalive_interval"} {
			if v := old[from]; v != nil {
				peer[to] = v
			}
		}
		if v := settings["reserved"]; v != nil {
			peer["reserved"] = v
		}
		peers = append(peers, peer)
	}
	endpoint["peers"] = peers
	originalDNS := root["dns"]
	root = map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": 10808}}, "endpoints": []any{endpoint}, "route": map[string]any{"final": "proxy"}}
	if dns, ok := originalDNS.(map[string]any); ok {
		if servers, ok := dns["servers"].([]any); ok {
			mapped := []any{}
			for i, v := range servers {
				ip, ok := v.(string)
				if !ok || net.ParseIP(ip) == nil {
					p.Code = "wireguard_dns_mapping_unsupported"
					p.Candidates = nil
					return p, true
				}
				mapped = append(mapped, map[string]any{"type": "udp", "tag": "dns-" + strconv.Itoa(i), "server": ip, "detour": "proxy"})
			}
			root["dns"] = map[string]any{"servers": mapped}
			root["route"].(map[string]any)["rules"] = []any{map[string]any{"protocol": "dns", "action": "hijack-dns"}}
		}
	}
	b, _ := json.Marshal(root)
	p.Candidates = []probe.Candidate{{Engine: "sing-box", Rule: "native.wireguard.v1", SHA256: repair.Digest(b), Config: b, RequiresConnection: true}}
	return p, true
}
