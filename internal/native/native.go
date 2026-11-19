package native

import (
	"bytes"
	"encoding/json"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/probe"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/protocolpolicy"
	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

const NativeID = "sing-box-1.14.4"
const NativeSHA = "1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a"

func Prepare(raw []byte) (probe.Plan, bool) {
	p := probe.Plan{Target: NativeID, Version: "native.v1", OriginalSHA256: repair.Digest(raw), Code: "native_import_unsupported", AndroidImport: "not_applicable", Candidates: []probe.Candidate{}}
	if len(raw) > repair.MaxBytes {
		p.Code = "inspection_size_limit"
		return p, true
	}
	if protocolpolicy.Disabled("", raw) {
		p.Code = protocolpolicy.Code
		return p, true
	}
	if decoded, err := probe.DecodeEnvelope(raw); err == nil {
		raw = decoded
	}
	if wg, ok := wireguard(raw); ok {
		wg.OriginalSHA256 = p.OriginalSHA256
		return wg, true
	}
	var config map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !json.Valid(raw) || d.Decode(&config) != nil {
		return p, false
	}
	outbounds, _ := config["outbounds"].([]any)
	endpoints, _ := config["endpoints"].([]any)
	members := append(append([]any{}, outbounds...), endpoints...)
	if len(members) == 0 {
		return p, false
	}
	first, _ := members[0].(map[string]any)
	typ, _ := first["type"].(string)
	if typ == "" {
		return p, false // Xray JSON uses protocol on its outbounds.
	}
	switch typ {
	case "vless", "vmess", "trojan", "shadowsocks":
		if len(outbounds) != 1 {
			return p, true
		}
	case "wireguard":
		if len(endpoints) != 1 || first["system"] == true {
			return p, true
		}
	default:
		return p, true
	}
	if len(members) != 1 || first["detour"] != nil {
		return p, true
	}
	for k := range config {
		switch k {
		case "outbounds", "endpoints", "inbounds", "log", "route", "dns":
		default:
			return p, true
		}
	}
	tag, _ := first["tag"].(string)
	if tag == "" {
		tag = "@shenvpn"
		first["tag"] = tag
	}
	route, _ := config["route"].(map[string]any)
	if route == nil {
		route = map[string]any{}
		config["route"] = route
	}
	if final, ok := route["final"].(string); ok && final != "" && final != tag {
		return p, true
	}
	if rules, _ := route["rules"].([]any); len(rules) > 0 {
		return p, true
	}
	route["final"] = tag
	config["inbounds"] = []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": 10808}}
	config["log"] = map[string]any{"disabled": true}
	if tls, ok := first["tls"].(map[string]any); ok && tls["insecure"] == true {
		tls["insecure"] = false
	}
	template, err := json.Marshal(config)
	if err != nil {
		return p, true
	}
	p.Code = "prepared"
	p.Candidates = []probe.Candidate{{Engine: "sing-box", Rule: "native.single.v2", SHA256: repair.Digest(template), Config: template, RequiresConnection: true}}
	return p, true
}
