package probe

import (
	"encoding/base64"
	"encoding/json"
)

// Several exporters put a VMess cipher into the TLS field. Neither TLS mode
// can be inferred from that spelling. Try both exact hypotheses; publication
// still requires a real authenticated, certificate-verified connection.
func vmessSecurityHypotheses(payload string) ([]Candidate, bool) {
	b, _, e := vmessPayload(payload)
	if e != nil {
		return nil, false
	}
	m, e := strictObject(b)
	if e != nil {
		return nil, false
	}
	cipher := str(m, "tls")
	switch cipher {
	case "auto", "aes-128-gcm", "chacha20-poly1305", "zero":
	default:
		return nil, false
	}
	if str(m, "scy") == "" {
		m["scy"] = cipher
	}
	out := []Candidate{}
	for _, mode := range []string{"tls", "none"} {
		m["tls"] = mode
		encoded, _ := json.Marshal(m)
		ob, e := vmess(base64.RawStdEncoding.EncodeToString(encoded))
		if e != nil {
			continue
		}
		delete(ob, "__input_rule")
		delete(ob, "__require_connection")
		root := M{"outbounds": []any{ob}, "routing": M{}}
		out = append(out, candidate(root, "vmess-misplaced-tls-hypothesis."+mode, true))
	}
	return out, len(out) > 0
}
