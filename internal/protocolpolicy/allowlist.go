// Package protocolpolicy checks the executable protocols in one complete profile.
package protocolpolicy

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"github.com/rezajafari0970/config-manager-and-residential-manager/internal/repair"
)

const Code = "protocol_disabled"

// AllowedProtocol reports whether the name denotes a permitted upstream proxy.
func AllowedProtocol(s string) bool {
	switch normalized(s) {
	case "vless", "vmess", "trojan", "ss", "shadowsocks", "wg", "wireguard":
		return true
	}
	return false
}

func normalized(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func DisabledKind(kind string) bool {
	switch normalized(kind) {
	case "", "json", "custom", "httpcustom", "napsternet":
		// The wrapper has no protocol identity of its own.
		return false
	}
	return !AllowedProtocol(kind)
}

func hysteria(s string) bool {
	switch normalized(s) {
	case "hy", "hy1", "hy2", "hysteria", "hysteria1", "hysteria2":
		return true
	}
	return false
}

func Disabled(kind string, raw []byte) bool {
	return DisabledKind(kind) || !allowedBytes(raw, 0)
}

func trim(b []byte) []byte {
	return bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(b), []byte{0xef, 0xbb, 0xbf}))
}

func decode64(raw []byte) ([]byte, bool) {
	enc := base64.RawStdEncoding
	if bytes.ContainsAny(raw, "-_") {
		enc = base64.RawURLEncoding
	}
	if len(raw) > 0 && raw[len(raw)-1] == '=' {
		enc = enc.WithPadding(base64.StdPadding)
	}
	b, err := enc.DecodeString(string(raw))
	return b, err == nil && len(b) > 0
}

func allowedBytes(raw []byte, depth int) bool {
	raw = trim(raw)
	if len(raw) == 0 || depth > 10 {
		return false
	}
	if bytes.HasPrefix(bytes.ToLower(raw[:min(len(raw), 11)]), []byte("[interface]")) {
		return wireguardINI(raw)
	}
	switch raw[0] {
	case '{', '[':
		return allowedJSONBytes(raw, root, depth)
	case '"':
		var s string
		return json.Unmarshal(raw, &s) == nil && allowedBytes([]byte(s), depth+1)
	}
	if bytes.ContainsAny(raw, "\r\n") {
		// Wrapped base64 can contain line breaks. A share URI is one record.
		b, ok := decode64(raw)
		return ok && allowedBytes(b, depth+1)
	}
	scheme, body, has := bytes.Cut(raw, []byte("://"))
	if !has {
		if bytes.Contains(raw, []byte("%")) {
			if s, e := url.PathUnescape(string(raw)); e == nil && s != string(raw) {
				return allowedBytes([]byte(s), depth+1)
			}
		}
		b, ok := decode64(raw)
		return ok && allowedBytes(b, depth+1)
	}
	name := normalized(string(scheme))
	body, _, _ = bytes.Cut(body, []byte("#"))
	if len(body) == 0 {
		return false
	}
	switch name {
	case "json", "custom", "httpcustom", "napsternet":
		if s, e := url.PathUnescape(string(body)); e == nil {
			return allowedBytes([]byte(s), depth+1)
		}
		return false
	case "vmess":
		payload, err := url.PathUnescape(string(body))
		if err != nil {
			return false
		}
		b, ok := decode64([]byte(payload))
		if ok {
			// v2-style VMess shares have implicit type VMess. An explicitly
			// declared outbound or stream in the encoded JSON is still inspected.
			return allowedJSONBytes(b, vmessShare, depth+1)
		}
		// Some clients emit an authority-style share.
		u, err := url.Parse(string(raw))
		if err != nil || u.User == nil || u.Hostname() == "" {
			return false
		}
	}
	if !AllowedProtocol(name) {
		return false
	}
	_, query, found := bytes.Cut(body, []byte("?"))
	if !found {
		return true
	}
	params, err := url.ParseQuery(string(query))
	if err != nil {
		return false
	}
	for k, vs := range params {
		for _, v := range vs {
			switch normalized(k) {
			case "net", "type", "network", "transport":
				if hysteria(v) {
					return false
				}
			case "xhttpextra", "extra":
				if strings.HasPrefix(strings.TrimSpace(v), "{") && !allowedJSONBytes([]byte(v), transport, depth+1) {
					return false
				}
			}
		}
	}
	return true
}

func wireguardINI(raw []byte) bool {
	iface, peer := false, false
	for line := range bytes.SplitSeq(raw, []byte{'\n'}) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' || line[0] == ';' {
			continue
		}
		switch strings.ToLower(string(line)) {
		case "[interface]":
			if iface || peer {
				return false
			}
			iface = true
		case "[peer]":
			if !iface {
				return false
			}
			peer = true
		default:
			key, _, ok := bytes.Cut(line, []byte{'='})
			if !ok || !iface || len(bytes.TrimSpace(key)) == 0 || bytes.ContainsAny(key, ":/{[") {
				return false
			}
		}
	}
	return iface && peer
}

// DisabledReader validates to EOF, using a streaming decoder for large JSON.
func DisabledReader(kind string, r io.Reader) (bool, error) {
	if DisabledKind(kind) {
		return true, nil
	}
	in := bufio.NewReader(r)
	head, err := io.ReadAll(io.LimitReader(in, repair.MaxBytes+1))
	if err != nil {
		return true, err
	}
	if len(head) <= repair.MaxBytes {
		return Disabled(kind, head), nil
	}
	start := trim(head)
	full := io.MultiReader(bytes.NewReader(head), in)
	if len(start) > 0 && (start[0] == '{' || start[0] == '[' && !bytes.HasPrefix(bytes.ToLower(start[:min(11, len(start))]), []byte("[interface]"))) {
		allowed, err := jsonProfile(full, root, 0)
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return true, nil
		}
		return !allowed, err
	}
	raw, err := io.ReadAll(full)
	if err != nil {
		return true, err
	}
	return Disabled(kind, raw), nil
}

type role uint8

const (
	ignore role = iota
	root
	outbound
	inbound
	transport
	vmessShare
	nestedRoute
	envelope
)

func auxiliary(s string) bool {
	switch normalized(s) {
	case "freedom", "direct", "blackhole", "block", "dns", "loopback", "selector", "urltest":
		return true
	}
	return false
}

func localInbound(s string) bool {
	switch normalized(s) {
	case "socks", "socks5", "http", "mixed", "tun", "dokodemo-door", "tunnel", "redirect", "tproxy", "direct":
		return true
	}
	return AllowedProtocol(s)
}

func fieldRole(parent role, key string) role {
	if parent == root || parent == vmessShare || parent == envelope {
		switch key {
		case "outbounds", "outbound", "outbounddetour", "outbounddetours", "endpoints", "proxies":
			return outbound
		case "inbounds", "inbound", "inbounddetour", "inbounddetours":
			return inbound
		case "config", "configs", "profile", "profiles", "configuration", "custom_config", "customconfig", "custom", "json", "jsonconfig", "configjson", "outboundconfig":
			return envelope
		}
	}
	switch key {
	case "streamsettings", "transport", "downloadsettings":
		return transport
	}
	return ignore
}

var errRejected = errors.New("protocol policy rejected")

func allowedJSONBytes(raw []byte, scope role, depth int) bool {
	ok, err := jsonProfile(bytes.NewReader(trim(raw)), scope, depth)
	if err != nil && len(raw) <= repair.MaxBytes {
		var syntax *json.SyntaxError
		if errors.As(err, &syntax) {
			b := repair.StripTrailingCommas(raw)
			if !bytes.Equal(b, raw) {
				ok, _ = jsonProfile(bytes.NewReader(trim(b)), scope, depth)
			}
		}
	}
	return ok
}

func jsonProfile(r io.Reader, scope role, depth int) (bool, error) {
	d := json.NewDecoder(r)
	d.UseNumber()
	t, err := d.Token()
	if err != nil {
		return false, err
	}
	found, err := walk(d, t, scope, depth)
	if errors.Is(err, errRejected) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	_, err = d.Token()
	if err != io.EOF {
		if err == nil {
			return false, nil
		}
		return false, err
	}
	return found || scope == transport, nil
}

// walk returns positive evidence of a permitted upstream. Every declared
// outbound in a chain is inspected, even if a different outbound is selected.
func walk(d *json.Decoder, token json.Token, where role, depth int) (bool, error) {
	if depth > 64 {
		return false, errRejected
	}
	switch token {
	case json.Delim('['):
		found := false
		for d.More() {
			t, e := d.Token()
			if e != nil {
				return false, e
			}
			p, e := walk(d, t, where, depth+1)
			if e != nil {
				return false, e
			}
			if (where == root || where == envelope) && !p {
				return false, errRejected
			}
			found = found || p
		}
		_, e := d.Token()
		return found, e
	case json.Delim('{'):
		declared, found := false, false
		var explicitRoutes, allowedRoute bool
		var seen map[string]bool
		vmessAddress, vmessID := false, false
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return false, e
			}
			key := normalized(k.(string))
			v, e := d.Token()
			if e != nil {
				return false, e
			}
			s, isString := v.(string)
			child := fieldRole(where, key)
			if where == ignore && (v == json.Delim('{') || v == json.Delim('[')) {
				// A nested client section can contain another core profile. Ordinary
				// string routing tags in these fields do not select a protocol.
				switch key {
				case "outbounds", "outbound", "outbounddetour", "outbounddetours", "endpoints", "proxies":
					child = nestedRoute
				}
			}
			if where != ignore && (child != ignore || key == "type" || key == "protocol" || key == "net" || key == "network") {
				if seen == nil {
					seen = make(map[string]bool)
				}
				if seen[key] {
					return false, errRejected
				}
				seen[key] = true
			}
			if (key == "type" || key == "protocol") && (where == root || where == outbound || where == inbound || where == vmessShare || where == nestedRoute || where == envelope) {
				// In classic VMess URI JSON, "type" is TCP header camouflage.
				if where == vmessShare && key == "type" {
					if !isString {
						return false, errRejected
					}
					switch normalized(s) {
					case "", "none", "---", "multi", "gun", "http", "utp", "srtp", "dtls", "wechat-video", "wireguard":
					default:
						return false, errRejected
					}
				} else {
					declared = true
					switch {
					case !isString:
						return false, errRejected
					case where == inbound:
						if !localInbound(s) {
							return false, errRejected
						}
					case AllowedProtocol(s):
						found = true
					case (where == root || where == envelope) && (normalized(s) == "json" || normalized(s) == "custom"):
						// Only its independently verified contents can qualify a wrapper.
					case !auxiliary(s):
						return false, errRejected
					}
				}
			}
			if isString && (where == transport || where == root || where == outbound || where == vmessShare || where == inbound || where == envelope) {
				switch key {
				case "network", "net", "transport":
					if hysteria(s) {
						return false, errRejected
					}
				case "type", "method":
					if where == transport && hysteria(s) {
						return false, errRejected
					}
				}
			}
			if (where != ignore || v == json.Delim('{') || v == json.Delim('[')) && (key == "hysteriasettings" || key == "hysteria2settings" || key == "hy2settings" || key == "hysteria1settings") {
				nonempty := v != nil
				if v == json.Delim('{') || v == json.Delim('[') {
					nonempty = d.More()
				}
				if nonempty {
					return false, errRejected
				}
			}
			if (where == root || where == vmessShare) && isString && s != "" {
				if key == "add" {
					vmessAddress = true
				}
				if key == "id" {
					vmessID = true
				}
			}
			p, e := walk(d, v, child, depth+1)
			if e != nil {
				return false, e
			}
			if child == outbound {
				explicitRoutes = true
				allowedRoute = allowedRoute || p
			}
			if child == envelope && !p {
				return false, errRejected
			}
			found = found || p
		}
		_, e := d.Token()
		if (where == outbound || where == inbound) && !declared {
			return false, errRejected
		}
		if where == inbound || where == ignore {
			return false, e
		}
		if explicitRoutes {
			return allowedRoute, e
		}
		return found || where == vmessShare && vmessAddress && vmessID, e
	default:
		if s, ok := token.(string); ok && (where == root || where == envelope) {
			if !allowedBytes([]byte(s), depth+1) {
				return false, errRejected
			}
			return true, nil
		}
		if where == outbound || where == inbound || where == envelope || where == root || where == vmessShare {
			return false, errRejected
		}
		return false, nil
	}
}
