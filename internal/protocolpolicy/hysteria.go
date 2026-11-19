// Package protocolpolicy identifies disabled connection protocols at the boundaries
// shared by collection, workers and publication. A profile is an atomic document.
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

func DisabledKind(kind string) bool {
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "hy", "hy1", "hy2", "hysteria", "hysteria1", "hysteria2":
		return true
	}
	return false
}

func Disabled(kind string, raw []byte) bool {
	if DisabledKind(kind) {
		return true
	}
	return disabledBytes(raw, 0)
}

func disabledBytes(raw []byte, depth int) bool {
	raw = bytes.TrimSpace(bytes.TrimPrefix(bytes.TrimSpace(raw), []byte{0xef, 0xbb, 0xbf}))
	if len(raw) == 0 || depth > 10 {
		return false
	}
	switch raw[0] {
	case '{', '[':
		// Avoid parsing ordinary exports on every print. Escaped JSON keys and
		// values still require a real parse. Root arrays may contain encoded shares.
		if raw[0] == '{' && !bytes.Contains(raw, []byte("hy")) && !bytes.Contains(raw, []byte("Hy")) &&
			!bytes.Contains(raw, []byte("hY")) && !bytes.Contains(raw, []byte("HY")) && !bytes.Contains(raw, []byte(`\u`)) {
			return false
		}
		blocked, err := disabledJSON(bytes.NewReader(raw), depth)
		if !blocked && err != nil && len(raw) <= repair.MaxBytes {
			clean := repair.StripTrailingCommas(raw)
			if !bytes.Equal(clean, raw) {
				blocked, _ = disabledJSON(bytes.NewReader(clean), depth)
			}
		}
		return blocked
	case '"':
		var inner string
		return json.Unmarshal(raw, &inner) == nil && disabledBytes([]byte(inner), depth+1)
	}
	scheme, payload, found := bytes.Cut(raw, []byte("://"))
	if found {
		name := strings.ToLower(string(scheme))
		if DisabledKind(name) {
			return true
		}
		switch name {
		case "json", "custom", "napsternet", "vmess":
			body, _, _ := bytes.Cut(payload, []byte("#"))
			if bytes.ContainsRune(body, '%') {
				if s, err := url.PathUnescape(string(body)); err == nil {
					body = []byte(s)
				}
			}
			return disabledBytes(body, depth+1)
		case "vless", "trojan", "ss", "socks", "socks5":
			rawQuery, _, _ := bytes.Cut(raw, []byte("#"))
			_, rawQuery, hasQuery := bytes.Cut(rawQuery, []byte("?"))
			if hasQuery {
				query, _ := url.ParseQuery(string(rawQuery))
				for _, k := range []string{"type", "network", "net", "transport"} {
					if DisabledKind(query.Get(k)) {
						return true
					}
				}
				// XHTTP's nested download transport is part of the executable profile.
				for _, k := range []string{"xhttpExtra", "extra"} {
					if v := query.Get(k); strings.HasPrefix(strings.TrimSpace(v), "{") && disabledBytes([]byte(v), depth+1) {
						return true
					}
				}
			}
		}
		return false
	}
	// Base64 is used for VMess shares and nested custom JSON envelopes.
	encoding := base64.RawStdEncoding
	if bytes.ContainsAny(raw, "-_") {
		encoding = base64.RawURLEncoding
	}
	if raw[len(raw)-1] == '=' {
		encoding = encoding.WithPadding(base64.StdPadding)
	}
	decoded, err := encoding.DecodeString(string(raw))
	return err == nil && disabledBytes(decoded, depth+1)
}

// DisabledReader examines a single extracted profile without truncating its JSON
// at the collector's diagnostic sampling limit. The caller owns the reader.
func DisabledReader(kind string, r io.Reader) (bool, error) {
	if DisabledKind(kind) {
		return true, nil
	}
	b := bufio.NewReader(r)
	for {
		lead, err := b.Peek(1)
		if err == io.EOF {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		switch lead[0] {
		case ' ', '\t', '\r', '\n':
			_, _ = b.Discard(1)
			continue
		case 0xef:
			prefix, _ := b.Peek(3)
			if bytes.Equal(prefix, []byte{0xef, 0xbb, 0xbf}) {
				_, _ = b.Discard(3)
				continue
			}
		case '{', '[':
			// Keep repairable documents available for the same syntax recovery as
			// the conversion pipeline. Larger JSON documents are scanned to EOF.
			head, err := io.ReadAll(io.LimitReader(b, repair.MaxBytes+1))
			if err != nil {
				return false, err
			}
			if len(head) <= repair.MaxBytes {
				return disabledBytes(head, 0), nil
			}
			blocked, err := disabledJSON(io.MultiReader(bytes.NewReader(head), b), 0)
			var syntax *json.SyntaxError
			if errors.As(err, &syntax) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				err = nil
			}
			return blocked, err
		}
		break
	}
	raw, err := io.ReadAll(b)
	if err != nil {
		return false, err
	}
	return disabledBytes(raw, 0), nil
}

type scope uint8

const (
	other scope = iota
	profile
	stream
)

func childScope(key string) scope {
	switch strings.ToLower(key) {
	case "inbounds", "inbound", "outbounds", "outbound", "endpoints", "proxies":
		return profile
	case "streamsettings", "transport", "downloadsettings":
		return stream
	}
	return other
}

func disabledJSON(r io.Reader, depth int) (bool, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return false, err
	}
	return walk(dec, t, profile, depth)
}

func walk(dec *json.Decoder, token json.Token, where scope, depth int) (bool, error) {
	switch token {
	case json.Delim('{'):
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return false, err
			}
			key, ok := k.(string)
			if !ok {
				return false, nil
			}
			v, err := dec.Token()
			if err != nil {
				return false, err
			}
			if s, ok := v.(string); ok && where != other {
				if where == stream && strings.EqualFold(key, "method") && DisabledKind(s) {
					return true, nil
				}
				switch strings.ToLower(key) {
				case "protocol", "type", "network", "net", "transport":
					if DisabledKind(s) {
						return true, nil
					}
				}
			}
			if blocked, err := walk(dec, v, childScope(key), depth); blocked || err != nil {
				return blocked, err
			}
		}
	case json.Delim('['):
		for dec.More() {
			v, err := dec.Token()
			if err != nil {
				return false, err
			}
			// JSON arrays are also used as subscriptions of JSON-encoded shares.
			if s, ok := v.(string); ok && where == profile && disabledBytes([]byte(s), depth+1) {
				return true, nil
			}
			if blocked, err := walk(dec, v, where, depth); blocked || err != nil {
				return blocked, err
			}
		}
	default:
		return false, nil
	}
	_, err := dec.Token()
	return false, err
}
