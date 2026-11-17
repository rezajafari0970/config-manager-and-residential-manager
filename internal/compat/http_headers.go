package compat

// NormalizeEmptyHTTPHeaders removes absent HTTP-camouflage Host values from
// generated candidates. Xray rejects null/empty arrays; omission uses its
// standard defaults. Explicit hosts, credentials and the stored raw stay intact.
func NormalizeEmptyHTTPHeaders(root M) []Change {
	var changes []Change
	obs, _ := root["outbounds"].([]any)
	for _, value := range obs {
		ob, _ := value.(M)
		stream, _ := ob["streamSettings"].(M)
		for _, key := range []string{"tcpSettings", "rawSettings"} {
			tcp, _ := stream[key].(M)
			header, _ := tcp["header"].(M)
			if header["type"] != "http" {
				continue
			}
			request, _ := header["request"].(M)
			headers, _ := request["headers"].(M)
			value, exists := headers["Host"]
			if !exists {
				continue
			}
			empty := value == nil
			if list, ok := value.([]any); ok {
				empty = len(list) == 0
			}
			if list, ok := value.([]string); ok {
				empty = len(list) == 0
			}
			if empty {
				delete(headers, "Host")
				tag, _ := ob["tag"].(string)
				changes = append(changes, Change{"empty-http-host.v1", tag, "omitted_absent_host"})
			}
		}
	}
	return changes
}
