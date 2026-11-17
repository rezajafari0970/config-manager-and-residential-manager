package convert

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestURITCPHTTPWithoutHostProducesValidHeaderLists(t *testing.T) {
	for _, host := range []string{"", "&host=keep.example"} {
		p := Prepare([]byte("vless://11111111-1111-4111-8111-111111111111@192.0.2.1:443?type=tcp&headerType=http" + host))
		if p.Code != "prepared" || len(p.Candidates) != 1 {
			t.Fatal(p.Code)
		}
		var root M
		json.Unmarshal(p.Candidates[0].Config, &root)
		for _, v := range root["outbounds"].([]any) {
			ob := v.(M)
			if ob["protocol"] != "vless" {
				continue
			}
			headers := ob["streamSettings"].(M)["tcpSettings"].(M)["header"].(M)["request"].(M)["headers"].(M)
			for _, v := range headers {
				if a, ok := v.([]any); !ok || len(a) == 0 {
					t.Fatal("invalid header list")
				}
			}
			if host != "" && !strings.Contains(string(p.Candidates[0].Config), "keep.example") {
				t.Fatal("explicit host lost")
			}
		}
	}
}
