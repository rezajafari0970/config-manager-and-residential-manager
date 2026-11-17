package panel

import (
	"context"
	"io"
	"testing"
)

func TestClientCoreFailureKeepsRawAndBlocksOrdinary(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	_, j := addConversion(t, s, conversionSample)
	result := conversionResult(j, 0, false)
	result.Core = "failed"
	result.Connection = "not_run"
	result.Code = "client_vless_encryption_required"
	result.RuntimeSHA256 = ""
	result.EndpointsPassed = 0
	if err := s.CompleteProbe(ctx, result); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Conversions(ctx, 0, true)
	if err != nil || len(rows) != 1 || rows[0].Available || rows[0].Code != result.Code {
		t.Fatal("rejection not retained", err)
	}
	body, err := s.vault.Open(j.Hash)
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	raw, _ := io.ReadAll(body)
	if string(raw) != conversionSample {
		t.Fatal("raw changed")
	}
}
