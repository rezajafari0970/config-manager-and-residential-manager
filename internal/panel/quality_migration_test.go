package panel

import (
	"context"
	"testing"
)

func TestPayloadReceiptCannotBeAssertedByCodeAlone(t *testing.T) {
	s := testStore(t)
	_, j := addConversion(t, s, conversionSample)
	r := conversionResult(j, 0, true)
	delete(r.Evidence, "payload_upload")
	if e := s.CompleteProbe(context.Background(), r); e == nil {
		t.Fatal("unearned payload proof")
	}
	r = conversionResult(j, 0, true)
	if e := s.CompleteProbe(context.Background(), r); e != nil {
		t.Fatal(e)
	}

}
