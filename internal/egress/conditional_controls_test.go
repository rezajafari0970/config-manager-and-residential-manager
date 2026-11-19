package egress

import (
	"slices"
	"testing"
)

func TestSupplementalControlsPreserveExistingRouteReceipts(t *testing.T) {
	// This digest identifies the baseline Ads route policy already stored in receipts.
	const baselineDigest = "3d28bb53f030023b18e1ed77800bf0790de312f90f1d45205798eeb206626794"
	if got := PolicyDigest(); got != baselineDigest {
		t.Fatalf("baseline policy digest changed to %s", got)
	}
	r, p, now := fixture()
	r.Samples = slices.DeleteFunc(r.Samples, func(s Sample) bool {
		control, _ := targetFor(s.Domain)
		return control.WhenAdsFamily != 0
	})
	d := Evaluate(r, p, r.Hash, now)
	if !d.Eligible || !d.CoverageComplete {
		t.Fatal("existing IPv4 receipt lost coverage", d.Reason)
	}
	for _, service := range d.Services {
		control, _ := targetFor(service.Domain)
		if control.WhenAdsFamily != 0 {
			t.Fatal("unattempted conditional service listed", service.Domain)
		}
	}
}

func TestIPv6ComparisonRequiresBothObservedGroupsInEachVariant(t *testing.T) {
	for _, tc := range []struct {
		name      string
		include   func(Sample) bool
		qualified bool
	}{
		{"no matching control", func(Sample) bool { return false }, false},
		{"Google alone", func(s Sample) bool { return s.Domain == "ipv6.google.com" }, false},
		{"one matching wave", func(s Sample) bool { return s.Wave == 1 }, false},
		{"controls in different variants", func(s Sample) bool { return (s.Domain == "ipv6.google.com") == (s.Variant == "raw") }, false},
		{"repeated same-wave controls in both variants", func(s Sample) bool { return s.Wave <= 2 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, p, now := fixture()
			for i := range r.Samples {
				s := &r.Samples[i]
				target, _ := targetFor(s.Domain)
				if s.ActualAds || (target.WhenAdsFamily == 6 && tc.include(*s)) {
					s.Family = 6
				}
				if target.WhenAdsFamily == 6 && s.Family == 4 && routeValid(*s, r) {
					t.Fatal("IPv4 echo accepted from IPv6-only control")
				}
			}
			d := Evaluate(r, p, r.Hash, now)
			if d.Eligible != tc.qualified || d.Negative {
				t.Fatalf("eligible=%t negative=%t reason=%s", d.Eligible, d.Negative, d.Reason)
			}
		})
	}
}
