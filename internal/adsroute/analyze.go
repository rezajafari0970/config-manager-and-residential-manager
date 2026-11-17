// Package adsroute exposes the shared route map without authorizing publication.
package adsroute

import "github.com/rezajafari0970/config-manager-and-residential-manager/internal/egress"

const Version = egress.RouteMapVersion

type VariantResult = egress.RouteVariant
type DomainResult = egress.DomainRoute
type Result = egress.RouteMap

func Analyze(r egress.Report, p egress.Plan, hash string, now int64) Result {
	return egress.ObserveRoutes(r, p, hash, now, Targets())
}
