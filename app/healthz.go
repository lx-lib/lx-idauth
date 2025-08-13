package app

import (
	"azugo.io/azugo"
)

type HealthzStatus string

const (
	// pass healthy (acceptable aliases: "ok" to support Node's Terminus and "up" for Java's SpringBoot)
	// fail unhealthy (acceptable aliases: "error" to support Node's Terminus and "down" for Java's SpringBoot), and
	// warn healthy, with some concerns.
	//
	// ref https://datatracker.ietf.org/doc/html/draft-inadarei-api-health-check#section-3.1
	// status: (required) indicates whether the service status is acceptable
	// or not.  API publishers SHOULD use following values for the field:
	// The value of the status field is case-insensitive and is tightly
	// related with the HTTP response code returned by the health endpoint.
	// For "pass" status, HTTP response code in the 2xx-3xx range MUST be
	// used.  For "fail" status, HTTP response code in the 4xx-5xx range
	// MUST be used.  In case of the "warn" status, endpoints MUST return
	// HTTP status in the 2xx-3xx range, and additional information SHOULD
	// be provided, utilizing optional fields of the response.
	HealthzPass HealthzStatus = "pass"
	HealthzFail HealthzStatus = "fail"
	HealthzWarn HealthzStatus = "warn"
)

// HealthzResponse is the data returned by the health endpoint, which will be marshaled to JSON format.
type HealthzResponse struct {
	Status      HealthzStatus `json:"status"`
	Description string        `json:"description"` // a human-friendly description of the service
}

func (r *router) healthz(ctx *azugo.Context) {
	ctx.SkipRequestLog()

	ctx.JSON(&HealthzResponse{
		Status:      HealthzPass,
		Description: ctx.App().AppName,
	})
}
