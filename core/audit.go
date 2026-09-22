package core

import (
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/lx-lib/lx-idauth/audit"
	"github.com/lx-lib/lx-idauth/core/util"

	"azugo.io/azugo"
	"azugo.io/opentelemetry"
	jsondb "github.com/lx-lib/lx-go-jsondb"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

const (
	correlationIDHeader    = "X-Correlation-ID"
	transactionIDMaxLength = 50
)

type AuditEvent struct {
	Session *Session
	Events  *audit.SaveAuditEventJSONRequestBody
}

type AuditEventPersonData struct {
	PersonCode string `json:"person_code"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
}

type AuditProvider interface {
	SaveEvent(ctx *azugo.Context, event *AuditEvent) (*http.Response, error)
}

type noopAuditProvider struct{}

func (ap noopAuditProvider) SaveEvent(ctx *azugo.Context, event *AuditEvent) (*http.Response, error) {
	return nil, nil
}

func NewNoopAuditProvider() AuditProvider {
	return noopAuditProvider{}
}

type RestAPIAuditProvider struct {
	config *RestAPIAuditProviderConfig
	client *audit.Client
}

type RestAPIAuditProviderConfig struct {
	AuditUrl               string
	AuditIncludePersonData bool
	AuditRestAPIKey        string
}

func NewRestAPIAuditProvider(config *RestAPIAuditProviderConfig) (AuditProvider, error) {
	auditClient, err := audit.NewClient(config.AuditUrl)
	if err != nil {
		return nil, err
	}

	return RestAPIAuditProvider{
		config: config,
		client: auditClient,
	}, nil
}

func (ap RestAPIAuditProvider) SaveEvent(ctx *azugo.Context, req *AuditEvent) (*http.Response, error) {
	events := *req.Events

	requestURL := string(ctx.Request().RequestURI())
	eventType := string(ctx.Request().Header.Method())
	serverIdentifier := ctx.App().AppName
	userIP := ctx.IP().String()

	transactionID := transactionIDFromContext(ctx)

	for i, event := range events {
		event.RequestUrl = util.PtrString(requestURL)
		if event.EventType == nil {
			event.EventType = util.PtrString(eventType)
		}
		event.ServerIdentifier = util.PtrString(serverIdentifier)
		event.TransactionId = util.PtrString(transactionID)
		event.UserIp = util.PtrString(userIP)

		if req.Session.Role != nil && req.Session.Role.Organization != nil {
			event.UserOrganizationCode = util.PtrString(req.Session.Role.Organization.Code)
			event.UserOrganizationId = util.PtrString(req.Session.Role.Organization.ID)
			event.UserOrganizationName = util.PtrString(req.Session.Role.Organization.Name)
			event.UserRoleId = util.PtrString(req.Session.Role.UserRoleID)
			event.UserRoleName = util.PtrString(req.Session.Role.Name)
		}

		if event.PersonAuditData == nil {
			event.PersonAuditData = &[]struct {
				FullName   *string `json:"fullName,omitempty"`
				PersonCode *string `json:"personCode,omitempty"`
			}{
				{
					FullName:   util.PtrString(ctx.User().DisplayName()),
					PersonCode: util.PtrString(ctx.User().ClaimValue("code")),
				},
			}
		}

		if event.UserFullName == nil {
			event.UserFullName = util.PtrString(ctx.User().DisplayName())
		}

		if event.UserCode == nil {
			event.UserCode = util.PtrString(ctx.User().ClaimValue("code"))
		}

		if event.UserId == nil {
			event.UserId = util.PtrString(ctx.User().ID())
		}

		if event.UserSessionId == nil {
			event.UserSessionId = util.PtrString(ctx.User().ClaimValue("sid"))
		}

		if event.IsApiUser == nil {
			event.IsApiUser = util.PtrBool(ctx.User().ClaimValue("is_service_client") == "true")
		}

		if event.Justification == nil {
			event.Justification = util.PtrString("")
		}

		if event.EventTimestamp == nil {
			event.EventTimestamp = util.PtrTime(time.Now())
		}

		events[i] = event
	}

	res, err := ap.client.SaveAuditEvent(ctx, &audit.SaveAuditEventParams{
		XAPIKEY: ap.config.AuditRestAPIKey,
	}, events)
	if err != nil {
		ctx.Log().Error("Failed to save audit event", zap.Error(err), zap.String("Server", ap.client.Server))
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		bodyBytes, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, err
		}

		ctx.StatusCode(res.StatusCode)
		ctx.Log().Error("Failed to save audit event", zap.String("body", string(bodyBytes)))

		return nil, &jsondb.ExecError{
			Code:    "err:audit:error",
			Message: "Radās kļūda veidojot audita ierakstu",
		}
	}

	return res, nil
}

func transactionIDFromContext(ctx *azugo.Context) string {
	if id := strings.TrimSpace(ctx.Header.Get(correlationIDHeader)); id != "" {
		if len(id) > transactionIDMaxLength {
			id = id[:transactionIDMaxLength]
		}
		return id
	}

	if span := trace.SpanContextFromContext(opentelemetry.FromContext(ctx)); span.HasTraceID() {
		return span.TraceID().String()
	}

	return ctx.ID()
}
