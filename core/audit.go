package core

import (
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/audit"
	"github.com/nobid-lsp-latvia/lx-idauth/core/util"

	"azugo.io/azugo"
	"go.uber.org/zap"
)

type AuditEvent struct {
	EventCode        string
	EventDescription string
	EventSuccessful  bool
	TransactionId    string
	PersonData       []AuditEventPersonData
	Session          *Session
}

type AuditEventPersonData struct {
	PersonCode string `json:"person_code"`
	FirstName  string `json:"first_name"`
	LastName   string `json:"last_name"`
}

type AuditProvider interface {
	SaveEvent(ctx *azugo.Context, event AuditEvent) error
}

type noopAuditProvider struct{}

func (ap noopAuditProvider) SaveEvent(ctx *azugo.Context, event AuditEvent) error {
	return nil
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

func (ap RestAPIAuditProvider) SaveEvent(ctx *azugo.Context, event AuditEvent) error {
	req := make(audit.SaveAuditEventJSONRequestBody, 1)

	req[0].EventCode = &event.EventCode
	req[0].EventDescription = &event.EventDescription
	req[0].EventSuccessful = &event.EventSuccessful
	req[0].TransactionId = &event.TransactionId
	req[0].EventType = util.PtrString(string(ctx.Request().Header.Method()))
	req[0].RequestUrl = util.PtrString(string(ctx.Request().RequestURI()))
	req[0].ServerIdentifier = util.PtrString(ctx.App().AppName)
	req[0].EventType = util.PtrString("")
	req[0].EventTimestamp = util.PtrTime(time.Now())
	req[0].UserId = util.PtrString(event.Session.Subject)
	req[0].UserIp = util.PtrString(ctx.IP().String())
	req[0].UserFullName = util.PtrString(event.Session.FirstName + " " + event.Session.LastName)
	req[0].UserPersonCode = util.PtrString(event.Session.Code)
	req[0].UserSessionId = util.PtrString(event.Session.ID)

	if event.Session.Role != nil && event.Session.Role.Organization != nil {
		req[0].UserOrganizationCode = &event.Session.Role.Organization.Code
		req[0].UserOrganizationId = util.PtrString(event.Session.Role.Organization.ID)
		req[0].UserOrganizationName = util.PtrString(event.Session.Role.Organization.Name)
		req[0].UserRoleId = util.PtrString(event.Session.Role.UserRoleID)
		req[0].UserRoleName = util.PtrString(event.Session.Role.Name)
	}

	if ap.config.AuditIncludePersonData {
		var personAuditData []struct {
			FullName   *string `json:"fullName,omitempty"`
			PersonCode *string `json:"personCode,omitempty"`
		}

		for _, person := range event.PersonData {
			personAuditData = append(personAuditData, struct {
				FullName   *string `json:"fullName,omitempty"`
				PersonCode *string `json:"personCode,omitempty"`
			}{
				FullName:   util.PtrString(person.FirstName + " " + person.LastName),
				PersonCode: util.PtrString(person.PersonCode),
			})
		}

		req[0].PersonAuditData = &personAuditData
	}

	resp, err := ap.client.SaveAuditEvent(ctx, &audit.SaveAuditEventParams{
		XAPIKEY: ap.config.AuditRestAPIKey,
	}, req)
	if err != nil {
		ctx.Log().Error("Failed to save audit event", zap.Error(err))

		return err
	}
	defer resp.Body.Close()

	return nil
}
