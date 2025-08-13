package core

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/nobid-lsp-latvia/lx-idauth/core/auth"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type OrganizationEntity struct {
	ID                 string `json:"id"`
	Code               string `json:"code"`
	Name               string `json:"name"`
	TypeID             string `json:"type_id"`
	Blocked            bool   `json:"blocked"`
	UserOrganizationID string `json:"user_organization_id"`
}

type RoleEntity struct {
	ID           string              `json:"id"`
	UserRoleID   string              `json:"user_role_id"`
	Organization *OrganizationEntity `json:"organization"`
	Code         string              `json:"code"`
	Name         string              `json:"name"`
	ShortName    string              `json:"short_name"`
	Description  string              `json:"description"`
	Blocked      bool                `json:"blocked"`
}

type GrantedRightListEntity struct {
	UserRoleID       string `json:"user_role_id"`
	RoleID           string `json:"role_id"`
	RoleCode         string `json:"role_code"`
	RoleName         string `json:"role_name"`
	RoleDescription  string `json:"role_description"`
	RightID          string `json:"right_id"`
	RightCode        string `json:"right_code"`
	RightName        string `json:"right_name"`
	RightDescription string `json:"right_description"`
	LevelID          string `json:"level_id"`
	LevelCode        string `json:"level_code"`
	Description      string `json:"description"`
}

type UserData struct {
	UserID          string                    `json:"user_id"`
	ClientID        string                    `json:"client_id" example:"892df848-ad6f-458a-b77b-435d98e7dbc1"`
	IsServiceClient bool                      `json:"is_service_client"`
	PersonCode      string                    `json:"person_code"`
	FirstName       string                    `json:"first_name"`
	LastName        string                    `json:"last_name"`
	Email           string                    `json:"email"`
	Roles           []*RoleEntity             `json:"roles"`
	Rights          []*GrantedRightListEntity `json:"rights"`
}

type GetUserDataRequest struct {
	Code         string  `json:"code" example:"01020311111"`
	FirstName    string  `json:"first_name" validate:"required" example:"John"`
	LastName     string  `json:"last_name" validate:"required" example:"Doe"`
	Email        string  `json:"email" example:"john.doe@gmail.com"`
	ClientID     *string `json:"client_id" example:"892df848-ad6f-458a-b77b-435d98e7dbc1"`
	ClientSecret *string `json:"client_secret"`
}

type Authorizer interface {
	GetUserData(ctx *azugo.Context, data *GetUserDataRequest) (*UserData, error)
}

type RestAPIAuthorizer struct {
	config *RestApiAuthorizerConfig
}

type RestApiAuthorizerConfig struct {
	ApiKey      string
	EndpointUrl string
}

func (a RestAPIAuthorizer) GetUserData(ctx *azugo.Context, data *GetUserDataRequest) (*UserData, error) {
	url, err := url.Parse(strings.TrimRight(a.config.EndpointUrl, "/"))
	if err != nil {
		return nil, err
	}

	if url.Path == "" {
		url.Path = "/api/1.0/authorize"
	}

	client := ctx.HTTPClient().WithBaseURL(url.Scheme + "://" + url.Host)
	req := client.NewRequest()
	if err := req.SetRequestURL(url.Path); err != nil {
		return nil, err
	}

	req.Header.SetMethod(fasthttp.MethodPost)
	defer client.ReleaseRequest(req)

	body, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req.SetBody(body)
	req.Header.Set("X-API-KEY", a.config.ApiKey)
	req.Header.Set(fasthttp.HeaderContentType, "application/json")

	res := client.NewResponse()
	defer client.ReleaseResponse(res)

	if err = client.Do(req, res); err != nil {
		ctx.Log().Error("Error getting user data",
			zap.Error(err),
		)
		return nil, err
	}

	respBody := res.Body()

	statusCode := res.StatusCode()
	if statusCode == fasthttp.StatusUnprocessableEntity {
		if len(string(respBody)) == 0 {
			return nil, &auth.AuthorizeError{
				Code:    auth.AuthErrUserNotExists,
				Message: "User not exists",
			}
		}

		errCode, errMessage, err := parseError(string(respBody))
		if err != nil {
			ctx.Log().Error("Error parsing error message",
				zap.Error(err),
				zap.String("response_body", string(respBody)),
			)

			return nil, errors.New(string(respBody))
		}

		if code, ok := auth.ErrorMap[*errCode]; ok {
			return nil, &auth.AuthorizeError{
				Code:    code,
				Message: *errMessage,
			}
		}

		return nil, &auth.AuthorizeError{
			Code:    auth.AuthErrServer,
			Message: *errMessage,
		}
	}

	if statusCode != fasthttp.StatusOK {
		ctx.Log().Error("Error getting user data",
			zap.Int("status_code", statusCode),
			zap.String("response_body", string(respBody)),
		)

		return nil, &auth.AuthorizeError{
			Code:    auth.AuthErrServer,
			Message: "Error retrieving user data",
		}
	}

	userData := &UserData{}
	if err = json.Unmarshal(respBody, userData); err != nil {
		ctx.Log().Error("Error unmarshalling user data",
			zap.Error(err),
			zap.String("response_body", string(respBody)),
		)

		return nil, err
	}

	return userData, nil
}

func NewRestApiAuthorizer(config *RestApiAuthorizerConfig) Authorizer {
	return &RestAPIAuthorizer{
		config: config,
	}
}

// NoopAuthorizer is a placeholder authorizer that performs no user lookup.
// It can be used in scenarios where any user is to be let into the system without roles and rights.
type noopAuthorizer struct{}

func (a noopAuthorizer) GetUserData(ctx *azugo.Context, data *GetUserDataRequest) (*UserData, error) {
	userData := &UserData{
		UserID:     data.Code,
		PersonCode: data.Code,
		FirstName:  data.FirstName,
		LastName:   data.LastName,
		Email:      data.Email,
	}

	return userData, nil
}

func NewNoopAuthorizer() Authorizer {
	return &noopAuthorizer{}
}

func parseError(errorText string) (*string, *string, error) {
	regex := regexp.MustCompile(`\[([^\]]+)\]\s(.+)`)
	matches := regex.FindStringSubmatch(errorText)

	if len(matches) > 2 {
		return &matches[1], &matches[2], nil
	}

	return nil, nil, errors.New("error parsing error message")
}
