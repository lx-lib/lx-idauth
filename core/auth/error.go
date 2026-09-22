package auth

import (
	"github.com/valyala/fasthttp"
)

type AuthErrCode string

const (
	AuthErrInvalidCallback  AuthErrCode = "invalid_callback"
	AuthErrCanceled         AuthErrCode = "canceled"
	AuthErrInvalidToken     AuthErrCode = "invalid_token"
	AuthErrInvalidScope     AuthErrCode = "invalid_scope"
	AuthErrTermsNotAccepted AuthErrCode = "terms_not_accepted"
	AuthErrServer           AuthErrCode = "server_error"
	AuthErrInvalidClient    AuthErrCode = "invalid_client"
	AuthErrNoSession        AuthErrCode = "no_session"
	AuthErrNoRights         AuthErrCode = "invalid_rights"
	AuthErrBlocked          AuthErrCode = "blocked"
	AuthErrAnnulled         AuthErrCode = "annulled"
	AuthErrUserNotExists    AuthErrCode = "user_not_exists"
	AuthErrMultipleUsers    AuthErrCode = "multiple_users"
	AuthErrInvalidRequest   AuthErrCode = "invalid_request"
	AuthErrNoToken          AuthErrCode = "no_token"
)

var ErrorMap = map[string]AuthErrCode{
	"err:user:few_users":  AuthErrMultipleUsers,
	"err:user:not_exists": AuthErrUserNotExists,
	"err:user:blocked":    AuthErrBlocked,
	"err:user:deleted":    AuthErrAnnulled,
}

type AuthorizeError struct {
	Code    AuthErrCode `json:"error"`
	Message string      `json:"error_description,omitempty"`
	State   *string     `json:"state,omitempty"`
}

func (e *AuthorizeError) Error() string {
	return string(e.Code) + ": " + e.Message
}

func (e *AuthorizeError) StatusCode() int {
	if len(e.Code) == 0 {
		return fasthttp.StatusInternalServerError
	}
	if e.Code == AuthErrInvalidToken ||
		e.Code == AuthErrInvalidScope ||
		e.Code == AuthErrNoRights ||
		e.Code == AuthErrBlocked ||
		e.Code == AuthErrAnnulled ||
		e.Code == AuthErrUserNotExists ||
		e.Code == AuthErrNoSession ||
		e.Code == AuthErrNoToken ||
		e.Code == AuthErrInvalidClient ||
		e.Code == AuthErrTermsNotAccepted {
		return fasthttp.StatusUnauthorized
	}
	if e.Code == AuthErrServer {
		return fasthttp.StatusInternalServerError
	}

	return fasthttp.StatusBadRequest
}
