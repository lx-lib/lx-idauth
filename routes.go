package idauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nobid-lsp-latvia/lx-idauth/core"
	"github.com/nobid-lsp-latvia/lx-idauth/core/auth"
	"github.com/nobid-lsp-latvia/lx-idauth/core/util"

	"azugo.io/azugo"
	"azugo.io/azugo/wsfed"
	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

func (a *IDAuth) token(ctx *azugo.Context) {
	grantType, err := ctx.Form.String("grant_type")
	if err != nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		return
	}

	switch grantType {
	case "client_credentials":
		a.clientCredentials(ctx)
	case "authorization_code":
		a.authorizationCode(ctx)
	default:
		a.clientCredentials(ctx, grantType)
	}
}

func (a *IDAuth) clientCredentials(ctx *azugo.Context, grantType ...string) {
	if len(grantType) == 0 {
		grantType = append(grantType, core.TOKEN_TYPE_BASIC)
	}

	validator := core.NewTokenValidator(grantType[0], a.clientStore, &core.PfasAuthTokenValidatorConfig{
		IntrospectionURL:          a.config.ExposedConfig().IntrospectionURL,
		IntrospectionClientId:     a.config.ExposedConfig().IntrospectionClientID,
		IntrospectionClientSecret: a.config.ExposedConfig().IntrospectionClientSecret,
	})
	result, err := validator.ValidateToken(ctx)
	if err != nil {
		ctx.Error(err)
		var authErr *auth.AuthorizeError
		if errors.As(err, &authErr) {
			ctx.JSON(authErr)
		}
		return
	}

	if !result.Valid {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		return
	}

	userData, err := a.authorizer.GetUserData(ctx, &core.GetUserDataRequest{
		ClientID:     &result.ClientID,
		ClientSecret: result.ClientSecret,
	})
	if err != nil {
		ctx.Error(err)
		var authErr *auth.AuthorizeError
		if errors.As(err, &authErr) {
			ctx.JSON(authErr)
		}
	}

	var role *core.RoleEntity
	if len(userData.Roles) == 1 {
		roleEntity := userData.Roles[0]
		if !roleEntity.Blocked && (roleEntity.Organization == nil || !roleEntity.Organization.Blocked) {
			role = getRoleByRelationID(userData.Roles, roleEntity.UserRoleID)
		}
	}

	issued := time.Now()
	session := &core.Session{
		ID:           ulid.Make().String(),
		Subject:      userData.UserID,
		FirstName:    userData.FirstName,
		LastName:     userData.LastName,
		Code:         userData.PersonCode,
		Email:        userData.Email,
		LastAccessed: &issued,
		State:        string(core.SessionStateAuthorized),
		Role:         role,
		Roles:        userData.Roles,
		Rights:       userData.Rights,
	}

	_, err = a.sessionStore.Create(ctx, session)
	if err != nil {
		ctx.Error(err)
		return
	}

	err = a.auditProvider.SaveEvent(ctx, core.AuditEvent{
		EventCode:        "api_service_authorized",
		EventDescription: "API klients autorizēts",
		EventSuccessful:  err == nil,
		TransactionId:    uuid.NewString(), // TODO: izmantot padoto transakcijas ID ja ir pieejams
		Session:          session,
	})
	if err != nil {
		err = a.sessionStore.Delete(ctx, session.ID)
		if err != nil {
			ctx.Error(err)
		}

		ctx.Error(errors.New("error saving audit event"))
		return
	}

	ctx.JSON(a.sessionToResponse(ctx, session))
}

func (a *IDAuth) authorizationCode(ctx *azugo.Context) {
	if !a.config.ExposedConfig().UsesAuthorizationCodeGrant {
		ctx.StatusCode(fasthttp.StatusForbidden)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Authorization code grant is not enabled",
		})
	}

	redirectURI, err := ctx.Form.String("redirect_uri")
	if err != nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "redirect_uri field required",
		})
		return
	}

	code, err := ctx.Form.String("code")
	if err != nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "code field required",
		})
		return
	}

	ott, err := a.OTT().GetToken(ctx, code)
	if err != nil {
		ctx.Error(err)
		return
	}

	if ott == nil {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Invalid ott token",
		})
		return
	}

	if ott.RedirectURI != redirectURI {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Invalid redirect uri",
		})

		// invalidates token
		_, err := a.OTT().RedeemToken(ctx, code)
		if err != nil {
			ctx.Error(err)
		}
		return
	}

	ott, err = a.OTT().RedeemToken(ctx, code)
	if err != nil {
		ctx.Error(err)
	}

	ctx.JSON(&map[string]string{
		"access_token": ott.SessionToken,
	})
}

func (a *IDAuth) authorize(ctx *azugo.Context) {
	clientID, err := ctx.Query.String("client_id")
	if err != nil {
		ctx.Error(err)
		return
	}

	client, err := a.clientStore.GetClient(clientID)
	if err != nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidClient,
			Message: "Client not found",
		})
		return
	}

	redirectURI, err := ctx.Query.String("redirect_uri")
	if err != nil {
		ctx.Error(err)
		return
	}

	if !validRedirectURI(client, redirectURI) {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Redirect uri is not allowed",
		})
		return
	}

	providerID := ctx.Query.StringOptional("acr_values")
	if providerID == nil {
		providerID = ctx.Query.StringOptional("auth_type")
	}

	if providerID == nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "auth_type or acr_values parameters required",
		})
		return
	}

	var state string
	stateParam := ctx.Query.StringOptional("state")
	if stateParam != nil {
		state = *stateParam
	} else {
		state = ulid.Make().String()
	}

	provider, err := a.GetProvider(*providerID)
	if err != nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "auth provider not found",
		})
		return
	}
	nonce := ctx.Query.StringOptional("nonce")
	codeChallenge := ctx.Query.StringOptional("code_challenge")
	codeChallengeMethod := ctx.Query.StringOptional("code_challenge_method")

	correlation, err := a.correlationStore.Set(ctx, &core.Correlation{
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Nonce:               nonce,
		State:               &state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
	})
	if err != nil {
		ctx.Error(err)
		return
	}

	// If there is already session ID, redirect back
	if correlation != nil && len(correlation.ID) != 0 {
		if err := a.RedirectToCaller(ctx, correlation); err != nil {
			ctx.Error(err)
		}
		return
	}

	err = provider.Authorize(ctx, correlation)
	if err != nil {
		correlation.ErrorCode = string(auth.AuthErrServer)
		if err := a.RedirectToCaller(ctx, correlation); err != nil {
			ctx.Error(err)
		}
	}
}

func (a *IDAuth) callback(ctx *azugo.Context) {
	providerID := ctx.Params.String("id")
	if providerID == "" {
		ctx.StatusCode(fasthttp.StatusNotFound)
		return
	}

	if a.handleSignoutResponse(ctx) {
		return
	}

	sess, err := a.correlationStore.Get(ctx)
	if sess == nil && err == nil {
		err = errors.New("no session")
	}
	if err != nil {
		ctx.Error(err)
		return
	}

	if sess.ID != "" {
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		return
	}

	provider, err := a.GetProvider(providerID)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrInvalidCallback)
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		_ = a.correlationStore.Delete(ctx)
		return
	}

	errorParam := ctx.Query.StringOptional("error")
	if errorParam != nil {
		sess.ErrorCode = string(auth.AuthErrCanceled)
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		return
	}

	sess.ID = ulid.Make().String()
	authToken, err := provider.Callback(ctx, sess)
	if err != nil {
		a.app.Log().Error("Error in provider callback",
			zap.Error(err),
			zap.String("providerId", providerID),
		)

		sess.ErrorCode = string(auth.AuthErrInvalidCallback)
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		return
	}

	if sess.ManagedByProvider {
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		return
	}

	if err := a.handleUserData(ctx, sess, authToken); err != nil {
		a.app.Log().Error("Error getting user data",
			zap.Error(err))
		if err := a.RedirectToCaller(ctx, sess); err != nil {
			ctx.Error(err)
		}
		return
	}

	if signoutProvider, ok := provider.(core.ProviderCallbackSignout); ok && signoutProvider.RequiresSignoutCallback() {
		signoutURL := signoutProvider.GetSignoutURL()
		if signoutURL == "" {
			ctx.Error(&auth.AuthorizeError{
				Code:    auth.AuthErrServer,
				Message: "Signout URL not found for provider " + providerID,
			})
			return
		}

		ctx.Redirect(signoutURL)
		return
	}

	if err := a.RedirectToCaller(ctx, sess); err != nil {
		ctx.Error(err)
	}
}

func (a *IDAuth) deleteSession(ctx *azugo.Context) {
	sessionID := ctx.UserValue(SessionUserValueKey).(*core.Session).ID
	session, err := a.sessionStore.GetSession(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}

	err = a.auditProvider.SaveEvent(ctx, core.AuditEvent{
		EventCode:        "logout",
		EventDescription: "Logout",
		EventSuccessful:  err == nil,
		TransactionId:    uuid.NewString(),
		PersonData: []core.AuditEventPersonData{
			{
				FirstName:  session.FirstName,
				LastName:   session.LastName,
				PersonCode: session.Code,
			},
		},
		Session: session,
	})
	if err != nil {
		ctx.Error(err)
		return
	}

	err = a.sessionStore.Delete(ctx, sessionID)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

func (a *IDAuth) getSession(ctx *azugo.Context) {
	session, err := a.sessionStore.GetSession(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}
	ctx.JSON(a.sessionToResponse(ctx, session))
}

func (a *IDAuth) extendSession(ctx *azugo.Context) {
	sessionID := ctx.UserValue(SessionUserValueKey).(*core.Session).ID
	session, err := a.sessionStore.Extend(ctx, sessionID)
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(a.sessionToResponse(ctx, session))
}

func (a *IDAuth) getSessionAvailableRoles(ctx *azugo.Context) {
	sessionRoles := ctx.UserValue(SessionUserValueKey).(*core.Session).Roles
	ctx.JSON(sessionRoles)
}

func (a *IDAuth) sessionToResponse(ctx *azugo.Context, session *core.Session) *core.SessionResponse {
	if session == nil || session.State == string(core.SessionStateNone) {
		return &core.SessionResponse{Active: false}
	}

	organization, role, scopes := getCurrentRole(session)

	secondsToLive := session.GetSecondsToLive(a.config.ExposedConfig().SessionTimeout)
	if secondsToLive < 0 {
		a.deleteSession(ctx)
		return &core.SessionResponse{Active: false}
	}

	resp := &core.SessionResponse{
		ID:                 session.ID,
		Active:             true,
		State:              session.State,
		Subject:            session.Subject,
		Code:               session.Code,
		FirstName:          session.FirstName,
		LastName:           session.LastName,
		GivenName:          session.FirstName,
		FamilyName:         session.LastName,
		Email:              util.PtrString(session.Email),
		Institution:        organization,
		Role:               role,
		Scope:              scopes,
		SecondsToLive:      secondsToLive,
		SecondsToCountdown: int(a.config.ExposedConfig().SessionCountdown.Seconds()),
	}

	return resp
}

func (a *IDAuth) handleSignoutResponse(ctx *azugo.Context) bool {
	wsfed := &wsfed.WsFederation{}
	if wsfed.IsSignoutResponse(ctx) {
		ctx.StatusCode(fasthttp.StatusOK)
		return true
	}
	return false
}

func (a *IDAuth) createSessionFromUserData(sess *core.Correlation, userData *core.UserData) *core.Session {
	var role *core.RoleEntity
	var state core.SessionState

	if !a.config.ExposedConfig().SessionRequiresRole {
		state = core.SessionStateAuthorized
	} else if len(userData.Roles) == 0 {
		// Role required, but user will have no roles to pick from
		// Frontend should show a message regarding this in the role select screen
		state = core.SessionStateRequireRole
	} else if len(userData.Roles) == 1 {
		roleEntity := userData.Roles[0]
		if !roleEntity.Blocked && (roleEntity.Organization == nil || !roleEntity.Organization.Blocked) {
			role = getRoleByRelationID(userData.Roles, roleEntity.UserRoleID)
		}
		state = core.SessionStateAuthorized
	} else {
		state = core.SessionStateRequireRole
	}

	issued := time.Now()
	return &core.Session{
		ID:           sess.ID,
		Subject:      userData.UserID,
		FirstName:    userData.FirstName,
		LastName:     userData.LastName,
		Code:         userData.PersonCode,
		Email:        userData.Email,
		LastAccessed: &issued,
		State:        string(state),
		Role:         role,
		Roles:        userData.Roles,
		Rights:       userData.Rights,
	}
}

func (a *IDAuth) handleUserData(ctx *azugo.Context, sess *core.Correlation, authToken *core.AuthRequest) error {
	req := &core.GetUserDataRequest{
		Code:      authToken.PersonCode,
		FirstName: authToken.FirstName,
		LastName:  authToken.LastName,
		Email:     authToken.Email,
	}

	userData, err := a.authorizer.GetUserData(ctx, req)
	if err != nil {
		var authErr *auth.AuthorizeError
		if errors.As(err, &authErr) {
			sess.ErrorCode = string(authErr.Code)
		} else {
			sess.ErrorCode = string(auth.AuthErrServer)
		}
		return err
	}

	if _, err := a.correlationStore.Set(ctx, sess); err != nil {
		return err
	}

	session := a.createSessionFromUserData(sess, userData)

	_, err = a.sessionStore.Create(ctx, session)
	if err != nil {
		sess.ErrorCode = string(auth.AuthErrServer)
	}

	err = a.auditProvider.SaveEvent(ctx, core.AuditEvent{
		EventCode:        "login",
		EventDescription: "Login",
		EventSuccessful:  err == nil,
		TransactionId:    uuid.NewString(),
		PersonData: []core.AuditEventPersonData{
			{
				FirstName:  session.FirstName,
				LastName:   session.LastName,
				PersonCode: session.Code,
			},
		},
		Session: session,
	})
	if err != nil {
		err = a.sessionStore.Delete(ctx, session.ID)
		if err != nil {
			ctx.Error(err)
		}

		ctx.Error(errors.New("error saving audit event"))
		return err
	}

	return err
}

type UpdateSessionRoleRequest struct {
	RoleID string `json:"role" validate:"required" example:"1"`
}

func (a *IDAuth) setSessionRole(ctx *azugo.Context) {
	session := ctx.UserValue(SessionUserValueKey).(*core.Session)
	req := &UpdateSessionRoleRequest{}
	if err := ctx.Body.JSON(req); err != nil {
		ctx.Error(err)
		return
	}

	role := getRoleByRelationID(session.Roles, req.RoleID)
	if role == nil {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		return
	}

	if role.Organization != nil && role.Organization.Blocked {
		ctx.StatusCode(fasthttp.StatusForbidden)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrBlocked,
			Message: "Organization is blocked",
		})
		return
	}

	if role.Blocked {
		ctx.StatusCode(fasthttp.StatusForbidden)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrBlocked,
			Message: "Role is blocked",
		})
		return
	}

	session.Role = role
	if session.State == string(core.SessionStateRequireRole) {
		session.State = string(core.SessionStateAuthorized)
	}
	session, err := a.sessionStore.Update(ctx, session)
	if err != nil {
		ctx.Error(err)
		return
	}

	err = a.auditProvider.SaveEvent(ctx, core.AuditEvent{
		EventCode:        "role_change",
		EventDescription: "Role change",
		EventSuccessful:  err == nil,
		TransactionId:    uuid.NewString(),
		PersonData: []core.AuditEventPersonData{
			{
				FirstName:  session.FirstName,
				LastName:   session.LastName,
				PersonCode: session.Code,
			},
		},
		Session: session,
	})
	if err != nil {
		ctx.Error(err)
		return
	}

	ctx.JSON(a.sessionToResponse(ctx, session))
}

func validRedirectURI(client *core.Client, redirectURI string) bool {
	for _, uri := range client.RedirectURI {
		if strings.Contains(uri, redirectURI) {
			return true
		}
	}
	return false
}

func getRoleByRelationID(roles []*core.RoleEntity, userRoleID string) *core.RoleEntity {
	for _, role := range roles {
		if role.UserRoleID == userRoleID {
			return role
		}
	}
	return nil
}

func getCurrentRole(session *core.Session) (*core.UserOrganization, *core.RoleBasic, []string) {
	var organization *core.UserOrganization
	var role *core.RoleBasic

	scopes := make([]string, 0, len(session.Rights))

	if session.Role == nil {
		return organization, role, scopes
	}

	role = &core.RoleBasic{
		ID:          session.Role.ID,
		UserRoleID:  session.Role.UserRoleID,
		Code:        session.Role.Code,
		Name:        session.Role.Name,
		Description: &session.Role.Description,
	}

	if session.Role.Organization != nil {
		organization = &core.UserOrganization{
			ID:                 session.Role.Organization.ID,
			Code:               session.Role.Organization.Code,
			Name:               session.Role.Organization.Name,
			TypeID:             session.Role.Organization.TypeID,
			UserOrganizationID: session.Role.Organization.UserOrganizationID,
		}
	}

	for _, right := range session.Rights {
		if right.UserRoleID == session.Role.UserRoleID {
			if right.LevelCode == "" {
				scopes = append(scopes, right.RightCode)
			} else {
				scopes = append(scopes, fmt.Sprintf("%s:%s", right.RightCode, right.LevelCode))
			}
		}
	}

	return organization, role, scopes
}
