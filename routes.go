package idauth

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lx-lib/lx-idauth/audit"
	"github.com/lx-lib/lx-idauth/core"
	"github.com/lx-lib/lx-idauth/core/auth"
	"github.com/lx-lib/lx-idauth/core/util"

	"azugo.io/azugo"
	"azugo.io/azugo/wsfed"
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
		a.clientCredentials(ctx, core.GRANT_TYPE_CLIENT_CREDENTIALS)
	case core.GRANT_TYPE_IAM:
		a.clientCredentials(ctx, core.GRANT_TYPE_IAM)
	case "authorization_code":
		a.authorizationCode(ctx)
	default:
		a.clientCredentials(ctx, grantType)
	}
}

func (a *IDAuth) clientCredentials(ctx *azugo.Context, grantType string) {
	var pfasConfig *core.PfasAuthTokenValidatorConfig
	var iamConfig *core.IAMAuthTokenValidatorConfig

	switch grantType {
	case core.GRANT_TYPE_PFAS:
		if !a.config.ExposedConfig().UsesPfasGrant {
			ctx.StatusCode(fasthttp.StatusForbidden)
			ctx.JSON(&auth.AuthorizeError{
				Code:    auth.AuthErrInvalidRequest,
				Message: "PFAS grant is not enabled",
			})
			return
		}
	case core.GRANT_TYPE_IAM:
		if !a.config.ExposedConfig().UsesIAMGrant {
			ctx.StatusCode(fasthttp.StatusForbidden)
			ctx.JSON(&auth.AuthorizeError{
				Code:    auth.AuthErrInvalidRequest,
				Message: "IAM grant is not enabled",
			})
			return
		}
	}

	if a.config.ExposedConfig().UsesPfasGrant {
		pfasConfig = &core.PfasAuthTokenValidatorConfig{
			IntrospectionURL:          a.config.ExposedConfig().IntrospectionURL,
			IntrospectionClientId:     a.config.ExposedConfig().IntrospectionClientID,
			IntrospectionClientSecret: a.config.ExposedConfig().IntrospectionClientSecret,
		}
	}

	if a.config.ExposedConfig().UsesIAMGrant {
		iamConfig = &core.IAMAuthTokenValidatorConfig{
			Issuer:  a.config.ExposedConfig().IAMIssuer,
			JWKSURL: a.config.ExposedConfig().IAMJWKSURL,
		}
	}

	validator, err := core.NewTokenValidator(grantType, a.clientStore, pfasConfig, iamConfig)
	if err != nil {
		ctx.Error(err)
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		return
	}

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
		return
	}

	var role *core.RoleEntity
	if len(userData.Roles) == 1 {
		roleEntity := userData.Roles[0]
		if !roleEntity.Blocked && (roleEntity.Organization == nil || !roleEntity.Organization.Blocked) {
			role = getRoleByRelationID(userData.Roles, roleEntity.UserRoleID)
		}
	}

	issued := time.Now().UTC()
	ipStr := ctx.IP().String()
	userAgentStr := ctx.UserAgent()

	session := &core.Session{
		ID:              ulid.Make().String(),
		Subject:         userData.UserID,
		FirstName:       userData.FirstName,
		LastName:        userData.LastName,
		Code:            userData.PersonCode,
		Email:           userData.Email,
		PhoneNumber:     userData.PhoneNumber,
		LastAccessed:    &issued,
		State:           string(core.SessionStateAuthorized),
		Role:            role,
		Roles:           userData.Roles,
		Rights:          userData.Rights,
		IsServiceClient: userData.IsServiceClient,
		IsTOSAccepted:   userData.IsTOSAccepted,
		Device: &core.DeviceEntity{
			IPAddress: &ipStr,
			UserAgent: &userAgentStr,
		},
	}

	_, err = a.sessionStore.Create(ctx, session)

	auditData := &core.AuditEvent{
		Session: session,
		Events: &audit.SaveAuditEventJSONRequestBody{
			{
				EventCode:        util.PtrString("api_service_authorized"),
				EventDescription: util.PtrString("API klients autorizēts"),
				EventSuccessful:  util.PtrBool(err == nil),
				IsApiUser:        util.PtrBool(session.IsServiceClient),
				UserFullName:     util.PtrString(strings.TrimSpace(session.FirstName + " " + session.LastName)),
				UserCode:         util.PtrString(session.Code),
				UserId:           util.PtrString(session.Subject),
				UserSessionId:    util.PtrString(session.ID),
			},
		},
	}

	if _, auditErr := a.auditProvider.SaveEvent(ctx, auditData); auditErr != nil && err == nil {
		err = auditErr
	}

	if err != nil {
		_ = a.sessionStore.Delete(ctx, session.ID)
		ctx.Error(err)
		return
	}

	ctx.JSON(&core.AccessTokenResponse{
		AccessToken: session.ID,
		TokenType:   core.AuthorizationBearer,
		ExpiresIn:   core.GetSecondsToLive(a.config.ExposedConfig().SessionTimeout, session.LastAccessed),
	})
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

	// redeem the token instead of getting it, so it can't be used again
	ott, err := a.OTT().RedeemToken(ctx, code)
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

	validRedirect := false
	if len(ott.RedirectURIs) > 0 {
		for _, uri := range ott.RedirectURIs {
			if uri == redirectURI {
				validRedirect = true
				break
			}
		}
	} else {
		validRedirect = (ott.RedirectURI == redirectURI)
	}

	if !validRedirect {
		ctx.StatusCode(fasthttp.StatusUnauthorized)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Invalid redirect uri",
		})

		return
	}

	ctx.JSON(&core.AccessTokenResponse{
		AccessToken: ott.SessionToken,
		TokenType:   core.AuthorizationBearer,
		ExpiresIn:   core.GetSecondsToLive(a.config.ExposedConfig().SessionTimeout, ott.SessionCreated),
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

	// Azugo utils.B2S causes corrupted cached values for OICD providers
	// Deep copies of variables are created to avoid this
	// https://github.com/azugo/azugo/issues/20
	// https://github.com/lx-lib/lx-idauth/issues/58
	correlation, err := a.correlationStore.Set(ctx, &core.Correlation{
		ClientID:            util.CloneStr(clientID),
		RedirectURI:         util.CloneStr(redirectURI),
		Nonce:               util.CloneStrPtr(nonce),
		State:               util.CloneStrPtr(&state),
		CodeChallenge:       util.CloneStrPtr(codeChallenge),
		CodeChallengeMethod: util.CloneStrPtr(codeChallengeMethod),
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

		var authErr *auth.AuthorizeError
		if errors.As(err, &authErr) {
			sess.ErrorCode = string(authErr.Code)
		} else {
			sess.ErrorCode = string(auth.AuthErrInvalidCallback)
		}

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

		ctx.RedirectUnsafe(signoutURL)
		return
	}

	if err := a.RedirectToCaller(ctx, sess); err != nil {
		ctx.Error(err)
	}
}

func (a *IDAuth) oidcLogoutCallback(ctx *azugo.Context) {
	sess, err := a.correlationStore.Get(ctx)
	if err != nil {
		ctx.Error(err)
		return
	}

	if sess == nil || sess.ID == "" {
		ctx.StatusCode(fasthttp.StatusNoContent)
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

	logoutURL := a.providerLogoutURL(session)

	err = a.sessionStore.Delete(ctx, sessionID)

	auditData := &core.AuditEvent{
		Session: session,
		Events: &audit.SaveAuditEventJSONRequestBody{
			{
				EventCode:        util.PtrString("logout"),
				EventDescription: util.PtrString("Atslēgšanās"),
				EventSuccessful:  util.PtrBool(err == nil),
				PersonAuditData: &[]struct {
					FullName   *string `json:"fullName,omitempty"`
					PersonCode *string `json:"personCode,omitempty"`
				}{},
			},
		},
	}

	if _, auditErr := a.auditProvider.SaveEvent(ctx, auditData); auditErr != nil && err == nil {
		err = auditErr
	}

	if err != nil {
		ctx.Error(err)
		return
	}

	if logoutURL != "" {
		ctx.StatusCode(fasthttp.StatusOK)
		ctx.Text(logoutURL)
		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// providerLogoutURL returns the upstream IDP logout URL when the session's
// provider implements core.ProviderLogout and an id_token is available.
func (a *IDAuth) providerLogoutURL(session *core.Session) string {
	if session == nil || session.Metadata == nil {
		return ""
	}
	providerID := session.Metadata[core.SessionMetaProviderID]
	idToken := session.Metadata[core.SessionMetaIDToken]
	if providerID == "" || idToken == "" {
		return ""
	}
	provider, err := a.GetProvider(providerID)
	if err != nil {
		return ""
	}
	logout, ok := provider.(core.ProviderLogout)
	if !ok {
		return ""
	}
	return logout.LogoutURL(idToken)
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
	session := ctx.UserValue(SessionUserValueKey).(*core.Session)
	sessionRoles := session.Roles
	ctx.JSON(sessionRoles)
}

func (a *IDAuth) sessionToResponse(ctx *azugo.Context, session *core.Session) *core.SessionResponse {
	if session == nil || session.State == string(core.SessionStateNone) {
		return &core.SessionResponse{Active: false}
	}

	organization, role, scopes := getCurrentRole(session)

	secondsToLive := core.GetSecondsToLive(a.config.ExposedConfig().SessionTimeout, session.LastAccessed)
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
		PhoneNumber:        session.PhoneNumber,
		Institution:        organization,
		Role:               role,
		Scope:              scopes,
		SecondsToLive:      secondsToLive,
		SecondsToCountdown: int(a.config.ExposedConfig().SessionCountdown.Seconds()),
		IsServiceClient:    session.IsServiceClient,
		IsTOSAccepted:      util.PtrBool(session.IsTOSAccepted),
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

	if a.config.ExposedConfig().AuthorizerRequiresTOS && !userData.IsTOSAccepted {
		state = core.SessionStateRequireAgreement
	} else if !a.config.ExposedConfig().SessionRequiresRole {
		state = core.SessionStateAuthorized
	} else if len(userData.Roles) == 0 {
		state = core.SessionStateRequireRole
	} else if len(userData.Roles) == 1 {
		state = core.SessionStateRequireRole

		roleEntity := userData.Roles[0]

		if !roleEntity.Blocked && (roleEntity.Organization == nil || !roleEntity.Organization.Blocked) {
			role = getRoleByRelationID(userData.Roles, roleEntity.UserRoleID)

			state = core.SessionStateAuthorized
		}
	} else {
		state = core.SessionStateRequireRole
	}

	issued := time.Now().UTC()
	return &core.Session{
		ID:              sess.ID,
		Subject:         userData.UserID,
		FirstName:       userData.FirstName,
		LastName:        userData.LastName,
		Code:            userData.PersonCode,
		Email:           userData.Email,
		PhoneNumber:     userData.PhoneNumber,
		LastAccessed:    &issued,
		State:           string(state),
		Role:            role,
		Roles:           userData.Roles,
		Rights:          userData.Rights,
		IsServiceClient: userData.IsServiceClient,
		IsTOSAccepted:   userData.IsTOSAccepted,
	}
}

func (a *IDAuth) termsAccept(ctx *azugo.Context) {
	session, err := a.sessionStore.GetSession(ctx)
	if err != nil {
		return
	}

	authToken := &core.AuthRequest{
		PersonCode: session.Code,
		FirstName:  session.FirstName,
		LastName:   session.LastName,
		Email:      session.Email,
		ProviderID: "",
		TOS:        true,
	}

	err = a.handleUserData(ctx, nil, authToken)

	auditData := &core.AuditEvent{
		Session: session,
		Events: &audit.SaveAuditEventJSONRequestBody{
			{
				EventCode:        util.PtrString("terms_accept"),
				EventDescription: util.PtrString("Piekrišana platformas lietošanas noteikumiem"),
				EventType:        util.PtrString("POST"),
				EventSuccessful:  util.PtrBool(err == nil),
				PersonAuditData: &[]struct {
					FullName   *string `json:"fullName,omitempty"`
					PersonCode *string `json:"personCode,omitempty"`
				}{},
			},
		},
	}

	if _, auditErr := a.auditProvider.SaveEvent(ctx, auditData); auditErr != nil && err == nil {
		err = auditErr
	}

	if err != nil {
		ctx.Error(err)
		return
	}
}

func (a *IDAuth) handleUserData(ctx *azugo.Context, sess *core.Correlation, authToken *core.AuthRequest) error {
	req := &core.GetUserDataRequest{
		Code:          authToken.PersonCode,
		FirstName:     authToken.FirstName,
		LastName:      authToken.LastName,
		Email:         authToken.Email,
		ProviderID:    authToken.ProviderID,
		IsTOSAccepted: authToken.TOS,
		Organizations: authToken.Organizations,
		RawClaims:     authToken.RawClaims,
	}

	userData, err := a.authorizer.GetUserData(ctx, req)
	if err != nil {
		var authErr *auth.AuthorizeError
		if sess != nil {
			if errors.As(err, &authErr) {
				sess.ErrorCode = string(authErr.Code)
			} else {
				sess.ErrorCode = string(auth.AuthErrServer)
			}
		}
		return err
	}

	if sess == nil {
		current, getErr := a.sessionStore.GetSession(ctx)
		if getErr != nil {
			return getErr
		}

		issued := time.Now().UTC()
		ipStr := ctx.IP().String()
		userAgentStr := ctx.UserAgent()

		current.Subject = userData.UserID
		current.FirstName = userData.FirstName
		current.LastName = userData.LastName
		current.Code = userData.PersonCode
		current.Email = userData.Email
		current.PhoneNumber = userData.PhoneNumber
		current.Roles = userData.Roles
		current.Rights = userData.Rights
		current.IsServiceClient = userData.IsServiceClient
		current.IsTOSAccepted = userData.IsTOSAccepted
		current.LastAccessed = &issued
		if current.Device == nil {
			current.Device = &core.DeviceEntity{}
		}
		current.Device.IPAddress = &ipStr
		current.Device.UserAgent = &userAgentStr

		if userData.IsTOSAccepted {
			var role *core.RoleEntity
			var state core.SessionState

			if !a.config.ExposedConfig().SessionRequiresRole {
				state = core.SessionStateAuthorized
			} else if len(userData.Roles) == 0 {
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

			current.State = string(state)
			current.Role = role
		}

		if _, err := a.sessionStore.Update(ctx, current); err != nil {
			return err
		}

		return nil
	}

	session := a.createSessionFromUserData(sess, userData)

	if !sess.ManagedByProvider {
		sess.SessionCreated = util.CloneTimePtr(session.LastAccessed)
	}

	if _, err := a.correlationStore.Set(ctx, sess); err != nil {
		return err
	}

	ipStr := ctx.IP().String()
	userAgentStr := ctx.UserAgent()

	session.Device = &core.DeviceEntity{
		IPAddress: &ipStr,
		UserAgent: &userAgentStr,
	}

	if authToken.ProviderID != "" || authToken.Token != "" {
		if session.Metadata == nil {
			session.Metadata = make(map[string]string, 2)
		}
		if authToken.ProviderID != "" {
			session.Metadata[core.SessionMetaProviderID] = authToken.ProviderID
		}
		if authToken.Token != "" {
			session.Metadata[core.SessionMetaIDToken] = authToken.Token
		}
	}

	_, err = a.sessionStore.Create(ctx, session)

	if a.config.ExposedConfig().AuthorizerRequiresTOS && !userData.IsTOSAccepted {
		tos, derr := buildTOSRedirect(sess.RedirectURI, a.config.ExposedConfig().TOSEndpoint)
		if derr != nil {
			return derr
		}

		sess.TOSTargetURI = &tos
		if _, err := a.correlationStore.Set(ctx, sess); err != nil {
			return err
		}
	}

	auditData := &core.AuditEvent{
		Session: session,
		Events: &audit.SaveAuditEventJSONRequestBody{
			{
				EventCode:        util.PtrString("login"),
				EventDescription: util.PtrString("Pieslēgšanās"),
				EventType:        util.PtrString("POST"),
				EventSuccessful:  util.PtrBool(err == nil),
				IsApiUser:        util.PtrBool(session.IsServiceClient),
				PersonAuditData: &[]struct {
					FullName   *string `json:"fullName,omitempty"`
					PersonCode *string `json:"personCode,omitempty"`
				}{},
				UserFullName:  util.PtrString(strings.TrimSpace(session.FirstName + " " + session.LastName)),
				UserCode:      util.PtrString(session.Code),
				UserId:        util.PtrString(session.Subject),
				UserSessionId: util.PtrString(session.ID),
			},
		},
	}

	if _, auditErr := a.auditProvider.SaveEvent(ctx, auditData); auditErr != nil && err == nil {
		err = auditErr
	}

	if err != nil {
		_ = a.sessionStore.Delete(ctx, session.ID)
		sess.ErrorCode = string(auth.AuthErrServer)
		ctx.Error(err)
		return err
	}

	return err
}

type UpdateSessionRoleRequest struct {
	RoleID string `json:"role" validate:"required" example:"1"`
}

func (a *IDAuth) setSessionRole(ctx *azugo.Context) {
	session := ctx.UserValue(SessionUserValueKey).(*core.Session)

	if !session.IsRoleRequired() && !session.IsAuthorized() {
		ctx.StatusCode(fasthttp.StatusBadRequest)
		ctx.JSON(&auth.AuthorizeError{
			Code:    auth.AuthErrInvalidRequest,
			Message: "Role selection not allowed in current session state",
		})
		return
	}

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

	auditData := &core.AuditEvent{
		Session: session,
		Events: &audit.SaveAuditEventJSONRequestBody{
			{
				EventCode:        util.PtrString("role_change"),
				EventDescription: util.PtrString("Lomas maiņa"),
				EventType:        util.PtrString("PUT"),
				EventSuccessful:  util.PtrBool(err == nil),
				PersonAuditData: &[]struct {
					FullName   *string `json:"fullName,omitempty"`
					PersonCode *string `json:"personCode,omitempty"`
				}{},
			},
		},
	}

	if _, auditErr := a.auditProvider.SaveEvent(ctx, auditData); auditErr != nil && err == nil {
		err = auditErr
	}

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

// buildTOSRedirect builds the TOS page URL from an original redirect_uri and endpoint.
// Rules:
// - If endpoint is empty, defaults to "/terms-of-service".
// - Endpoint is normalized to start with a single leading slash.
// - If original path ends with "/auth-done", replace that suffix with endpoint, preserving any prefix path.
// - Otherwise, use scheme+host of original and set path to endpoint.
func buildTOSRedirect(original string, endpoint string) (string, error) {
	if endpoint == "" {
		endpoint = "/terms-of-service"
	}
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	u, err := url.Parse(original)
	if err != nil {
		return "", err
	}

	if strings.HasSuffix(u.Path, "/auth-done") {
		base := strings.TrimSuffix(u.Path, "/auth-done")
		u.Path = base + endpoint
	} else {
		u.Path = endpoint
	}
	u.RawQuery = ""
	return u.String(), nil
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
		DataScopes:  session.Role.DataScopes,
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
