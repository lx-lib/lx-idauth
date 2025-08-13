package core

import (
	"time"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
)

type Session struct {
	ID            string
	State         string
	Code          string
	Subject       string
	FirstName     string
	LastName      string
	Email         string
	Role          *RoleEntity
	Specialty     string
	ValidDateTill *time.Time
	Scope         []string
	LastAccessed  *time.Time
	Roles         []*RoleEntity
	Rights        []*GrantedRightListEntity
	Metadata      map[string]string
}

func (s *Session) GetSecondsToLive(sessionTimeout time.Duration) int {
	return int((sessionTimeout - time.Now().UTC().Sub(*s.LastAccessed)).Seconds())
}

// IsActive returns true if session is active.
func (s *Session) IsActive() bool {
	return s != nil && s.State != string(SessionStateNone)
}

// IsAuthorized returns true if session is authorized.
func (s *Session) IsAuthorized() bool {
	return s.IsActive() && s.State == string(SessionStateAuthorized)
}

// Scopes returns merged session and role scopes.
func (s *Session) Scopes() []string {
	scope := make([]string, len(s.Scope))
	m := make(map[string]struct{})
	for i, v := range s.Scope {
		if _, ok := m[v]; ok {
			continue
		}
		m[v] = struct{}{}
		scope[i] = v
	}
	return scope
}

func (s *Session) ToClaims() map[string]token.ClaimStrings {
	claims := map[string]token.ClaimStrings{
		"sid":         {s.ID},
		"sub":         {s.Subject},
		"given_name":  {s.FirstName},
		"family_name": {s.LastName},
		"scope":       s.Scope,
	}

	if s.Role != nil && s.Role.Organization != nil {
		claims["org_id"] = []string{s.Role.Organization.ID}
		claims["org_code"] = []string{s.Role.Organization.Code}
		claims["org_name"] = []string{s.Role.Organization.Name}
	}

	return claims
}

type SessionStore interface {
	Create(ctx *azugo.Context, session *Session) (*Session, error)
	Update(ctx *azugo.Context, session *Session) (*Session, error)
	GetSession(ctx *azugo.Context) (*Session, error)
	GetSessionByID(ctx *azugo.Context, sessionId string) (*Session, error)
	Extend(ctx *azugo.Context, sessionId string) (*Session, error)
	Delete(ctx *azugo.Context, sessionId string) error
}

// SessionState represents the session state.
type SessionState string

const (
	SessionStateNone                SessionState = "none"
	SessionStateRequireAgreement    SessionState = "req_agreement"
	SessionStateRequireRole         SessionState = "req_role"
	SessionStateRequireOrganization SessionState = "req_organization"
	SessionStateAuthorized          SessionState = "authorized"
	SessionStateBlocked             SessionState = "blocked"
	SessionStateNotExist            SessionState = "not_exist"
)

// Role represents the role.
type Role struct {
	Code        string   `json:"code"`
	AppCode     string   `json:"appCode"`
	AppURL      string   `json:"appUrl"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Scope       []string `json:"scope"`
}

var EmptySession = &Session{State: string(SessionStateNone)}

// UserOrganization represents user organization.
type UserOrganization struct {
	// Primary entity identifier
	ID string `json:"id"`
	// Code is the organization code
	Code string `json:"code" example:"40000000000"`
	// Name is the organization name
	Name string `json:"name" example:"Test Organization"`
	// TypeID is the organization type identifier
	TypeID string `json:"type_id" example:"1"`
	// UserOrganizationID is the user organization relation identifier
	UserOrganizationID string `json:"user_organization_id"`
}

// RoleBasic represents a role in the system.
type RoleBasic struct {
	// Primary entity identifier
	ID string `json:"id" example:"1"`
	// User Role relation identifier
	UserRoleID string `json:"user_role_id" example:"1"`
	// Code is the role's unique identifier.
	Code string `json:"code" example:"ADMIN"`
	// AppCode is the code of application this role is bound to.
	AppCode string `json:"appCode,omitempty" example:"SOMEAPP"`
	// Name is the role's name.
	Name string `json:"name" example:"Administrator"`
	// Description is the role's description.
	Description *string `json:"description,omitempty" example:"Role for system administration"`
	// System describes if the role is system role.
	System bool `json:"system,omitempty" example:"true"`
	// AppURL is the URL of selected role's application
	AppURL string `json:"appUrl"`
}

// SessionResponse is the response body for the session data

type SessionResponse struct {
	// ID is the session ID
	ID string `json:"sid,omitempty" example:"01FMG08GHT6QJE32XHGVMWB82D"`
	// Active is the session active flag
	Active bool `json:"active"`
	// State is the session state
	State string `json:"st" example:"authorized"`
	// Subject is the authorized users unique identifier
	Subject string `json:"sub,omitempty" example:"2"`
	// Code is unique person identifier
	Code string `json:"code,omitempty" example:"11111111111"`
	// FirstName is the authorized users first name
	FirstName string `json:"firstName,omitempty" example:"Jānis"`
	// LastName is the authorized users last name
	LastName string `json:"lastName,omitempty" example:"Testiņš"`
	// FirstName is the authorized users first name
	GivenName string `json:"given_name,omitempty" example:"Jānis"` // For backwards compatibility
	// LastName is the authorized users last name
	FamilyName string `json:"family_name,omitempty" example:"Testiņš"` // For backwards compatibility
	// Institution is the authorized users organization
	Institution *UserOrganization `json:"institution,omitempty"`
	// Role is the authorized users role
	Role *RoleBasic `json:"role,omitempty"`
	// Scope is the list of user rights
	Scope []string `json:"scope" example:"[\"admin/settings:read\"]"`
	// Session timeout in seconds
	SecondsToLive int `json:"secondsToLive"`
	// Seconds before session expiration when session countdown should appear
	SecondsToCountdown int `json:"secondsToCountdown"`
	// Email is the email address of the user's position.
	Email *string `json:"email,omitempty" example:"jancigs.testins@test-organization.xx"`
	// Phone is the phone number of the user's position.
	Phone *string `json:"phone,omitempty" example:"+37100000000"`
}

// UserOrganizationResponse is the response body for the organization data user has access to.
type UserOrganizationResponse []UserOrganization

// UserOrganization represents user organization.
type UserOrganizationRole struct {
	// OrganizationCode is the organization code
	OrganizationCode string `json:"organizationCode" example:"40000000000"`
	// OrganizationName is the organization name
	OrganizationName string `json:"organizationName" example:"Test Organization"`
	// RoleCode is the role code
	RoleCode string `json:"roleCode" example:"TEST_ROLE"`
	// RoleName is the role name
	RoleName string `json:"roleName" example:"Test role"`
	// Position ID is the position identifier
	PositionID int `json:"positionId" example:"123"`
	// PositionName is the position name
	PositionName string `json:"positionName" example:"Test position"`
	// Email is the email address of the user's position.
	Email *string `json:"email,omitempty" example:"jancigs.testins@test-organization.xx"`
	// Phone is the phone number of the user's position.
	Phone *string `json:"phone,omitempty" example:"+37100000000"`
	// AppURL is the URL of selected role's application
	AppURL string `json:"appUrl,omitempty" example:"https://example.com"`
}

type UserOrganizationRoleResponse []UserOrganizationRole
