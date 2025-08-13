package idauth

import (
	"crypto/x509"
	"encoding/base64"
	"net/url"

	"github.com/nobid-lsp-latvia/lx-idauth/core"

	"azugo.io/azugo"
	"azugo.io/azugo/wsfed"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

const (
	ClaimTypeAuthorityFullName string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/AuthorityFullName"
	ClaimTypeURAuthorityCode   string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/URAuthorityCode"
	ClaimTypeVIRegistryNumber  string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/VIRegistryNumber"
	ClaimTypeVIAuthorityCode   string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/VIAuthorityCode"
	ClaimTypeVIMedicalCode     string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/VIMedicalCode"
	ClaimTypeDelegations       string = "http://ip.vm.gov.lv/ws/2011/11/identity/claims/Delegations"
)

// ErrExternalAuthNotFoundError is returned when vpm is not found.
type ErrExternalAuthNotFoundError struct {
	ExternalAuthID string
}

func (e ErrExternalAuthNotFoundError) Error() string {
	return "External auth not found"
}

type VPMAuthProvider struct {
	auth       *IDAuth
	config     *core.AuthProviderConfig
	wsfed      *wsfed.WsFederation
	signoutURL string
}

func NewVPMService(auth *IDAuth, conf *core.AuthProviderConfig) (*VPMAuthProvider, error) {
	wsfed, err := wsfed.New(auth.app, conf.MetadataURL)
	if err != nil {
		return nil, err
	}
	if len(conf.IDPEndpoint) > 0 {
		var u *url.URL
		if u, err = url.Parse(conf.IDPEndpoint); err != nil {
			return nil, err
		}
		wsfed.IDPEndpoint = u
	}
	if len(conf.SigningCertificatePEM) > 0 {
		certData, err := base64.StdEncoding.DecodeString(conf.SigningCertificatePEM)
		if err != nil {
			return nil, err
		}

		idpCert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, err
		}

		// If custom signing certificate is provided, clear store to not use one received from metadata
		wsfed.ClearCertificateStore()
		wsfed.AddTrustedSigningCertificate(idpCert)
	}
	return &VPMAuthProvider{
		auth:       auth,
		config:     conf,
		wsfed:      wsfed,
		signoutURL: "",
	}, nil
}

func (p *VPMAuthProvider) Authorize(ctx *azugo.Context, sess *core.Correlation) error {
	url, err := p.wsfed.SigninURL(ctx, p.config.Realm)
	if err != nil {
		ctx.Log().Error("Error while gettting sign in url", zap.Error(err))
		ctx.StatusCode(fasthttp.StatusInternalServerError)
		return nil
	}

	ctx.Redirect(url)
	return nil
}

func (p *VPMAuthProvider) Callback(ctx *azugo.Context, sess *core.Correlation) (*core.AuthRequest, error) {
	if p.wsfed.IsSignoutResponse(ctx) {
		ctx.StatusCode(fasthttp.StatusOK)
		return nil, nil
	}

	token, err := p.wsfed.ReadResponse(ctx, wsfed.TokenAudience(p.config.Realm), wsfed.SaveToken(true))
	if err != nil {
		return nil, err
	}

	if p.config.PostCallbackSignout {
		signoutURL, err := p.wsfed.SignoutURL(p.config.Realm, wsfed.WithRequestWreply(ctx.BaseURL()+"/callback/"+p.config.ID))
		if err != nil {
			return nil, err
		}
		p.signoutURL = signoutURL
	}

	authToken := p.convertVPM(token)
	authToken.IPAddress = ctx.IP().String()
	authToken.Nonce = sess.Nonce
	return authToken, nil
}

func (p *VPMAuthProvider) GetSignoutURL() string {
	return p.signoutURL
}

func (p *VPMAuthProvider) RequiresSignoutCallback() bool {
	return p.config.PostCallbackSignout
}

func (ws *VPMAuthProvider) convertVPM(p *wsfed.Token) *core.AuthRequest {
	return &core.AuthRequest{
		PersonCode: p.ClaimValue(wsfed.ClaimTypePrivatePersonalIdentifier),
		FirstName:  p.ClaimValue(wsfed.ClaimTypeGivenName),
		LastName:   p.ClaimValue(wsfed.ClaimTypeSurname),
		SessionID:  p.ClaimValue(wsfed.ClaimTypeSID),
		Token:      p.Validated,
	}
}
