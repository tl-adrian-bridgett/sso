package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/buzzfeed/sso/internal/auth/circuit"
	log "github.com/buzzfeed/sso/internal/pkg/logging"
	"github.com/buzzfeed/sso/internal/pkg/sessions"
	"github.com/datadog/datadog-go/statsd"
)

// AmazonCognitoProvider is an implementation of the Provider interface.
type AmazonCognitoProvider struct {
	*ProviderData
	StatsdClient *statsd.Client
	cb           *circuit.Breaker
}

// NewAmazonCognitoProvider returns a new AmazonCognitoProvider and sets the provider url endpoints.
func NewAmazonCognitoProvider(p *ProviderData, OrgURL string) (*AmazonCognitoProvider, error) {
	if OrgURL == "" {
		return nil, errors.New("missing setting: amazon_cognito_url")
	}

	p.ProviderName = "AmazonCognito"
	scheme := "https"

	// interact with resource owner and obtain an authorization grant
	p.SignInURL = &url.URL{
		Scheme: scheme,
		Host:   OrgURL,
		Path:   "/oauth2/authorize",
	}

	// returns access tokens, ID tokens or refresh tokens
	p.RedeemURL = &url.URL{
		Scheme: scheme,
		Host:   OrgURL,
		Path:   "/oauth2/token",
	}

	// TODO: Cognito doesn't provide a revoke endpoint to log out users
	// revokes an access or refresh token
	p.RevokeURL = &url.URL{}

	// takes an access token and returns claims for the currently logged-in user
	p.ProfileURL = &url.URL{
		Scheme: scheme,
		Host:   OrgURL,
		Path:   "/oauth2/userInfo",
	}

	// TODO: This isn't a validate endpoint but repeating userinfo
	// takes token as a URL query and returns active/inactive, and further info if active.
	p.ValidateURL = &url.URL{
		Scheme: scheme,
		Host:   OrgURL,
		Path:   "/oauth2/userInfo",
	}

	if p.Scope == "" {
		p.Scope = "openid profile email aws.cognito.signin.user.admin"
	}

	amazonCognitoProvider := &AmazonCognitoProvider{
		ProviderData: p,
	}

	amazonCognitoProvider.cb = circuit.NewBreaker(&circuit.Options{
		HalfOpenConcurrentRequests: 2,
		OnStateChange:              amazonCognitoProvider.cbStateChange,
		OnBackoff:                  amazonCognitoProvider.cbBackoff,
		ShouldTripFunc:             func(c circuit.Counts) bool { return c.ConsecutiveFailures >= 3 },
		ShouldResetFunc:            func(c circuit.Counts) bool { return c.ConsecutiveSuccesses >= 6 },
		BackoffDurationFunc: circuit.ExponentialBackoffDuration(
			time.Duration(200)*time.Second, time.Duration(500)*time.Millisecond,
		),
	})

	return amazonCognitoProvider, nil
}

// Sets the providers StatsdClient
func (p *AmazonCognitoProvider) SetStatsdClient(statsdClient *statsd.Client) {
	p.StatsdClient = statsdClient
}

// ValidateSessionState attempts to validate the session state's access token.
func (p *AmazonCognitoProvider) ValidateSessionState(s *sessions.SessionState) bool {
	if s.AccessToken == "" {
		return false
	}

	_, err := p.GetUserProfile(s.AccessToken)
	if err != nil {
		return false
	}

	return true
}

// GetSignInURL returns the sign in url with typical oauth parameters
func (p *AmazonCognitoProvider) GetSignInURL(redirectURI, state string) string {
	// https://developer.okta.com/docs/api/resources/oidc/#authorize
	var a url.URL
	a = *p.SignInURL

	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("response_type", "code")
	params.Set("client_id", p.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Add("state", state)
	params.Set("identity_provider", "COGNITO")
	params.Add("scope", p.Scope)

	a.RawQuery = params.Encode()
	return a.String()
}

func (p *AmazonCognitoProvider) amazonCognitoRequest(method, endpoint string, params url.Values, tags []string, header http.Header, basicAuth bool, response interface{}) error {
	logger := log.NewLogEntry()

	startTS := time.Now()
	var body io.Reader

	tags = append(tags, "provider:amazonCognito")
	switch method {
	case "POST":
		body = bytes.NewBufferString(params.Encode())
	case "GET":
		// error checking skipped because we are just parsing in
		// order to make a copy of an existing URL
		u, _ := url.Parse(endpoint)
		u.RawQuery = params.Encode()
		endpoint = u.String()
	default:
		// ¯\_(ツ)_/¯
		return ErrBadRequest
	}

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return err
	}
	if header != nil {
		req.Header = header
	}

	if basicAuth {
		req.SetBasicAuth(p.ClientID, p.ClientSecret)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.StatsdClient.Incr("provider.request", tags, 1.0)
	resp, err := httpClient.Do(req)
	if err != nil {
		tags = append(tags, "error:http_client_error")
		p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
		return err
	}
	tags = append(tags, fmt.Sprintf("status_code:%d", resp.StatusCode))
	p.StatsdClient.Timing("provider.latency", time.Now().Sub(startTS), tags, 1.0)
	p.StatsdClient.Incr("provider.response", tags, 1.0)

	var respBody []byte
	respBody, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		tags = append(tags, "error:invalid_body")
		p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
		return err
	}
	if resp.StatusCode != http.StatusOK {
		p.StatsdClient.Incr("provider.error", tags, 1.0)
		logger.WithHTTPStatus(resp.StatusCode).WithEndpoint(stripToken(endpoint)).WithResponseBody(
			respBody).Info()
		switch resp.StatusCode {
		case 400:
			var response struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			e := json.Unmarshal(respBody, &response)
			if e == nil && response.ErrorDescription == "Token expired or revoked" {
				p.StatsdClient.Incr("provider.token_revoked", tags, 1.0)
				return ErrTokenRevoked
			}
			return ErrBadRequest
		case 429:
			return ErrRateLimitExceeded
		default:
			return ErrServiceUnavailable
		}
	}

	if response != nil {
		err := json.Unmarshal(respBody, &response)
		if err != nil {
			p.StatsdClient.Incr("provider.internal_error", tags, 1.0)
			return err
		}
	}

	return nil
}

func (p *AmazonCognitoProvider) cbBackoff(duration time.Duration, reset time.Time) {
	logger := log.NewLogEntry()

	p.StatsdClient.Timing("provider.backoff", duration, nil, 1.0)
	logger.WithBackoffDuration(duration).WithBackoffReset(reset).Info(
		"circuit breaker backoff set")
}

func (p *AmazonCognitoProvider) cbStateChange(from, to circuit.State) {
	logger := log.NewLogEntry()

	p.StatsdClient.Incr("provider.circuit_change", []string{fmt.Sprintf("from_state:%s", from), fmt.Sprintf("to_state:%s", to)}, 1.0)
	logger.WithCircuitChangeFrom(from).WithCircuitChangeTo(to).Info("circuit breaker trigger")
}

// Redeem fulfills the Provider interface.
// The authenticator uses this method to redeem the code provided to /callback after the user logs into their AmazonCognito account.
// The code is redeemed for an access token and refresh token
// 1. POSTs the code and grant_type to https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html
// 2. If the request fails, the authenticator will return a 500 and display an error page (see oauth_proxy.go#OAuthCallback)
// 3. If the request succeeds, the data from AmazonCognito contains:
//     - the access token which we use to get data from AmazonCognito
//     - the refresh token which we can use to get a new access_token
//     - the expiration time of the access token
//     - a Base64 encoded id token which contains the user's email
//       address and whether or not that email address is verified
func (p *AmazonCognitoProvider) Redeem(redirectURL, code string) (*sessions.SessionState, error) {
	logger := log.NewLogEntry()

	if code == "" {
		return nil, ErrBadRequest
	}
	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	params.Add("scope", p.Scope)

	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}

	err := p.amazonCognitoRequest("POST", p.RedeemURL.String(), params, []string{"action:redeem"}, nil, true, &response)
	if err != nil {
		return nil, err
	}

	logger.Info(fmt.Sprintf("response %#v", response))

	email, err := p.verifyEmailWithAccessToken(response.AccessToken)
	if err != nil {
		return nil, err
	}

	return &sessions.SessionState{
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,

		RefreshDeadline:  sessions.ExtendDeadline(time.Duration(response.ExpiresIn) * time.Second),
		LifetimeDeadline: sessions.ExtendDeadline(p.SessionLifetimeTTL),
		Email:            email,
	}, nil
}

// verifyEmailWithAccessToken takes in an access token and
// checks if it is verified with AmazonCognito. Conditionally returns
// an empty string, or if validated the email address in question.
func (p *AmazonCognitoProvider) verifyEmailWithAccessToken(accessToken string) (string, error) {
	if accessToken == "" {
		return "", ErrBadRequest
	}

	userinfo, err := p.GetUserProfile(accessToken)
	if err != nil {
		return "", err
	}

	if userinfo.EmailAddress == "" {
		return "", errors.New("missing email")
	}

	return userinfo.EmailAddress, nil
}

// ValidateGroupMembership takes in an email, a list of allowed groups an access token
// TODO
// - compares allowed groups to users' groups.
// Conditionally returns an empty (nil) slice or a slice of the matching groups.
func (p *AmazonCognitoProvider) ValidateGroupMembership(email string, allowedGroups []string, accessToken string) ([]string, error) {
	return allowedGroups, nil
}

// GetUserProfile takes in an access token and sends a request to the /userinfo endpoint.
// Conditionally returns nil response or a struct of specified claims.
func (p *AmazonCognitoProvider) GetUserProfile(AccessToken string) (*GetUserProfileResponse, error) {
	response := &GetUserProfileResponse{}

	if AccessToken == "" {
		return nil, ErrBadRequest
	}

	bearer := fmt.Sprintf("Bearer %s", AccessToken)
	header := http.Header{}
	header.Set("Authorization", bearer)

	err := p.amazonCognitoRequest("GET", p.ProfileURL.String(), nil, []string{"action:userinfo"}, header, false, response)
	if err != nil {
		return nil, err
	}

	return response, nil
}

// RefreshSessionIfNeeded takes in a SessionState and
// returns false if the session is not refreshed and true if it is.
func (p *AmazonCognitoProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || !s.RefreshPeriodExpired() || s.RefreshToken == "" {
		return false, nil
	}

	newToken, duration, err := p.RefreshAccessToken(s.RefreshToken)
	if err != nil {
		return false, err
	}
	logger := log.NewLogEntry()

	s.AccessToken = newToken

	s.RefreshDeadline = time.Now().Add(duration).Truncate(time.Second)
	logger.WithUser(s.Email).WithRefreshDeadline(s.RefreshDeadline).Info("refreshed access token")

	return true, nil
}

// RefreshAccessToken takes in a refresh token and returns the new access token along with an expiration date.
func (p *AmazonCognitoProvider) RefreshAccessToken(refreshToken string) (token string, expires time.Duration, err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")

	var response struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}

	err = p.amazonCognitoRequest("POST", p.RedeemURL.String(), params, []string{"action:refresh"}, nil, true, &response)
	if err != nil {
		return "", 0, err
	}

	return response.AccessToken, time.Duration(response.ExpiresIn) * time.Second, nil
}

// Revoke revokes the refresh token from a given session state.
// For the Amazon Cognito provider this triggers a global sign out
// Revoking the refresh token implicitly revokes the access token, forcing re-authentication.
func (p *AmazonCognitoProvider) Revoke(s *sessions.SessionState) error {
	// TODO: There is no revoke endpoint
	// Global Sign Out?
	return nil
}
