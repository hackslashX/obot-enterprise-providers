package main

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

type Options struct {
	ClientID                          string `env:"OBOT_AUTHENTIK_AUTH_PROVIDER_CLIENT_ID"`
	ClientSecret                      string `env:"OBOT_AUTHENTIK_AUTH_PROVIDER_CLIENT_SECRET"`
	IssuerURL                         string `env:"OBOT_AUTHENTIK_AUTH_PROVIDER_ISSUER_URL"`
	APIToken                          string `env:"OBOT_AUTHENTIK_AUTH_PROVIDER_API_TOKEN" optional:"true"`
	APIBaseURL                        string `env:"OBOT_AUTHENTIK_AUTH_PROVIDER_API_BASE_URL" optional:"true"`
	ObotServerURL                     string `env:"OBOT_SERVER_PUBLIC_URL,OBOT_SERVER_URL"`
	PostgresConnectionDSN             string `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_DSN" optional:"true"`
	PostgresMaxConnections            int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_CONNECTIONS" optional:"true"`
	PostgresMaxIdleConnections        int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_MAX_IDLE_CONNECTIONS" optional:"true"`
	PostgresConnectionLifetimeSeconds int    `env:"OBOT_AUTH_PROVIDER_POSTGRES_CONNECTION_LIFETIME_SECONDS" optional:"true"`
	AuthCookieSecret                  string `env:"OBOT_AUTH_PROVIDER_COOKIE_SECRET"`
	AuthEmailDomains                  string `default:"*" env:"OBOT_AUTH_PROVIDER_EMAIL_DOMAINS"`
	AuthTokenRefreshDuration          string `optional:"true" default:"1h" env:"OBOT_AUTH_PROVIDER_TOKEN_REFRESH_DURATION"`
	LoggingEnabled                    string `optional:"true" env:"OBOT_AUTH_PROVIDER_ENABLE_LOGGING"`
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("expected an HTTPS URL without credentials, query, or fragment")
	}
	return nil
}

func (o Options) proxyOptions() (*options.Options, error) {
	issuer := strings.TrimSpace(o.IssuerURL)
	if err := validateHTTPSURL(issuer); err != nil {
		return nil, fmt.Errorf("invalid issuer URL: %w", err)
	}
	if o.APIBaseURL != "" {
		if err := validateHTTPSURL(o.APIBaseURL); err != nil {
			return nil, fmt.Errorf("invalid API base URL: %w", err)
		}
		if o.APIToken == "" {
			return nil, fmt.Errorf("API base URL requires an API token")
		}
	}
	serverURL, err := url.Parse(o.ObotServerURL)
	if err != nil || (serverURL.Scheme != "http" && serverURL.Scheme != "https") || serverURL.Hostname() == "" || serverURL.User != nil || serverURL.RawQuery != "" || serverURL.Fragment != "" {
		return nil, fmt.Errorf("invalid Obot server URL")
	}
	if o.ClientID == "" || o.ClientSecret == "" {
		return nil, fmt.Errorf("client ID and client secret are required")
	}
	refresh, err := time.ParseDuration(o.AuthTokenRefreshDuration)
	if err != nil || refresh < 0 {
		return nil, fmt.Errorf("token refresh duration must be a nonnegative duration")
	}
	secret, err := base64.StdEncoding.DecodeString(o.AuthCookieSecret)
	if err != nil || (len(secret) != 16 && len(secret) != 24 && len(secret) != 32) {
		return nil, fmt.Errorf("cookie secret must be base64 encoding of 16, 24, or 32 bytes")
	}

	legacy := options.NewLegacyOptions()
	legacy.LegacyProvider.ProviderType = "oidc"
	legacy.LegacyProvider.ProviderName = "Authentik"
	legacy.LegacyProvider.ClientID = o.ClientID
	legacy.LegacyProvider.ClientSecret = o.ClientSecret
	legacy.LegacyProvider.OIDCIssuerURL = issuer
	legacy.LegacyProvider.Scope = "openid email profile offline_access"
	legacy.LegacyProvider.CodeChallengeMethod = "S256"
	// Keep issuer, signature, nonce and verified-email checks enabled.
	legacy.LegacyProvider.InsecureOIDCSkipNonce = false
	legacy.LegacyProvider.OIDCGroupsClaim = "obot_unsupported_groups"
	legacy.LegacyProvider.UserIDClaim = "sub"
	result, err := legacy.ToOptions()
	if err != nil {
		return nil, fmt.Errorf("convert proxy options: %w", err)
	}
	result.Server.BindAddress = ""
	result.MetricsServer.BindAddress = ""
	if o.PostgresConnectionDSN != "" {
		result.Session.Type = options.PostgresSessionStoreType
		result.Session.Postgres.ConnectionDSN = o.PostgresConnectionDSN
		result.Session.Postgres.MaxOpenConns = o.PostgresMaxConnections
		result.Session.Postgres.MaxIdleConns = o.PostgresMaxIdleConnections
		result.Session.Postgres.ConnMaxLifetime = o.PostgresConnectionLifetimeSeconds
		result.Session.Postgres.TableNamePrefix = "authentik_"
	}
	result.Cookie.Refresh = refresh
	result.Cookie.Name = "obot_access_token"
	result.Cookie.Secret = string(secret)
	result.Cookie.Secure = serverURL.Scheme == "https"
	result.Cookie.CSRFExpire = 30 * time.Minute
	result.RawRedirectURL = strings.TrimRight(o.ObotServerURL, "/") + "/"
	for _, domain := range strings.Split(o.AuthEmailDomains, ",") {
		if domain = strings.TrimSpace(domain); domain != "" {
			result.EmailDomains = append(result.EmailDomains, domain)
		}
	}
	if len(result.EmailDomains) == 0 {
		return nil, fmt.Errorf("at least one allowed email domain is required")
	}
	logging := strings.EqualFold(o.LoggingEnabled, "true")
	result.Logging.RequestEnabled = logging
	result.Logging.AuthEnabled = logging
	result.Logging.StandardEnabled = logging
	return result, nil
}
