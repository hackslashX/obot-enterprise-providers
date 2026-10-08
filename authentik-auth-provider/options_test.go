package main

import (
	"encoding/base64"
	"reflect"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func testOptions() Options {
	return Options{
		ClientID:                 "client",
		ClientSecret:             "secret",
		IssuerURL:                "https://auth.example.com/application/o/obot/",
		ObotServerURL:            "https://obot.example.com",
		AuthCookieSecret:         base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901")),
		AuthEmailDomains:         "example.com, example.org",
		AuthTokenRefreshDuration: "1h",
	}
}

func TestProxyOptions(t *testing.T) {
	opts := testOptions()
	opts.PostgresConnectionDSN = "postgres://localhost/obot"
	opts.PostgresMaxConnections = 10
	opts.PostgresMaxIdleConnections = 3
	opts.PostgresConnectionLifetimeSeconds = 60
	got, err := opts.proxyOptions()
	if err != nil {
		t.Fatal(err)
	}
	p := got.Providers[0]
	if p.Type != options.OIDCProvider || p.OIDCConfig.IssuerURL != opts.IssuerURL || p.ClientID != opts.ClientID || p.ClientSecret != opts.ClientSecret {
		t.Fatalf("unexpected provider options: %#v", p)
	}
	if p.CodeChallengeMethod != "S256" || p.Scope != "openid email profile offline_access" {
		t.Fatalf("unexpected authorization settings: %#v", p)
	}
	if p.OIDCConfig.InsecureSkipIssuerVerification == nil || *p.OIDCConfig.InsecureSkipIssuerVerification || p.OIDCConfig.InsecureAllowUnverifiedEmail == nil || *p.OIDCConfig.InsecureAllowUnverifiedEmail || p.OIDCConfig.InsecureSkipNonce == nil || *p.OIDCConfig.InsecureSkipNonce {
		t.Fatalf("OIDC security checks disabled: %#v", p.OIDCConfig)
	}
	if p.OIDCConfig.GroupsClaim != "obot_unsupported_groups" || p.OIDCConfig.UserIDClaim != "sub" {
		t.Fatal("must not import raw Authentik group names")
	}
	if !got.Cookie.Secure || got.Cookie.Name != "obot_access_token" || got.Cookie.Refresh != time.Hour || got.Cookie.CSRFExpire != 30*time.Minute {
		t.Fatalf("unexpected cookie options: %#v", got.Cookie)
	}
	if !reflect.DeepEqual(got.EmailDomains, []string{"example.com", "example.org"}) || got.RawRedirectURL != "https://obot.example.com/" {
		t.Fatal("incorrect email domains or redirect URL")
	}
	pg := got.Session.Postgres
	if got.Session.Type != options.PostgresSessionStoreType || pg.TableNamePrefix != "authentik_" || pg.ConnectionDSN != opts.PostgresConnectionDSN || pg.MaxOpenConns != 10 || pg.MaxIdleConns != 3 || pg.ConnMaxLifetime != 60 {
		t.Fatalf("unexpected postgres options: %#v", pg)
	}
}

func TestInvalidOptions(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Options)
	}{
		{
			name:   "HTTP directory API",
			change: func(o *Options) { o.APIBaseURL = "http://auth.example.com"; o.APIToken = "token" },
		},
		{
			name:   "directory API URL without token",
			change: func(o *Options) { o.APIBaseURL = "https://auth.example.com" },
		},
		{
			name:   "HTTP issuer",
			change: func(o *Options) { o.IssuerURL = "http://auth.example.com/" },
		},
		{
			name:   "issuer credentials",
			change: func(o *Options) { o.IssuerURL = "https://user:pass@auth.example.com/" },
		},
		{
			name:   "issuer query",
			change: func(o *Options) { o.IssuerURL += "?foo=bar" },
		},
		{
			name:   "issuer fragment",
			change: func(o *Options) { o.IssuerURL += "#foo" },
		},
		{
			name:   "invalid server URL",
			change: func(o *Options) { o.ObotServerURL = "javascript:alert(1)" },
		},
		{
			name:   "missing client secret",
			change: func(o *Options) { o.ClientSecret = "" },
		},
		{
			name:   "invalid refresh",
			change: func(o *Options) { o.AuthTokenRefreshDuration = "tomorrow" },
		},
		{
			name:   "negative refresh",
			change: func(o *Options) { o.AuthTokenRefreshDuration = "-1h" },
		},
		{
			name:   "invalid base64 secret",
			change: func(o *Options) { o.AuthCookieSecret = "!!!" },
		},
		{
			name:   "short cookie secret",
			change: func(o *Options) { o.AuthCookieSecret = base64.StdEncoding.EncodeToString([]byte("short")) },
		},
		{
			name:   "empty domain list",
			change: func(o *Options) { o.AuthEmailDomains = " , " },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := testOptions()
			tt.change(&o)
			if _, err := o.proxyOptions(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestLocalObotAndZeroRefresh(t *testing.T) {
	o := testOptions()
	o.ObotServerURL = "http://localhost:8080/"
	o.AuthTokenRefreshDuration = "0s"
	o.AuthEmailDomains = "*"
	got, err := o.proxyOptions()
	if err != nil {
		t.Fatal(err)
	}
	if got.Cookie.Secure || got.Cookie.Refresh != 0 || got.RawRedirectURL != "http://localhost:8080/" {
		t.Fatal("unexpected development options")
	}
}
