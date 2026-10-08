package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/directory"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/profile"
	"github.com/obot-platform/providers/auth-providers-common/pkg/env"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: authentik-auth-provider: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var opts Options
	if err := env.LoadEnvForStruct(&opts); err != nil {
		return fmt.Errorf("load options: %w", err)
	}
	proxyOpts, err := opts.proxyOptions()
	if err != nil {
		return err
	}
	if err := validation.Validate(proxyOpts); err != nil {
		return fmt.Errorf("validate options: %w", err)
	}
	proxy, err := oauth2proxy.NewOAuthProxy(proxyOpts, oauth2proxy.NewValidator(proxyOpts.EmailDomains, proxyOpts.AuthenticatedEmailsFile))
	if err != nil {
		return fmt.Errorf("create oauth2 proxy: %w", err)
	}

	// Discovery supplies the userinfo endpoint; do not guess it from the application slug.
	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, client), proxyOpts.Providers[0].OIDCConfig.IssuerURL)
	if err != nil {
		return fmt.Errorf("discover Authentik provider: %w", err)
	}
	var discovery struct {
		UserInfoURL string `json:"userinfo_endpoint"`
	}
	if err := provider.Claims(&discovery); err != nil {
		return fmt.Errorf("read discovery: %w", err)
	}
	if err := validateHTTPSURL(discovery.UserInfoURL); err != nil {
		return fmt.Errorf("invalid userinfo endpoint: %w", err)
	}

	var directoryClient *directory.Client
	if opts.APIToken != "" {
		baseURL := opts.APIBaseURL
		if baseURL == "" {
			issuer, _ := url.Parse(proxyOpts.Providers[0].OIDCConfig.IssuerURL)
			baseURL = issuer.Scheme + "://" + issuer.Host
		}
		directoryClient, err = directory.New(baseURL, opts.APIToken, nil)
		if err != nil {
			return err
		}
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}
	host := os.Getenv("OBOT_PROVIDER_LISTEN_HOST")
	if host == "" {
		host = "127.0.0.1"
	}
	addr := net.JoinHostPort(host, port)
	mux := newMux(proxy, provider, client, directoryClient, addr)
	fmt.Printf("listening on %s\n", addr)
	if err := http.ListenAndServe(addr, mux); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func newMux(proxy *oauth2proxy.OAuthProxy, provider *oidc.Provider, client *http.Client, directoryClient *directory.Client, addr string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/{$}", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, "http://%s", addr)
	})
	mux.HandleFunc("/obot-get-state", func(w http.ResponseWriter, r *http.Request) {
		var sr state.SerializableRequest
		if err := json.NewDecoder(r.Body).Decode(&sr); err != nil {
			http.Error(w, "invalid state request", http.StatusBadRequest)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), sr.Method, sr.URL, nil)
		if err != nil {
			http.Error(w, "invalid state request", http.StatusBadRequest)
			return
		}
		req.Header = sr.Header
		ss, err := state.GetSerializableState(proxy, req)
		if err != nil {
			http.Error(w, "failed to load session", http.StatusUnauthorized)
			return
		}
		// Authentik's profile scope includes group names, not stable directory IDs.
		// Obot synchronizes memberships through the separate directory endpoints.
		ss.Groups = []string{}
		ss.GroupInfos = state.GroupInfoList{}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ss)
	})
	mux.Handle("/obot-get-user-info", profile.HandlerWithDirectory(provider, client, directoryClient))
	registerDirectoryRoutes(mux, directoryClient)
	mux.HandleFunc("/", proxy.ServeHTTP)
	return mux
}
