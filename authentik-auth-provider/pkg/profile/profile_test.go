package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/directory"
)

func testProvider(t *testing.T, userinfo http.HandlerFunc) (*oidc.Provider, *http.Client) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"userinfo_endpoint":%q}`, srv.URL, srv.URL+"/authorize", srv.URL+"/token", srv.URL+"/jwks", srv.URL+"/userinfo")
	})
	mux.HandleFunc("/userinfo", userinfo)
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), client), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return p, client
}

func TestHandler(t *testing.T) {
	p, client := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer access-token" {
			t.Errorf("unexpected authorization header")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"untrusted-directory-id","sub":"stable-subject","email":"user@example.com","email_verified":true,"name":"Example User","picture":"https://example.com/avatar.png"}`))
	})
	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	req.Header.Set("Authorization", "Bearer access-token")
	w := httptest.NewRecorder()
	Handler(p, client).ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got Profile
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != "" || got.Subject != "stable-subject" || got.Name != "Example User" || got.Picture != "https://example.com/avatar.png" || !got.EmailVerified {
		t.Fatalf("unexpected profile: %#v", got)
	}
}

func TestInvalidProfiles(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "unverified email",
			status: http.StatusOK,
			body:   `{"sub":"user","email":"user@example.com","email_verified":false}`,
		},
		{
			name:   "missing verification",
			status: http.StatusOK,
			body:   `{"sub":"user","email":"user@example.com"}`,
		},
		{
			name:   "missing subject",
			status: http.StatusOK,
			body:   `{"email":"user@example.com","email_verified":true}`,
		},
		{
			name:   "missing email",
			status: http.StatusOK,
			body:   `{"sub":"user","email_verified":true}`,
		},
		{
			name:   "invalid JSON",
			status: http.StatusOK,
			body:   `not JSON`,
		},
		{
			name:   "upstream error",
			status: http.StatusUnauthorized,
			body:   `sensitive upstream error`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, client := testProvider(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
			req.Header.Set("Authorization", "Bearer access-token")
			w := httptest.NewRecorder()
			Handler(p, client).ServeHTTP(w, req)
			if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), tt.body) {
				t.Fatalf("unexpected response %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestMissingBearerToken(t *testing.T) {
	for _, header := range []string{"", "Bearer", "Basic secret", "Bearer token extra"} {
		t.Run(header, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
			req.Header.Set("Authorization", header)
			w := httptest.NewRecorder()
			Handler(nil, nil).ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", w.Code)
			}
		})
	}
}

func TestUserinfoRedirectRejected(t *testing.T) {
	p, client := testProvider(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/other", http.StatusFound)
	})
	if _, err := Fetch(context.Background(), p, client, "access-token"); err == nil {
		t.Fatal("expected redirect to be rejected")
	}
}

func TestDirectoryProfileLookupID(t *testing.T) {
	p, client := testProvider(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"sub":"opaque-hashed-subject","preferred_username":"alice","email":"alice@example.com","email_verified":true,"name":"Alice"}`))
	})
	api := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer service-token" || r.URL.Path != "/api/v3/core/users/" || r.URL.Query().Get("username") != "alice" {
			t.Errorf("unexpected directory lookup: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pagination":{"count":1,"next":0},"results":[{"pk":42,"username":"alice","email":"alice@example.com","is_active":true}]}`))
	}))
	t.Cleanup(api.Close)
	directoryClient, err := directory.New(api.URL, "service-token", api.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/obot-get-user-info", nil)
	req.Header.Set("Authorization", "Bearer login-token")
	w := httptest.NewRecorder()
	HandlerWithDirectory(p, client, directoryClient).ServeHTTP(w, req)
	var got Profile
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &got) != nil || got.ID != "42" || got.Subject != "opaque-hashed-subject" {
		t.Fatalf("directory ID must differ from OIDC subject: %d %s", w.Code, w.Body.String())
	}
}
