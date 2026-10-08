package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oauth2proxy "github.com/oauth2-proxy/oauth2-proxy/v7"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/validation"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func TestProviderRoutes(t *testing.T) {
	o, err := testOptions().proxyOptions()
	if err != nil {
		t.Fatal(err)
	}
	// No network calls are needed to exercise proxy routing and cookie storage.
	skip := true
	o.Providers[0].OIDCConfig.SkipDiscovery = &skip
	o.Providers[0].OIDCConfig.JwksURL = "https://auth.example.com/jwks"
	o.Providers[0].LoginURL = "https://auth.example.com/authorize"
	o.Providers[0].RedeemURL = "https://auth.example.com/token"
	if err := validation.Validate(o); err != nil {
		t.Fatal(err)
	}
	proxy, err := oauth2proxy.NewOAuthProxy(o, oauth2proxy.NewValidator(o.EmailDomains, o.AuthenticatedEmailsFile))
	if err != nil {
		t.Fatal(err)
	}
	mux := newMux(proxy, nil, nil, nil, "127.0.0.1:9999")
	for _, path := range []string{"/obot-list-auth-groups", "/obot-get-auth-groups", "/obot-list-user-auth-groups"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusNotFound {
			t.Errorf("%s: expected 404, got %d", path, w.Code)
		}
	}

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://obot.example.com/oauth2/start", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("OAuth start returned %d: %s", w.Code, w.Body.String())
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	query := location.Query()
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" || query.Get("nonce") == "" || query.Get("state") == "" || query.Get("response_type") != "code" {
		t.Fatalf("missing OAuth protections: %v", query)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://obot.example.com/oauth2/callback?code=bad", nil))
	if w.Code < 400 {
		t.Fatalf("callback without state/CSRF cookie accepted: %d", w.Code)
	}

	store, err := sessions.NewSessionStore(&o.Session, &o.Cookie)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now()
	expires := created.Add(time.Hour)
	cookieWriter := httptest.NewRecorder()
	sessionReq := httptest.NewRequest(http.MethodGet, "https://obot.example.com/", nil)
	if err := store.Save(cookieWriter, sessionReq, &sessionsapi.SessionState{
		User:        "stable-subject",
		Email:       "user@example.com",
		AccessToken: "access-token",
		CreatedAt:   &created,
		ExpiresOn:   &expires,
		Groups:      []string{"admins"},
	}); err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	for _, cookie := range cookieWriter.Result().Cookies() {
		header.Add("Cookie", cookie.Name+"="+cookie.Value)
	}
	body, err := json.Marshal(state.SerializableRequest{
		Method: http.MethodGet,
		URL:    "https://obot.example.com/",
		Header: header,
	})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/obot-get-state", strings.NewReader(string(body))))
	if w.Code != http.StatusOK {
		t.Fatalf("get state returned %d: %s", w.Code, w.Body.String())
	}
	var ss state.SerializableState
	if err := json.Unmarshal(w.Body.Bytes(), &ss); err != nil {
		t.Fatal(err)
	}
	if ss.User != "stable-subject" || ss.Email != "user@example.com" || len(ss.Groups) != 0 || len(ss.GroupInfos) != 0 {
		t.Fatalf("unexpected session state: %#v", ss)
	}
}
