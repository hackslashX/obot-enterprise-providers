package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/directory"
	"golang.org/x/oauth2"
)

type Profile struct {
	ID                string `json:"id,omitempty"`
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	Picture           string `json:"picture,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
}

func Fetch(ctx context.Context, provider *oidc.Provider, client *http.Client, token string) (*Profile, error) {
	info, err := provider.UserInfo(oidc.ClientContext(ctx, client), oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token, TokenType: "Bearer"}))
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	var result Profile
	if err := info.Claims(&result); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}
	if result.Subject == "" || result.Email == "" || !result.EmailVerified {
		return nil, fmt.Errorf("userinfo must include a subject and a verified email")
	}
	// Only directory resolution may supply the API lookup ID. A custom scope
	// mapping's id claim must not become an arbitrary directory lookup.
	result.ID = ""
	return &result, nil
}

func Handler(provider *oidc.Provider, client *http.Client) http.Handler {
	return HandlerWithDirectory(provider, client, nil)
}

func HandlerWithDirectory(provider *oidc.Provider, client *http.Client, directoryClient *directory.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fields := strings.Fields(r.Header.Get("Authorization"))
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
			http.Error(w, "a bearer token is required", http.StatusUnauthorized)
			return
		}
		result, err := Fetch(r.Context(), provider, client, fields[1])
		if err != nil {
			// Do not expose upstream responses, which can contain credentials or user data.
			http.Error(w, "failed to fetch verified user profile", http.StatusBadGateway)
			return
		}
		if directoryClient != nil {
			user, err := directoryClient.ResolveUser(r.Context(), result.PreferredUsername, result.Email)
			if err != nil {
				if errors.Is(err, directory.ErrUserUnavailable) {
					http.Error(w, "Authentik account is unavailable", http.StatusForbidden)
					return
				}
				http.Error(w, "failed to resolve Authentik directory user", http.StatusBadGateway)
				return
			}
			// Session identity remains the OIDC subject. Obot's separate group lookup
			// ID must be the API's numeric primary key, not a guessed subject format.
			result.ID = strconv.Itoa(user.ID)
		}
		// Without directory access, leave the profile ID unset so Obot can resolve
		// it when an administrator later enables directory synchronization.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}
