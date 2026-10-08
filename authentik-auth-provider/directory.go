package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/directory"
)

func registerDirectoryRoutes(mux *http.ServeMux, client *directory.Client) {
	if client == nil {
		for _, path := range []string{"/obot-list-auth-groups", "/obot-get-auth-groups", "/obot-list-user-auth-groups"} {
			mux.HandleFunc(path, http.NotFound)
		}
		return
	}
	mux.HandleFunc("/obot-list-auth-groups", authcommon.ListGroupsHandler("authentik", client.GroupPage))
	mux.HandleFunc("/obot-get-auth-groups", authcommon.GetGroupsHandler("authentik", client.GroupsByIDs))
	mux.HandleFunc("/obot-list-user-auth-groups", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 128))
		if err != nil {
			http.Error(w, "invalid user ID", http.StatusBadRequest)
			return
		}
		id := strings.TrimSpace(string(body))
		if id == "" {
			http.Error(w, "user ID is required", http.StatusBadRequest)
			return
		}
		groups, err := client.UserGroups(r.Context(), id)
		if err != nil {
			if errors.Is(err, directory.ErrUserUnavailable) {
				http.Error(w, "Authentik account is unavailable", http.StatusForbidden)
				return
			}
			http.Error(w, "failed to fetch Authentik memberships", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groups)
	})
}
