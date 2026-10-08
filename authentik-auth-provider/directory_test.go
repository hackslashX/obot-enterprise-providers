package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/enterprise-providers/authentik-auth-provider/pkg/directory"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

func TestDirectoryRoutes(t *testing.T) {
	const groupID = "11111111-1111-1111-1111-111111111111"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v3/core/groups/":
			_, _ = w.Write([]byte(`{"pagination":{"current":1,"next":0},"results":[{"pk":"` + groupID + `","name":"Engineering"}]}`))
		case "/api/v3/core/users/42/":
			_ = json.NewEncoder(w).Encode(directory.User{ID: 42, Active: true, Groups: []string{groupID}})
		case "/api/v3/core/groups/" + groupID + "/":
			_ = json.NewEncoder(w).Encode(directory.Group{ID: groupID, Name: "Engineering"})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	client, err := directory.New(srv.URL, "token", srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerDirectoryRoutes(mux, client)

	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups?limit=50", nil))
	var page authcommon.GroupPage
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &page) != nil || len(page.Items) != 1 || page.Items[0].ID != "authentik/"+groupID {
		t.Fatalf("unexpected listing: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/obot-get-auth-groups?ids=authentik/"+groupID, nil))
	var list authcommon.GroupList
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list.Items) != 1 {
		t.Fatalf("unexpected resolution: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader("42")))
	var groups state.GroupInfoList
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &groups) != nil || len(groups) != 1 || groups[0].ID != "authentik/"+groupID {
		t.Fatalf("unexpected memberships: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader("99")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing directory user must be forbidden: %d", w.Code)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/obot-list-user-auth-groups", strings.NewReader(strings.Repeat("x", 200))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized request accepted: %d", w.Code)
	}
	cursor, err := authcommon.EncodeCursor("okta", "", 50, "2")
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/obot-list-auth-groups?cursor="+cursor, nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("foreign cursor accepted: %d", w.Code)
	}
}
