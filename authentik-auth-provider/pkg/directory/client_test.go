package directory

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/obot-platform/enterprise-providers/authcommon"
)

const (
	childID  = "11111111-1111-1111-1111-111111111111"
	parentID = "22222222-2222-2222-2222-222222222222"
	otherID  = "33333333-3333-3333-3333-333333333333"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer directory-secret" {
			t.Errorf("missing directory API token")
		}
		handler(w, r)
	}))
	t.Cleanup(srv.Close)
	client, err := New(srv.URL, "directory-secret", srv.Client().Transport)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

func TestGroupPages(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if r.URL.Path != "/api/v3/core/groups/" || q.Get("page_size") != "50" || q.Get("search") != "Engineering & Ops" || q.Get("ordering") != "name,pk" || q.Get("include_users") != "false" {
			t.Errorf("unexpected group request: %s", r.URL)
		}
		switch q.Get("page") {
		case "1":
			writeJSON(w, map[string]any{
				"pagination": map[string]int{"current": 1, "next": 2},
				"results":    []Group{{ID: childID, Name: "Engineering"}},
			})
		case "2":
			writeJSON(w, map[string]any{
				"pagination": map[string]int{"current": 2, "next": 0},
				"results":    []Group{{ID: parentID, Name: "Ops"}},
			})
		default:
			t.Errorf("unexpected page")
		}
	})
	first, err := client.GroupPage(t.Context(), authcommon.PageRequest{
		NameFilter: "Engineering & Ops",
		Limit:      50,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.NextCursor != "2" || len(first.Items) != 1 || first.Items[0].ID != "authentik/"+childID {
		t.Fatalf("unexpected first page: %+v", first)
	}
	second, err := client.GroupPage(t.Context(), authcommon.PageRequest{
		NameFilter: "Engineering & Ops",
		Limit:      50,
		Cursor:     first.NextCursor,
	})
	if err != nil || second.NextCursor != "" || len(second.Items) != 1 {
		t.Fatalf("unexpected second page: %+v, %v", second, err)
	}
	for _, cursor := range []string{"https://evil.example/", "-1", "0", "1000001"} {
		if _, err := client.GroupPage(t.Context(), authcommon.PageRequest{Limit: 50, Cursor: cursor}); !errors.Is(err, authcommon.ErrInvalidCursor) {
			t.Fatalf("cursor %q accepted: %v", cursor, err)
		}
	}
}

func TestGroupsByIDs(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v3/core/groups/"+childID+"/" {
			writeJSON(w, Group{ID: childID, Name: "Renamed group"})
			return
		}
		http.NotFound(w, r)
	})
	groups, err := client.GroupsByIDs(t.Context(), []string{childID, otherID})
	if err != nil || len(groups) != 1 || groups[0].Name != "Renamed group" {
		t.Fatalf("unexpected resolved groups: %+v, %v", groups, err)
	}
	if _, err := client.GroupsByIDs(t.Context(), []string{"../../users"}); err == nil {
		t.Fatal("unsafe ID accepted")
	}
}

func TestResolveUser(t *testing.T) {
	tests := []struct {
		name    string
		user    User
		count   int
		wantErr bool
	}{
		{
			name: "active exact user",
			user: User{
				ID:       42,
				Username: "alice",
				Email:    "alice@example.com",
				Active:   true,
			},
			count: 1,
		},
		{
			name: "inactive user",
			user: User{
				ID:       42,
				Username: "alice",
				Email:    "alice@example.com",
			},
			count:   1,
			wantErr: true,
		},
		{
			name: "wrong username",
			user: User{
				ID:       42,
				Username: "bob",
				Email:    "alice@example.com",
				Active:   true,
			},
			count:   1,
			wantErr: true,
		},
		{
			name: "wrong email",
			user: User{
				ID:       42,
				Username: "alice",
				Email:    "bob@example.com",
				Active:   true,
			},
			count:   1,
			wantErr: true,
		},
		{
			name: "ambiguous result",
			user: User{
				ID:       42,
				Username: "alice",
				Email:    "alice@example.com",
				Active:   true,
			},
			count:   2,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/v3/core/users/" || r.URL.Query().Get("username") != "alice" {
					t.Errorf("unexpected lookup request: %s", r.URL)
				}
				writeJSON(w, map[string]any{
					"pagination": map[string]int{"count": tt.count},
					"results": []User{
						tt.user,
					},
				})
			})
			user, err := client.ResolveUser(t.Context(), "alice", "ALICE@example.com")
			if tt.wantErr {
				if !errors.Is(err, ErrUserUnavailable) {
					t.Fatalf("wanted unavailable user error, got %v", err)
				}
			} else if err != nil || user.ID != 42 {
				t.Fatalf("unexpected user: %+v, %v", user, err)
			}
		})
	}
}

func TestUserGroupsIncludeAncestors(t *testing.T) {
	var lookups atomic.Int32
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/core/users/42/":
			writeJSON(w, User{ID: 42, Active: true, Groups: []string{childID, parentID}})
		case "/api/v3/core/groups/" + childID + "/":
			lookups.Add(1)
			writeJSON(w, Group{ID: childID, Name: "Child", Parent: parentID})
		case "/api/v3/core/groups/" + parentID + "/":
			lookups.Add(1)
			// Include a cycle to verify termination and duplicate suppression.
			writeJSON(w, Group{ID: parentID, Name: "Parent", Parents: []string{childID, otherID}})
		case "/api/v3/core/groups/" + otherID + "/":
			lookups.Add(1)
			writeJSON(w, Group{ID: otherID, Name: "Ancestor"})
		default:
			t.Errorf("unexpected request: %s", r.URL)
		}
	})
	groups, err := client.UserGroups(t.Context(), "42")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(groups.IDs(), []string{"authentik/" + childID, "authentik/" + parentID, "authentik/" + otherID}) || lookups.Load() != 3 {
		t.Fatalf("unexpected memberships: %+v, lookups=%d", groups, lookups.Load())
	}
}

func TestUserGroupsFailClosed(t *testing.T) {
	client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v3/core/users/42/":
			writeJSON(w, User{ID: 42, Active: true, Groups: []string{childID, parentID}})
		case "/api/v3/core/users/43/":
			writeJSON(w, User{
				ID:     43,
				Active: false,
			})
		case "/api/v3/core/groups/" + childID + "/":
			writeJSON(w, Group{ID: childID, Name: "Child"})
		case "/api/v3/core/groups/" + parentID + "/":
			http.Error(w, "directory-secret must not leak", http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	})
	if groups, err := client.UserGroups(t.Context(), "42"); err == nil || len(groups) != 0 || strings.Contains(err.Error(), "directory-secret") {
		t.Fatalf("partial memberships or credentials exposed: %+v, %v", groups, err)
	}
	for _, id := range []string{"43", "44"} {
		if _, err := client.UserGroups(t.Context(), id); !errors.Is(err, ErrUserUnavailable) {
			t.Fatalf("missing/inactive user accepted: %v", err)
		}
	}
	for _, id := range []string{"sub-hash", "../groups", "-1", "042"} {
		if _, err := client.UserGroups(t.Context(), id); err == nil {
			t.Fatalf("invalid ID %q accepted", id)
		}
	}
}

func TestTransportAndPaginationErrors(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "redirect",
			status: http.StatusFound,
		},
		{
			name:   "malformed JSON",
			status: http.StatusOK,
			body:   "invalid",
		},
		{
			name:   "repeating page",
			status: http.StatusOK,
			body:   `{"pagination":{"current":1,"next":1},"results":[]}`,
		},
		{
			name:   "URL cursor",
			status: http.StatusOK,
			body:   `{"pagination":{"current":1,"next":"https://evil.example/"},"results":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", "https://evil.example/")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			})
			if _, err := client.GroupPage(t.Context(), authcommon.PageRequest{Limit: 50}); err == nil {
				t.Fatal("expected upstream error")
			}
		})
	}
	if _, err := New("http://auth.example.com", "token", nil); err == nil {
		t.Fatal("HTTP API base URL accepted")
	}
	if _, err := New("https://auth.example.com", "", nil); err == nil {
		t.Fatal("missing API token accepted")
	}
	client := testClient(t, func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, User{}) })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := client.UserGroups(ctx, "42"); err == nil {
		t.Fatal("canceled context ignored")
	}
}
