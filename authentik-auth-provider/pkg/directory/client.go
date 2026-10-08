package directory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obot-platform/enterprise-providers/authcommon"
	"github.com/obot-platform/providers/auth-providers-common/pkg/state"
)

const maxMembershipGroups = 10000

var groupIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

var ErrUserUnavailable = errors.New("Authentik user is missing or inactive")

type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// New accepts the Authentik instance URL, not the application's OIDC issuer URL.
func New(baseURL, token string, transport http.RoundTripper) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("Authentik API base URL must be HTTPS without credentials, query, or fragment")
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("Authentik API token is required")
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/") + "/api/v3",
		token:   token,
		http: &http.Client{
			Transport: transport,
			Timeout:   15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

type Group struct {
	ID      string   `json:"pk"`
	Name    string   `json:"name"`
	Parents []string `json:"parents"`
	// Authentik versions before multi-parent groups use a single parent field.
	Parent string `json:"parent"`
}

func (g Group) info() state.GroupInfo {
	return state.GroupInfo{ID: "authentik/" + g.ID, Name: g.Name}
}

type User struct {
	ID       int      `json:"pk"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Active   bool     `json:"is_active"`
	Groups   []string `json:"groups"`
}

type page[T any] struct {
	Pagination struct {
		Next    int `json:"next"`
		Current int `json:"current"`
		Count   int `json:"count"`
	} `json:"pagination"`
	Results []T `json:"results"`
}

func (c *Client) get(ctx context.Context, path string, query url.Values, result any) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path+"?"+query.Encode(), nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("Authentik directory request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		// Never include the upstream response body or the API token in errors.
		return false, fmt.Errorf("Authentik directory returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil {
		return false, err
	}
	if len(body) > 4*1024*1024 {
		return false, errors.New("Authentik directory response exceeds size limit")
	}
	if err := json.Unmarshal(body, result); err != nil {
		return false, fmt.Errorf("invalid Authentik directory response: %w", err)
	}
	return true, nil
}

func groupQuery() url.Values {
	return url.Values{"include_users": {"false"}, "include_inherited_roles": {"false"}}
}

func (c *Client) GroupPage(ctx context.Context, req authcommon.PageRequest) (authcommon.PageResult, error) {
	number := 1
	if req.Cursor != "" {
		var err error
		number, err = strconv.Atoi(req.Cursor)
		if err != nil || number < 1 || number > 1000000 {
			return authcommon.PageResult{}, authcommon.ErrInvalidCursor
		}
	}
	query := groupQuery()
	query.Set("page", strconv.Itoa(number))
	query.Set("page_size", strconv.Itoa(req.Limit))
	query.Set("ordering", "name,pk")
	if req.NameFilter != "" {
		query.Set("search", req.NameFilter)
	}
	var response page[Group]
	found, err := c.get(ctx, "/core/groups/", query, &response)
	if err != nil {
		return authcommon.PageResult{}, err
	}
	if !found {
		return authcommon.PageResult{}, errors.New("Authentik groups endpoint not found")
	}
	if response.Pagination.Current != number || (response.Pagination.Next != 0 && response.Pagination.Next != number+1) {
		return authcommon.PageResult{}, errors.New("invalid Authentik pagination")
	}
	result := authcommon.PageResult{Items: state.GroupInfoList{}}
	for _, group := range response.Results {
		if !groupIDPattern.MatchString(group.ID) {
			return authcommon.PageResult{}, errors.New("invalid Authentik group ID")
		}
		result.Items = append(result.Items, group.info())
	}
	if response.Pagination.Next != 0 {
		result.NextCursor = strconv.Itoa(response.Pagination.Next)
	}
	return result, nil
}

func (c *Client) group(ctx context.Context, id string) (*Group, error) {
	if !groupIDPattern.MatchString(id) {
		return nil, errors.New("invalid Authentik group ID")
	}
	var group Group
	found, err := c.get(ctx, "/core/groups/"+id+"/", groupQuery(), &group)
	if err != nil || !found {
		return nil, err
	}
	if group.ID != id {
		return nil, errors.New("Authentik returned a different group ID")
	}
	return &group, nil
}

func (c *Client) GroupsByIDs(ctx context.Context, ids []string) (state.GroupInfoList, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return authcommon.ResolveGroupsByLookup(ctx, ids, func(ctx context.Context, id string) (*state.GroupInfo, error) {
		group, err := c.group(ctx, id)
		if err != nil || group == nil {
			return nil, err
		}
		info := group.info()
		return &info, nil
	})
}

// ResolveUser maps the authenticated preferred_username to the directory's numeric ID.
// Authentik's OIDC sub can be a hash, UUID, or username, so it is not a directory ID.
func (c *Client) ResolveUser(ctx context.Context, username, email string) (*User, error) {
	if username == "" || email == "" {
		return nil, errors.New("directory lookup requires preferred_username and email claims")
	}
	var response page[User]
	found, err := c.get(ctx, "/core/users/", url.Values{
		"username":       {username},
		"page_size":      {"2"},
		"include_groups": {"false"},
		"include_roles":  {"false"},
	}, &response)
	if err != nil {
		return nil, err
	}
	if !found || len(response.Results) != 1 || response.Pagination.Next != 0 || response.Pagination.Count != 1 {
		return nil, ErrUserUnavailable
	}
	user := response.Results[0]
	if user.ID <= 0 || user.Username != username || !strings.EqualFold(user.Email, email) || !user.Active {
		return nil, ErrUserUnavailable
	}
	return &user, nil
}

func (c *Client) UserGroups(ctx context.Context, id string) (state.GroupInfoList, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	number, err := strconv.Atoi(id)
	if err != nil || number <= 0 || strconv.Itoa(number) != id {
		return nil, errors.New("directory user ID must be a positive integer")
	}
	var user User
	found, err := c.get(ctx, "/core/users/"+id+"/", url.Values{"include_groups": {"false"}, "include_roles": {"false"}}, &user)
	if err != nil {
		return nil, err
	}
	if !found || !user.Active || user.ID != number {
		return nil, ErrUserUnavailable
	}
	// Follow parent IDs as well as direct memberships. Use UUIDs, never names,
	// and deduplicate to handle overlapping ancestors and malformed cycles.
	queue := append([]string(nil), user.Groups...)
	seen := map[string]bool{}
	result := state.GroupInfoList{}
	for len(queue) > 0 {
		id, rest := queue[0], queue[1:]
		queue = rest
		if seen[id] {
			continue
		}
		if len(seen) >= maxMembershipGroups {
			return nil, errors.New("Authentik membership graph exceeds group limit")
		}
		seen[id] = true
		group, err := c.group(ctx, id)
		if err != nil {
			return nil, err // Never return a successful, partial membership list.
		}
		if group == nil {
			continue // A group deleted during the read grants no permissions.
		}
		result = append(result, group.info())
		queue = append(queue, group.Parents...)
		if group.Parent != "" {
			queue = append(queue, group.Parent)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}
