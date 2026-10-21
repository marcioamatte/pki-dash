package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"github.com/marcioamatte/pki-dash/internal/store"
)

// RoleMap turns the groups an identity provider reports into one role. The
// highest role any group grants wins. A person with none of the listed groups
// gets Default, and if that is empty they get no access at all, so adding
// someone to the provider never grants access to this application by itself.
type RoleMap struct {
	Admin, Operator, Viewer []string
	Default                 string // "", viewer or operator; never admin
}

// Enabled reports whether external sign-in can grant anything.
func (m RoleMap) Enabled() bool {
	return len(m.Admin)+len(m.Operator)+len(m.Viewer) > 0 || m.Default != ""
}

// Validate rejects a default that would hand out too much.
func (m RoleMap) Validate() error {
	switch m.Default {
	case "", store.RoleViewer, store.RoleOperator:
	default:
		return errors.New("the default role must be empty, viewer or operator")
	}
	return nil
}

func normGroup(g string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(g), "/"))
}

func inGroups(have map[string]bool, want []string) bool {
	for _, g := range want {
		if have[normGroup(g)] {
			return true
		}
	}
	return false
}

// Resolve returns the role for a set of groups, or false for no access.
// A leading "/" (Keycloak's full group path) and letter case are ignored.
func (m RoleMap) Resolve(groups []string) (string, bool) {
	have := make(map[string]bool, len(groups))
	for _, g := range groups {
		have[normGroup(g)] = true
	}
	switch {
	case inGroups(have, m.Admin):
		return store.RoleAdmin, true
	case inGroups(have, m.Operator):
		return store.RoleOperator, true
	case inGroups(have, m.Viewer):
		return store.RoleViewer, true
	}
	if m.Default != "" {
		return m.Default, true
	}
	return "", false
}

// ExternalIdentity is a person an identity provider has authenticated.
type ExternalIdentity struct {
	Issuer, Subject, Username string
	Groups                    []string
}

var badNameChars = regexp.MustCompile(`[^A-Za-z0-9._@-]+`)

// accountName makes a valid username out of what the provider suggested.
func accountName(suggested, subject string) string {
	n := strings.Trim(badNameChars.ReplaceAllString(suggested, "_"), "_")
	if len(n) > 59 {
		n = n[:59]
	}
	if len(n) < 3 {
		n = "sso-" + shortHash(subject)
	}
	return n
}

func shortHash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:6]
}

// LoginExternal opens a session for a person the identity provider has
// authenticated. The provider is the source of truth for the role: it is
// recomputed at every sign-in, so removing someone from a group takes effect
// at their next login (and the role change ends their other sessions).
//
// The account is keyed on issuer and subject, never on the name or e-mail, so
// nobody can take over an existing account (local or not) by choosing a name.
func (a *Auth) LoginExternal(ctx context.Context, id ExternalIdentity) (*Session, error) {
	if id.Issuer == "" || id.Subject == "" {
		return nil, ErrNoAccess
	}
	ext := id.Issuer + "#" + id.Subject
	name := accountName(id.Username, ext)
	deny := func(reason string, err error) (*Session, error) {
		_ = a.st.AuditEvent(ctx, name, "user.login_failed", "", "oidc: "+reason)
		return nil, err
	}

	role, ok := a.opts.ExternalRoles.Resolve(id.Groups)
	if !ok {
		return deny("no group grants access", ErrNoAccess)
	}

	u, err := a.st.GetUserByExternal(ctx, store.SourceOIDC, ext)
	if errors.Is(err, store.ErrNotFound) {
		u, err = a.provision(ctx, name, ext, role)
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return deny("account disabled", ErrNoAccess)
	}
	if u.Role != role {
		if err := a.st.SetRole(ctx, "oidc", u.ID, role); err != nil {
			if errors.Is(err, store.ErrLastAdmin) {
				return deny("would remove the last admin", ErrNoAccess)
			}
			return nil, err
		}
		u.Role = role
	}
	return a.openSession(ctx, u, role, "oidc")
}

// provision creates the account on first sign-in. If the suggested name is
// taken by someone else, a short suffix derived from the subject is added.
func (a *Auth) provision(ctx context.Context, name, ext, role string) (store.User, error) {
	for _, candidate := range []string{name, name + "-" + shortHash(ext)} {
		if len(candidate) > 64 {
			candidate = candidate[:64]
		}
		_, err := a.st.CreateUser(ctx, "oidc", store.User{Username: candidate, Role: role, AuthSource: store.SourceOIDC, ExternalID: ext}, false)
		switch {
		case err == nil:
			return a.st.GetUserByExternal(ctx, store.SourceOIDC, ext)
		case errors.Is(err, store.ErrExists):
			// Either the name is taken, or two first logins of the same person
			// raced and the other won: look before trying another name.
			if u, gerr := a.st.GetUserByExternal(ctx, store.SourceOIDC, ext); gerr == nil {
				return u, nil
			}
		default:
			return store.User{}, err
		}
	}
	return store.User{}, store.ErrExists
}
