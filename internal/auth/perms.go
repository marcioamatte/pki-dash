package auth

import "github.com/marcioamatte/pki-dash/internal/store"

// Permission is something a role may do.
type Permission string

const (
	PermViewCAs            Permission = "ca.view"
	PermViewCerts          Permission = "cert.view"
	PermIssueCert          Permission = "cert.issue"
	PermCreateIntermediate Permission = "ca.create_intermediate"
	PermCreateRoot         Permission = "ca.create_root"
	PermExportCAKey        Permission = "ca.export_key"
	PermRemoveRootKey      Permission = "ca.remove_root_key"
	PermManageVault        Permission = "vault.manage"
	PermManageUsers        Permission = "user.manage"
	PermViewAudit          Permission = "audit.view"
)

var viewer = []Permission{PermViewCAs, PermViewCerts}

// rolePerms is deliberately a closed list: a role gets nothing it is not
// named for, and an unknown role gets nothing at all.
var rolePerms = map[string][]Permission{
	store.RoleViewer:   viewer,
	store.RoleOperator: append(append([]Permission{}, viewer...), PermIssueCert),
	store.RoleAdmin: {
		PermViewCAs, PermViewCerts, PermIssueCert, PermCreateIntermediate, PermCreateRoot,
		PermExportCAKey, PermRemoveRootKey, PermManageVault, PermManageUsers, PermViewAudit,
	},
}

// Can reports whether role holds perm.
func Can(role string, perm Permission) bool {
	for _, p := range rolePerms[role] {
		if p == perm {
			return true
		}
	}
	return false
}

func validRole(role string) bool { _, ok := rolePerms[role]; return ok }
