package rbac

import "webtyp.com/orm"

// subjectGrants is the roles+permissions resolved for one (projectID,
// subjectID) pair. rbac never persists a "user" row — a subject is just an
// id that may or may not have UserRole assignments. No assignment means
// empty Roles/Permissions, never an error: "Empty or unknown subject IDs
// are denied" (see README), not "not found".
type subjectGrants struct {
	SubjectID   string
	Roles       []Role
	Permissions []Permission
}

func resolveSubjectGrants(db *orm.DB, projectID, subjectID string) (*subjectGrants, error) {
	g := &subjectGrants{SubjectID: subjectID, Roles: []Role{}, Permissions: []Permission{}}

	qbUserRoles := db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.UserId).Eq(subjectID)
	userRoles, err := ReadAllUserRole(qbUserRoles)
	if err != nil {
		return nil, err
	}
	if len(userRoles) == 0 {
		return g, nil
	}

	var roleIDs []any
	for _, ur := range userRoles {
		roleIDs = append(roleIDs, ur.RoleId)
	}

	qbRoles := db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).In(roleIDs)
	roles, err := ReadAllRole(qbRoles)
	if err != nil {
		return nil, err
	}
	g.Roles = make([]Role, len(roles))
	for i, r := range roles {
		g.Roles[i] = *r
	}

	qbRolePerms := db.Query(&RolePermission{}).Where(RolePermission_.ProjectId).Eq(projectID).Where(RolePermission_.RoleId).In(roleIDs)
	rolePerms, err := ReadAllRolePermission(qbRolePerms)
	if err != nil {
		return nil, err
	}

	var permIDs []any
	for _, rp := range rolePerms {
		permIDs = append(permIDs, rp.PermissionId)
	}
	if len(permIDs) == 0 {
		return g, nil
	}

	qbPerms := db.Query(&Permission{}).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).In(permIDs)
	perms, err := ReadAllPermission(qbPerms)
	if err != nil {
		return nil, err
	}

	// Deduplicate permissions using slice lookup (no map)
	var uniquePerms []Permission
	for _, p := range perms {
		exists := false
		for _, up := range uniquePerms {
			if up.Id == p.Id {
				exists = true
				break
			}
		}
		if !exists {
			uniquePerms = append(uniquePerms, *p)
		}
	}
	g.Permissions = uniquePerms
	return g, nil
}
