package rbac

import (
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
)

func (m *Service) CreateRole(projectID, id string, code model.RoleCode, name, description string) error {
	r := &Role{
		ProjectId:   projectID,
		Id:          id,
		Code:        string(code),
		Name:        name,
		Description: description,
	}
	err := m.db.Create(r)
	if err != nil && isUniqueViolation(err) {
		qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
		existingR, readErr := ReadOneRole(qb, &Role{})
		if readErr != nil {
			return readErr
		}
		existingR.Code = string(code)
		existingR.Name = name
		existingR.Description = description
		return m.db.Update(existingR, orm.Eq(Role_.ProjectId, existingR.ProjectId), orm.Eq(Role_.Id, existingR.Id))
	}
	return err
}

func (m *Service) GetRole(projectID, id string) (*Role, error) {
	qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
	return ReadOneRole(qb, &Role{})
}

func (m *Service) DeleteRole(projectID, id string) error {
	qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
	roles, err := ReadAllRole(qb)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return nil // Or ErrNotFound
	}
	r := roles[0]

	// Delete from link tables first to simulate cascade, since tinywasm/orm doesn't cascade automatically like PRAGMA foreign_keys = ON does unless DB level handles it
	urQb := m.db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.RoleId).Eq(id)
	urs, _ := ReadAllUserRole(urQb)
	for _, ur := range urs {
		m.db.Delete(ur, orm.Eq(UserRole_.ProjectId, ur.ProjectId), orm.Eq(UserRole_.UserId, ur.UserId), orm.Eq(UserRole_.RoleId, ur.RoleId))
	}

	rpQb := m.db.Query(&RolePermission{}).Where(RolePermission_.ProjectId).Eq(projectID).Where(RolePermission_.RoleId).Eq(id)
	rps, _ := ReadAllRolePermission(rpQb)
	for _, rp := range rps {
		m.db.Delete(rp, orm.Eq(RolePermission_.ProjectId, rp.ProjectId), orm.Eq(RolePermission_.RoleId, rp.RoleId), orm.Eq(RolePermission_.PermissionId, rp.PermissionId))
	}

	err = m.db.Delete(r, orm.Eq(Role_.ProjectId, r.ProjectId), orm.Eq(Role_.Id, r.Id))
	if err == nil {
		m.ucache.InvalidateByRole(id)
	}
	return err
}

func (m *Service) CreatePermission(projectID, id, name string, resource model.Resource, action model.Action) error {
	p := &Permission{
		ProjectId: projectID,
		Id:        id,
		Name:      name,
		Resource:  string(resource),
		Action:    action.String(),
	}
	err := m.db.Create(p)
	if err != nil && isUniqueViolation(err) {
		qb := m.db.Query(&Permission{}).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
		existingP, readErr := ReadOnePermission(qb, &Permission{})
		if readErr != nil {
			return readErr
		}
		existingP.Name = name
		existingP.Resource = string(resource)
		existingP.Action = action.String()
		return m.db.Update(existingP, orm.Eq(Permission_.ProjectId, existingP.ProjectId), orm.Eq(Permission_.Id, existingP.Id))
	}
	return err
}

func (m *Service) GetPermission(projectID, id string) (*Permission, error) {
	qb := m.db.Query(&Permission{}).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
	return ReadOnePermission(qb, &Permission{})
}

func (m *Service) DeletePermission(projectID, id string) error {
	qb := m.db.Query(&Permission{}).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
	p, err := ReadOnePermission(qb, &Permission{})
	if err != nil {
		return err
	}

	err = m.db.Delete(p, orm.Eq(Permission_.ProjectId, p.ProjectId), orm.Eq(Permission_.Id, p.Id))
	if err == nil {
		m.ucache.InvalidateByPermission(id)
	}
	return err
}

func (m *Service) AssignRole(projectID, userID, roleID string) error {
	ur := &UserRole{
		ProjectId: projectID,
		UserId:    userID,
		RoleId:    roleID,
	}
	err := m.db.Create(ur)
	if err != nil && isUniqueViolation(err) {
		return nil // Ignore duplicates
	}
	if err == nil {
		m.ucache.Delete(projectID, userID) // Invalidate user to reload roles
	}
	return err
}

func (m *Service) RevokeRole(projectID, userID, roleID string) error {
	qb := m.db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.UserId).Eq(userID).Where(UserRole_.RoleId).Eq(roleID)
	ur, err := ReadOneUserRole(qb, &UserRole{})
	if err != nil {
		return err
	}
	err = m.db.Delete(ur, orm.Eq(UserRole_.ProjectId, ur.ProjectId), orm.Eq(UserRole_.UserId, ur.UserId), orm.Eq(UserRole_.RoleId, ur.RoleId))
	if err == nil {
		m.ucache.Delete(projectID, userID)
	}
	return err
}

func (m *Service) GetUserRoles(projectID, userID string) ([]Role, error) {
	qbUserRoles := m.db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.UserId).Eq(userID)
	userRoles, err := ReadAllUserRole(qbUserRoles)
	if err != nil {
		return nil, err
	}

	var roleIDs []any
	for _, ur := range userRoles {
		roleIDs = append(roleIDs, ur.RoleId)
	}

	if len(roleIDs) == 0 {
		return []Role{}, nil
	}

	qbRoles := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).In(roleIDs)
	rolesPtrs, err := ReadAllRole(qbRoles)
	if err != nil {
		return nil, err
	}

	roles := make([]Role, len(rolesPtrs))
	for i, r := range rolesPtrs {
		roles[i] = *r
	}
	return roles, nil
}

func (m *Service) AssignPermission(projectID, roleID, permissionID string) error {
	rp := &RolePermission{
		ProjectId:    projectID,
		RoleId:       roleID,
		PermissionId: permissionID,
	}
	err := m.db.Create(rp)
	if err != nil && isUniqueViolation(err) {
		return nil // Ignore duplicates
	}
	if err == nil {
		m.ucache.InvalidateByRole(roleID) // Invalidate users with this role
	}
	return err
}

type RBACObject interface {
	HandlerName() string
	AllowedRoles(action model.Action) []model.RoleCode
}

func (m *Service) GetRoleByCode(projectID string, code model.RoleCode) (*Role, error) {
	qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Code).Eq(string(code))
	roles, err := ReadAllRole(qb)
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, orm.ErrNotFound
	}
	return roles[0], nil
}

// Register builds permissions from handlers' declared resource/action
// grants and assigns them to the roles those handlers name — policy stays
// with the caller (see README: "Policy belongs to the consumer"); rbac
// only persists what Register is told.
func (m *Service) Register(projectID string, handlers ...RBACObject) error {
	return registerRBAC(m, projectID, handlers...)
}

func registerRBAC(m *Service, projectID string, handlers ...RBACObject) error {
	actions := []model.Action{model.Create, model.Read, model.Update, model.Delete}
	for _, h := range handlers {
		resource := h.HandlerName()
		for _, action := range actions {
			roles := h.AllowedRoles(action)
			if len(roles) == 0 {
				continue
			}

			permID := resource + ":" + action.String()
			if err := m.CreatePermission(projectID, permID, permID, model.Resource(resource), action); err != nil {
				return err
			}

			for _, code := range roles {
				r, err := m.GetRoleByCode(projectID, code)
				if err != nil {
					continue // Role not found, skip assignment
				}
				if err := m.AssignPermission(projectID, r.Id, permID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (m *Service) HasPermission(projectID, subjectID string, resource model.Resource, action model.Action) (bool, error) {
	if subjectID == "" {
		return false, nil
	}
	g, err := m.subjectGrants(projectID, subjectID)
	if err != nil {
		return false, err
	}

	for _, p := range g.Permissions {
		// Una acción ilegible NO se salta: saltarla borra el permiso real en silencio y deja
		// la fila corrupta invisible para siempre. Denegar sí; callar no.
		pAction, err := model.ParseAction(p.Action)
		if err != nil {
			return false, err
		}
		grant := model.Grant{
			Resource: model.Resource(p.Resource),
			Actions:  pAction,
		}
		if grant.Matches(resource, action) {
			return true, nil
		}
	}
	return false, nil
}

func (m *Service) subjectGrants(projectID, subjectID string) (*subjectGrants, error) {
	if cached, ok := m.ucache.Get(projectID, subjectID); ok {
		return cached, nil
	}
	g, err := resolveSubjectGrants(m.db, projectID, subjectID)
	if err != nil {
		return nil, err
	}
	m.ucache.Set(projectID, subjectID, g)
	return g, nil
}
