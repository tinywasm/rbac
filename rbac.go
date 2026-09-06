package rbac

import (
	"webtyp.com/fmt"
	"webtyp.com/model"
	"webtyp.com/orm"
)

func (m *Service) CreateRole(projectID, id string, code model.RoleCode, name, description string) error {
	// Check if role already exists by (projectID, id) -> upsert path
	existingByID, err := m.GetRole(projectID, id)
	if err == nil {
		// Existing role by ID found. Verify code is not taken by another role ID.
		existingByCode, codeErr := m.GetRoleByCode(projectID, code)
		if codeErr == nil && existingByCode.Id != id {
			return ErrDuplicateRoleCode
		}
		if codeErr != nil && codeErr != ErrRoleNotFound && codeErr != orm.ErrNotFound {
			return codeErr
		}
		existingByID.Code = string(code)
		existingByID.Name = name
		existingByID.Description = description
		return m.db.Update(existingByID, orm.Eq(Role_.ProjectId, existingByID.ProjectId), orm.Eq(Role_.Id, existingByID.Id))
	}
	if err != ErrRoleNotFound && err != orm.ErrNotFound {
		return err
	}

	// New role by ID. Check if code is already used by another role.
	existingByCode, codeErr := m.GetRoleByCode(projectID, code)
	if codeErr == nil && existingByCode.Id != id {
		return ErrDuplicateRoleCode
	}
	if codeErr != nil && codeErr != ErrRoleNotFound && codeErr != orm.ErrNotFound {
		return codeErr
	}

	r := &Role{
		ProjectId:   projectID,
		Id:          id,
		Code:        string(code),
		Name:        name,
		Description: description,
	}
	return m.db.Create(r)
}

// SetRoleSessionTTL sets the role's SessionTtl (seconds; 0 reverts to "use
// the caller's default"). See RoleModel's session_ttl comment for the
// most-restrictive-wins policy a caller applies across a user's roles.
func (m *Service) SetRoleSessionTTL(projectID, id string, ttl int64) error {
	r := &Role{}
	qb := m.db.Query(r).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
	r, err := ReadOneRole(qb, r)
	if err != nil {
		return err
	}
	r.SessionTtl = ttl
	return m.db.Update(r, orm.Eq(Role_.ProjectId, r.ProjectId), orm.Eq(Role_.Id, r.Id))
}

func (m *Service) GetRole(projectID, id string) (*Role, error) {
	r := &Role{}
	qb := m.db.Query(r).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
	return ReadOneRole(qb, r)
}

func (m *Service) DeleteRole(projectID, id string) error {
	qb := m.db.Query(&Role{}).Where(Role_.ProjectId).Eq(projectID).Where(Role_.Id).Eq(id)
	roles, err := ReadAllRole(qb)
	if err != nil {
		return err
	}
	if len(roles) == 0 {
		return ErrRoleNotFound
	}
	r := roles[0]

	// Delete from link tables first to simulate cascade, since webtyp/orm doesn't cascade automatically like PRAGMA foreign_keys = ON does unless DB level handles it
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

// DeleteRoleByCode borra el rol y todas sus asignaciones. ErrRoleNotFound si
// el code no existe en el proyecto.
func (m *Service) DeleteRoleByCode(projectID string, code model.RoleCode) error {
	role, err := m.GetRoleByCode(projectID, code)
	if err != nil {
		return err
	}
	return m.DeleteRole(projectID, role.Id)
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
		existingP := &Permission{}
		qb := m.db.Query(existingP).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
		existingP, readErr := ReadOnePermission(qb, existingP)
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
	p := &Permission{}
	qb := m.db.Query(p).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
	return ReadOnePermission(qb, p)
}

func (m *Service) DeletePermission(projectID, id string) error {
	p := &Permission{}
	qb := m.db.Query(p).Where(Permission_.ProjectId).Eq(projectID).Where(Permission_.Id).Eq(id)
	p, err := ReadOnePermission(qb, p)
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
	ur := &UserRole{}
	qb := m.db.Query(ur).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.UserId).Eq(userID).Where(UserRole_.RoleId).Eq(roleID)
	ur, err := ReadOneUserRole(qb, ur)
	if err != nil {
		if err == orm.ErrNotFound || fmt.Contains(err.Error(), "no rows") {
			return nil
		}
		return err
	}
	err = m.db.Delete(ur, orm.Eq(UserRole_.ProjectId, ur.ProjectId), orm.Eq(UserRole_.UserId, ur.UserId), orm.Eq(UserRole_.RoleId, ur.RoleId))
	if err == nil {
		m.ucache.Delete(projectID, userID)
	}
	return err
}

// RevokeRoleByCode quita el rol identificado por su code al usuario dentro
// del proyecto. Es el par de AssignRoleByCode y el camino que debe usar un
// consumidor que habla en codes — nunca borrar la fila UserRole a mano: el
// borrado directo NO invalida el caché de permisos y deja concediendo
// accesos ya revocados.
//
// Idempotente: revocar un rol que el usuario no tiene no es un error.
// ErrRoleNotFound si el code no existe en el proyecto.
func (m *Service) RevokeRoleByCode(projectID, userID string, code model.RoleCode) error {
	role, err := m.GetRoleByCode(projectID, code)
	if err != nil {
		return err
	}
	return m.RevokeRole(projectID, userID, role.Id)
}

// AssignRoleByCode concede el rol identificado por su code. Idempotente.
// ErrRoleNotFound si el code no existe en el proyecto — a diferencia de
// CreateRole, NO lo crea: conceder un rol y definirlo son decisiones
// distintas y mezclarlas hace que un typo en el code cree un rol vacío.
func (m *Service) AssignRoleByCode(projectID, userID string, code model.RoleCode) error {
	role, err := m.GetRoleByCode(projectID, code)
	if err != nil {
		return err
	}
	return m.AssignRole(projectID, userID, role.Id)
}

// UsersInRole devuelve los ids de usuario que tienen el rol. Sólo ids: este
// paquete no conoce la tabla de usuarios (ver ARCHITECTURE.md), así que
// resolver perfiles es del consumidor.
func (m *Service) UsersInRole(projectID string, code model.RoleCode) ([]string, error) {
	role, err := m.GetRoleByCode(projectID, code)
	if err != nil {
		return nil, err
	}

	qb := m.db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.RoleId).Eq(role.Id)
	urs, err := ReadAllUserRole(qb)
	if err != nil {
		return nil, err
	}

	userIDs := make([]string, 0, len(urs))
	for _, ur := range urs {
		userIDs = append(userIDs, ur.UserId)
	}
	return userIDs, nil
}

// RoleUserCount devuelve cuántos usuarios tienen el rol, sin traerlos.
func (m *Service) RoleUserCount(projectID string, code model.RoleCode) (int64, error) {
	role, err := m.GetRoleByCode(projectID, code)
	if err != nil {
		return 0, err
	}

	qb := m.db.Query(&UserRole{}).Where(UserRole_.ProjectId).Eq(projectID).Where(UserRole_.RoleId).Eq(role.Id)
	urs, err := ReadAllUserRole(qb)
	if err != nil {
		return 0, err
	}
	return int64(len(urs)), nil
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
		return nil, ErrRoleNotFound
	}
	if len(roles) > 1 {
		return nil, ErrDuplicateRoleCode
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
