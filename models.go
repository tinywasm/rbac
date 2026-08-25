package rbac

import "github.com/tinywasm/model"

// Every table carries project_id as part of its primary key: two projects
// (misitio, mjosefa-cms, ...) can each define a role with the same natural
// id ("role_admin") without colliding, and every query is scoped by it.
// References between these four tables are soft (plain string columns,
// no DB-managed FK) — rbac never imports a project's own domain types, and
// a composite FK across (project_id, id) is not worth the complexity here.

var RoleModel = model.Definition{
	Name: "role",
	Fields: model.Fields{
		{Name: "project_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "code", Type: model.Text()},
		{Name: "name", Type: model.Text()},
		{Name: "description", Type: model.Text()},
		// session_ttl: seconds. 0 (default) means "use the caller's default TTL" —
		// a role without it declared never extends another, more sensitive role's
		// session (see veltylabs/iam's use of the MOST restrictive SessionTTL
		// among a user's roles when issuing an authorization token).
		{Name: "session_ttl", Type: model.Int()},
	},
}

var PermissionModel = model.Definition{
	Name: "permission",
	Fields: model.Fields{
		{Name: "project_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "name", Type: model.Text()},
		{Name: "resource", Type: model.Text()},
		{Name: "action", Type: model.Text()}, // stores CRUD letters ("crud", "r", "ru", ...)
	},
}

var UserRoleModel = model.Definition{
	Name: "user_role",
	Fields: model.Fields{
		{Name: "project_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "role_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
	},
}

var RolePermissionModel = model.Definition{
	Name: "role_permission",
	Fields: model.Fields{
		{Name: "project_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "role_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
		{Name: "permission_id", Type: model.Text(), DB: &model.FieldDB{PK: true}, NotNull: true},
	},
}
