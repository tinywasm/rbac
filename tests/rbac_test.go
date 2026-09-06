package tests

import (
	"testing"

	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/rbac"
	"webtyp.com/storage/mem"
)

func newTestService(t *testing.T) *rbac.Service {
	t.Helper()
	_, svc := newTestServiceWithDB(t)
	return svc
}

// newTestServiceWithDB also returns the raw *orm.DB, for tests that need
// to write a row rbac's own typed API cannot produce (e.g. a corrupt
// stored action, simulating a row from an old library version).
func newTestServiceWithDB(t *testing.T) (*orm.DB, *rbac.Service) {
	t.Helper()
	db := orm.New(mem.New())
	if ddlCompiler, ok := db.RawConn().(ddl.Compiler); ok {
		if err := rbac.Migrate(db.RawConn(), ddlCompiler); err != nil {
			t.Fatalf("rbac.Migrate: %v", err)
		}
	}
	svc, err := rbac.New(db)
	if err != nil {
		t.Fatalf("rbac.New: %v", err)
	}
	return db, svc
}

const testProject = "proj-1"

type mockExecer struct {
	executed []string
}

func (m *mockExecer) Exec(query string, args ...any) error {
	m.executed = append(m.executed, query)
	return nil
}

type mockCompiler struct{}

func (m *mockCompiler) CompileDDL(s ddl.Stmt, mModel model.Model) (string, []any, error) {
	var name string
	if mModel != nil {
		name = mModel.ModelName()
	}
	return "CREATE TABLE mock (" + name + ");", nil, nil
}

func TestMigrateAcceptsExecer(t *testing.T) {
	execer := &mockExecer{}
	compiler := &mockCompiler{}

	if err := rbac.Migrate(execer, compiler); err != nil {
		t.Fatalf("Migrate failed with mockExecer: %v", err)
	}

	if len(execer.executed) == 0 {
		t.Fatalf("expected DDL statements executed, got 0")
	}
}

func TestClosedByDefault(t *testing.T) {
	svc := newTestService(t)

	t.Run("anonymous subject has no permissions", func(t *testing.T) {
		if svc.Can(testProject, "", "docs", model.Read) {
			t.Error("empty subject should have no permissions")
		}
	})

	t.Run("subject with no assignments has no permissions", func(t *testing.T) {
		if svc.Can(testProject, "subject-with-nothing", "docs", model.Read) {
			t.Error("subject without roles should have no permissions")
		}
	})
}

// TestFullFlow proves the whole assignment path end to end, and that
// deleting a role revokes what it granted.
func TestFullFlow(t *testing.T) {
	svc := newTestService(t)

	if err := svc.CreateRole(testProject, "r_editor", "editor", "Editor", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.CreatePermission(testProject, "p_read_invoice", "Read invoice", "invoice", model.Read); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if err := svc.AssignPermission(testProject, "r_editor", "p_read_invoice"); err != nil {
		t.Fatalf("AssignPermission: %v", err)
	}
	if err := svc.AssignRole(testProject, "user-1", "r_editor"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	if !svc.Can(testProject, "user-1", "invoice", model.Read) {
		t.Error("expected editor to read invoice")
	}
	if svc.Can(testProject, "user-1", "invoice", model.Update) {
		t.Error("expected editor NOT to update invoice (unassigned action)")
	}

	if err := svc.DeleteRole(testProject, "r_editor"); err != nil {
		t.Fatalf("DeleteRole: %v", err)
	}
	if svc.Can(testProject, "user-1", "invoice", model.Read) {
		t.Error("expected permission revoked after role deletion")
	}
}

// TestGetRole is the consumer-shaped test ReadOneRole's calling convention
// needed: passing db.Query(...) and ReadOneRole(qb, ...) two SEPARATE
// &Role{} literals scans into the one baked into qb and returns the other,
// still zero-valued, with err == nil — a silent "found nothing" that looks
// like success. The fix is reusing the same *Role in both calls.
func TestGetRole(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_1", "editor", "Editor", "can edit"); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	r, err := svc.GetRole(testProject, "r_1")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if r.Id != "r_1" || r.ProjectId != testProject || r.Name != "Editor" {
		t.Fatalf("GetRole returned a zero-valued role: %+v", r)
	}
}

// TestSetRoleSessionTTL proves the field a caller needs to pick "the most
// restrictive TTL among a user's roles" (see veltylabs/iam's IssueAuthToken)
// actually round-trips through the role a subject is assigned.
func TestSetRoleSessionTTL(t *testing.T) {
	svc := newTestService(t)

	if err := svc.CreateRole(testProject, "r_short", "short", "Short-lived", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.SetRoleSessionTTL(testProject, "r_short", 300); err != nil {
		t.Fatalf("SetRoleSessionTTL: %v", err)
	}
	if err := svc.AssignRole(testProject, "user-1", "r_short"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	roles, err := svc.GetUserRoles(testProject, "user-1")
	if err != nil {
		t.Fatalf("GetUserRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].SessionTtl != 300 {
		t.Fatalf("expected one role with SessionTtl=300, got %+v", roles)
	}
}

// TestProjectsAreIsolated is the property project_id exists for: the same
// subject id can hold different roles in different projects without
// either leaking into the other.
func TestProjectsAreIsolated(t *testing.T) {
	svc := newTestService(t)
	const (
		projectA = "misitio"
		projectB = "mjosefa-cms"
		subject  = "user-shared-across-projects"
	)

	if err := svc.CreateRole(projectA, "role_admin", "admin", "Admin", ""); err != nil {
		t.Fatalf("CreateRole(A): %v", err)
	}
	if err := svc.CreatePermission(projectA, "perm_all", "All", model.Wildcard, model.AllActions); err != nil {
		t.Fatalf("CreatePermission(A): %v", err)
	}
	if err := svc.AssignPermission(projectA, "role_admin", "perm_all"); err != nil {
		t.Fatalf("AssignPermission(A): %v", err)
	}
	if err := svc.AssignRole(projectA, subject, "role_admin"); err != nil {
		t.Fatalf("AssignRole(A): %v", err)
	}

	// Same role id ("role_admin"), different project: must not collide with A,
	// and subject has NOT been assigned it in B.
	if err := svc.CreateRole(projectB, "role_admin", "admin", "Admin", ""); err != nil {
		t.Fatalf("CreateRole(B) should not collide with project A's role of the same id: %v", err)
	}

	if !svc.Can(projectA, subject, "anything", model.Read) {
		t.Error("expected subject to have wildcard access in project A")
	}
	if svc.Can(projectB, subject, "anything", model.Read) {
		t.Error("expected subject to have NO access in project B: role was never assigned there")
	}
}

// TestHasPermission_CorruptActionFailsLoudly is ported from webtyp/auth
// (pre-split vestige, see rbac ARCHITECTURE.md): a row whose stored action
// is not a valid CRUD string must deny AND surface an error — never a
// silent (false, nil) indistinguishable from "no permission". Such a row
// can only come from the database directly — CreatePermission's typed
// model.Action cannot write one — so this seeds it via the raw *orm.DB,
// simulating a hand edit, a migration, or an old library version.
func TestHasPermission_CorruptActionFailsLoudly(t *testing.T) {
	db, svc := newTestServiceWithDB(t)

	if err := svc.CreateRole(testProject, "r_corrupt", "editor", "Editor", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := db.Create(&rbac.Permission{
		ProjectId: testProject, Id: "p_corrupt", Name: "corrupt",
		Resource: "docs", Action: "raed", // not a CRUD string: ParseAction must fail
	}); err != nil {
		t.Fatalf("seed corrupt permission: %v", err)
	}
	if err := svc.AssignPermission(testProject, "r_corrupt", "p_corrupt"); err != nil {
		t.Fatalf("AssignPermission: %v", err)
	}
	if err := svc.AssignRole(testProject, "user-corrupt", "r_corrupt"); err != nil {
		t.Fatalf("AssignRole: %v", err)
	}

	ok, err := svc.HasPermission(testProject, "user-corrupt", "docs", model.Read)
	if ok {
		t.Error("a corrupt row granted permission")
	}
	if err == nil {
		t.Fatal("HasPermission swallowed an illegible action: returned (false, nil), " +
			"indistinguishable from \"this subject has no such permission\"")
	}
}

func TestCreateRoleRejectsDuplicateCode(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "id-1", "admin", "Admin 1", ""); err != nil {
		t.Fatalf("CreateRole initial: %v", err)
	}
	err := svc.CreateRole(testProject, "id-2", "admin", "Admin 2", "")
	if err != rbac.ErrDuplicateRoleCode {
		t.Fatalf("expected ErrDuplicateRoleCode, got %v", err)
	}
}

func TestSameCodeAllowedInDifferentProjects(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole("proj-A", "id-a", "admin", "Admin A", ""); err != nil {
		t.Fatalf("CreateRole proj-A: %v", err)
	}
	if err := svc.CreateRole("proj-B", "id-b", "admin", "Admin B", ""); err != nil {
		t.Fatalf("CreateRole proj-B with same code in different project should succeed: %v", err)
	}
}

func TestCreateRoleSameIDStillUpserts(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "id-1", "admin", "Admin", "Initial"); err != nil {
		t.Fatalf("CreateRole initial: %v", err)
	}
	if err := svc.CreateRole(testProject, "id-1", "admin_v2", "Admin Updated", "Updated"); err != nil {
		t.Fatalf("CreateRole same ID upsert: %v", err)
	}
	r, err := svc.GetRole(testProject, "id-1")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if r.Code != "admin_v2" || r.Name != "Admin Updated" {
		t.Fatalf("unexpected role after upsert: %+v", r)
	}
}

func TestGetRoleByCodeErrorsOnAmbiguity(t *testing.T) {
	db, svc := newTestServiceWithDB(t)

	// Seed duplicate role rows directly into DB (bypassing CreateRole check)
	if err := db.Create(&rbac.Role{ProjectId: testProject, Id: "id-1", Code: "editor", Name: "Ed1"}); err != nil {
		t.Fatalf("db.Create 1: %v", err)
	}
	if err := db.Create(&rbac.Role{ProjectId: testProject, Id: "id-2", Code: "editor", Name: "Ed2"}); err != nil {
		t.Fatalf("db.Create 2: %v", err)
	}

	_, err := svc.GetRoleByCode(testProject, "editor")
	if err != rbac.ErrDuplicateRoleCode {
		t.Fatalf("expected GetRoleByCode to return ErrDuplicateRoleCode on duplicate codes, got %v", err)
	}
}

func TestMigrateDetectsPreexistingDuplicates(t *testing.T) {
	db := orm.New(mem.New())
	ddlCompiler := &mockCompiler{}

	// Pre-create table and seed duplicate role rows directly
	if err := db.RawConn().Exec("CREATE TABLE role (project_id TEXT, id TEXT, code TEXT, name TEXT, description TEXT, session_ttl INT, PRIMARY KEY(project_id, id))"); err != nil {
		t.Fatalf("exec create table: %v", err)
	}
	if err := db.Create(&rbac.Role{ProjectId: "proj-dup", Id: "r1", Code: "dupcode", Name: "N1"}); err != nil {
		t.Fatalf("db.Create r1: %v", err)
	}
	if err := db.Create(&rbac.Role{ProjectId: "proj-dup", Id: "r2", Code: "dupcode", Name: "N2"}); err != nil {
		t.Fatalf("db.Create r2: %v", err)
	}

	dups, err := rbac.FindDuplicateRoleCodes(db)
	if err != nil {
		t.Fatalf("FindDuplicateRoleCodes: %v", err)
	}
	if len(dups) != 1 || dups[0].ProjectID != "proj-dup" || dups[0].Code != "dupcode" {
		t.Fatalf("FindDuplicateRoleCodes expected [proj-dup, dupcode], got %+v", dups)
	}

	err = rbac.Migrate(db.RawConn(), ddlCompiler)
	if err != rbac.ErrDuplicateRoleCode {
		t.Fatalf("expected Migrate to return ErrDuplicateRoleCode on preexisting duplicates, got %v", err)
	}
}

func TestRevokeRoleByCodeInvalidatesCache(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_viewer", "viewer", "Viewer", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.CreatePermission(testProject, "p_read", "Read docs", "docs", model.Read); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if err := svc.AssignPermission(testProject, "r_viewer", "p_read"); err != nil {
		t.Fatalf("AssignPermission: %v", err)
	}
	if err := svc.AssignRoleByCode(testProject, "user-viewer", "viewer"); err != nil {
		t.Fatalf("AssignRoleByCode: %v", err)
	}

	if !svc.Can(testProject, "user-viewer", "docs", model.Read) {
		t.Fatal("expected viewer to read docs")
	}

	if err := svc.RevokeRoleByCode(testProject, "user-viewer", "viewer"); err != nil {
		t.Fatalf("RevokeRoleByCode: %v", err)
	}

	if svc.Can(testProject, "user-viewer", "docs", model.Read) {
		t.Fatal("expected permission to be revoked and cache invalidated")
	}
}

func TestRevokeRoleByCodeIsIdempotent(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_manager", "manager", "Manager", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	if err := svc.RevokeRoleByCode(testProject, "user-unassigned", "manager"); err != nil {
		t.Fatalf("RevokeRoleByCode on unassigned user should succeed (idempotent), got %v", err)
	}
}

func TestRevokeRoleByCodeUnknownCode(t *testing.T) {
	svc := newTestService(t)
	err := svc.RevokeRoleByCode(testProject, "user-1", "nonexistent_code")
	if err != rbac.ErrRoleNotFound {
		t.Fatalf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestAssignRoleByCodeDoesNotCreateRole(t *testing.T) {
	svc := newTestService(t)
	err := svc.AssignRoleByCode(testProject, "user-1", "nonexistent_code")
	if err != rbac.ErrRoleNotFound {
		t.Fatalf("expected ErrRoleNotFound, got %v", err)
	}

	_, err = svc.GetRoleByCode(testProject, "nonexistent_code")
	if err != rbac.ErrRoleNotFound {
		t.Fatalf("expected role still not to exist, got %v", err)
	}
}

func TestUsersInRole(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_dev", "developer", "Dev", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	users, err := svc.UsersInRole(testProject, "developer")
	if err != nil {
		t.Fatalf("UsersInRole empty: %v", err)
	}
	if users == nil || len(users) != 0 {
		t.Fatalf("expected empty non-nil slice for role without users, got %+v", users)
	}

	if err := svc.AssignRoleByCode(testProject, "u1", "developer"); err != nil {
		t.Fatalf("AssignRoleByCode u1: %v", err)
	}
	if err := svc.AssignRoleByCode(testProject, "u2", "developer"); err != nil {
		t.Fatalf("AssignRoleByCode u2: %v", err)
	}

	users, err = svc.UsersInRole(testProject, "developer")
	if err != nil {
		t.Fatalf("UsersInRole: %v", err)
	}
	if len(users) != 2 || users[0] != "u1" || users[1] != "u2" {
		t.Fatalf("unexpected UsersInRole result: %+v", users)
	}
}

func TestRoleUserCount(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_tester", "tester", "Tester", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	cnt, err := svc.RoleUserCount(testProject, "tester")
	if err != nil || cnt != 0 {
		t.Fatalf("expected 0 users, got %d, err %v", cnt, err)
	}

	_ = svc.AssignRoleByCode(testProject, "u1", "tester")
	_ = svc.AssignRoleByCode(testProject, "u2", "tester")

	cnt, err = svc.RoleUserCount(testProject, "tester")
	if err != nil || cnt != 2 {
		t.Fatalf("expected 2 users, got %d, err %v", cnt, err)
	}
}

func TestDeleteRoleUnknownReturnsNotFound(t *testing.T) {
	svc := newTestService(t)
	err := svc.DeleteRole(testProject, "unknown_role_id")
	if err != rbac.ErrRoleNotFound {
		t.Fatalf("expected ErrRoleNotFound, got %v", err)
	}
}

func TestDeleteRoleByCodeRemovesAssignments(t *testing.T) {
	svc := newTestService(t)
	if err := svc.CreateRole(testProject, "r_ops", "ops", "Ops", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.AssignRoleByCode(testProject, "u_ops", "ops"); err != nil {
		t.Fatalf("AssignRoleByCode: %v", err)
	}

	if err := svc.DeleteRoleByCode(testProject, "ops"); err != nil {
		t.Fatalf("DeleteRoleByCode: %v", err)
	}

	_, err := svc.UsersInRole(testProject, "ops")
	if err != rbac.ErrRoleNotFound {
		t.Fatalf("expected ErrRoleNotFound after role deleted by code, got %v", err)
	}
}
