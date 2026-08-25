package tests

import (
	"testing"

	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
	"github.com/tinywasm/rbac"
	"github.com/tinywasm/storage/mem"
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
	svc, err := rbac.New(db)
	if err != nil {
		t.Fatalf("rbac.New: %v", err)
	}
	return db, svc
}

const testProject = "proj-1"

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

// TestHasPermission_CorruptActionFailsLoudly is ported from tinywasm/auth
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
