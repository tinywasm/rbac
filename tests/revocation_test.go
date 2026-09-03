package tests

import (
	"testing"

	"github.com/tinywasm/model"
)

// TestAdminRevokesAccess_TakesEffectImmediately reproduces the exact flow
// of the admin panel in veltylabs/iam, proving that revoking a role by code
// invalidates the permissions cache immediately on the same Service instance.
func TestAdminRevokesAccess_TakesEffectImmediately(t *testing.T) {
	svc := newTestService(t)
	const (
		projectID = "proj-revocation"
		roleID    = "r_admin_id"
		roleCode  = model.RoleCode("admin")
		userID    = "user-1"
		permID    = "docs:u"
	)

	if err := svc.CreateRole(projectID, roleID, roleCode, "Admin", ""); err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := svc.CreatePermission(projectID, permID, "Update docs", "docs", model.Update); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	if err := svc.AssignPermission(projectID, roleID, permID); err != nil {
		t.Fatalf("AssignPermission: %v", err)
	}
	if err := svc.AssignRoleByCode(projectID, userID, roleCode); err != nil {
		t.Fatalf("AssignRoleByCode: %v", err)
	}

	// 1. Check permission — populates the subject cache in svc
	ok, err := svc.HasPermission(projectID, userID, "docs", model.Update)
	if err != nil {
		t.Fatalf("HasPermission initial check: %v", err)
	}
	if !ok {
		t.Fatal("expected user to have permission before revocation")
	}

	// 2. Revoke role by code — the method exposed to admin consumers
	if err := svc.RevokeRoleByCode(projectID, userID, roleCode); err != nil {
		t.Fatalf("RevokeRoleByCode: %v", err)
	}

	// 3. Permission check MUST return false immediately without recreating Service
	ok, err = svc.HasPermission(projectID, userID, "docs", model.Update)
	if err != nil {
		t.Fatalf("HasPermission after revocation check: %v", err)
	}
	if ok {
		t.Fatal("revocation failed to invalidate cache: user still has permission!")
	}
}
