package rbac

import "github.com/tinywasm/fmt"

// ErrNotFound reports that a role or permission id has no matching row.
var ErrNotFound = fmt.Err("rbac", "not", "found")

func isUniqueViolation(err error) bool {
	return fmt.Contains(err.Error(), "UNIQUE constraint failed") ||
		fmt.Contains(err.Error(), "constraint: unique") ||
		fmt.Contains(err.Error(), "duplicate key")
}
