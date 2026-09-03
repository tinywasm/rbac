package rbac

import "github.com/tinywasm/fmt"

// ErrNotFound reports that a role or permission id has no matching row.
var ErrNotFound = fmt.Err("rbac", "not", "found")

// ErrDuplicateRoleCode reporta que la base tiene dos roles con el mismo code
// dentro de un proyecto — un estado que este paquete ya no permite crear pero
// que una base anterior a esta versión pudo haber acumulado. Se resuelve a
// mano: hay que decidir cuál de los dos roles sobrevive y reasignar sus
// usuarios. Migrate NO lo resuelve solo porque elegir cuál borrar es una
// decisión de política, no de esquema.
var ErrDuplicateRoleCode = fmt.Err("rbac", "duplicate", "role", "code")

// ErrRoleNotFound reporta que el rol identificado por su code no existe en el
// proyecto especificado.
var ErrRoleNotFound = fmt.Err("rbac", "role", "not", "found")

func isUniqueViolation(err error) bool {
	return fmt.Contains(err.Error(), "UNIQUE constraint failed") ||
		fmt.Contains(err.Error(), "constraint: unique") ||
		fmt.Contains(err.Error(), "duplicate key")
}
