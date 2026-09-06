package rbac

import (
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/storage"
)

// Índice único compuesto: dos roles con el mismo code dentro de un proyecto
// hacen que GetRoleByCode devuelva uno arbitrario y que borrar el rol deje
// vivo al otro con sus usuarios asignados — una revocación que no revoca.
// Se emite acá y no en el modelo porque webtyp/ddl todavía no expresa
// unicidad compuesta; si algún día lo hace, esto se muda al modelo.
const roleCodeUniqueIndex = `CREATE UNIQUE INDEX IF NOT EXISTS ` +
	`idx_role_project_code ON role (project_id, code)`

// RoleCodeRef nombra un rol por su par natural, el que el consumidor usa.
type RoleCodeRef struct {
	ProjectID string
	Code      string
}

// FindDuplicateRoleCodes devuelve los pares (project_id, code) que aparecen
// más de una vez. Vacío = la base está lista para el índice único.
func FindDuplicateRoleCodes(db *orm.DB) ([]RoleCodeRef, error) {
	qb := db.Query(&Role{})
	roles, err := ReadAllRole(qb)
	if err != nil {
		return nil, err
	}

	type roleCodeCount struct {
		ref RoleCodeRef
		cnt int
	}
	var counts []roleCodeCount
	for _, r := range roles {
		found := false
		for i := range counts {
			if counts[i].ref.ProjectID == r.ProjectId && counts[i].ref.Code == r.Code {
				counts[i].cnt++
				found = true
				break
			}
		}
		if !found {
			counts = append(counts, roleCodeCount{
				ref: RoleCodeRef{ProjectID: r.ProjectId, Code: r.Code},
				cnt: 1,
			})
		}
	}

	var dups []RoleCodeRef
	for _, c := range counts {
		if c.cnt > 1 {
			dups = append(dups, c.ref)
		}
	}
	if dups == nil {
		return []RoleCodeRef{}, nil
	}
	return dups, nil
}

// Migrate reconciles the database schema this package owns: Role,
// Permission, UserRole and RolePermission, in dependency order.
//
// It is deliberately NOT called by New. Schema reconciliation is deploy-time
// work — running it per process start costs a network round trip per model,
// which in a Cloudflare Worker is paid again on every isolate cold start
// (measured at 8.5–10.4 s across ~14 models in veltylabs/iam). Call this
// once from a migration binary, then let New assume the schema exists.
//
// conn is a ddl.Execer, not an *orm.DB, so a deploy-time transport that can
// only execute DDL satisfies it — goflare.NewD1Migrator returns exactly that.
// An *orm.DB's RawConn() also satisfies it, for local/test callers:
//
//	// deploy time, against D1's HTTP API:
//	conn, _ := goflare.NewD1Migrator(accountID, databaseID, apiToken)
//	err := rbac.Migrate(conn, sqlt.NewCompiler())
//
//	// local dev / tests, against an in-memory or sqlite DB:
//	err := rbac.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))
func Migrate(conn ddl.Execer, ddlCompiler ddl.Compiler) error {
	models := []model.Model{&Role{}, &Permission{}, &UserRole{}, &RolePermission{}}
	sorted, err := ddl.TopologicalSort(models)
	if err != nil {
		return err
	}
	if err := ddl.New(conn, ddlCompiler).Sync(sorted...); err != nil {
		return err
	}

	if sconn, ok := conn.(storage.Conn); ok {
		dups, err := FindDuplicateRoleCodes(orm.New(sconn))
		if err != nil {
			return err
		}
		if len(dups) > 0 {
			return ErrDuplicateRoleCode
		}
	}

	return conn.Exec(roleCodeUniqueIndex)
}
