package rbac

import (
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
)

func initSchema(db *orm.DB) error {
	models := []model.Model{
		&User{}, &Role{}, &Permission{},
		&Identity{}, &LANIP{},
		&OAuthState{}, &UserRole{}, &RolePermission{},
		&Session{},
	}
	ddlCompiler, ok := db.RawConn().(ddl.Compiler)
	if !ok {
		return nil
	}
	sorted, err := ddl.TopologicalSort(models)
	if err != nil {
		return err
	}
	return ddl.New(db.RawConn(), ddlCompiler).Sync(sorted...)
}
