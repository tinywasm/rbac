package rbac

import (
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
)

func initSchema(db *orm.DB) error {
	models := []model.Model{&Role{}, &Permission{}, &UserRole{}, &RolePermission{}}
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
