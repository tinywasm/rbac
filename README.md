# tinywasm/rbac
<img src="docs/img/badges.svg">

Role-based authorization runtime for TinyWasm applications. Authentication and
sessions belong to `tinywasm/auth`. Both are siblings that depend only on
`tinywasm/user` and never on each other.

```mermaid
flowchart TD
    U[user] --> R[rbac]
    U --> A[auth]
    R --> C[app]
    A --> C
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Dependency rules and authorization mechanics

## Usage

Every table — and every call — carries a `projectID`: one `Service` over one
database serves every consuming project (`misitio`, `mjosefa-cms`, ...)
without their roles/permissions colliding or leaking into each other.

Schema reconciliation (`rbac.Migrate`) is performed once at deploy time, not inside `rbac.New`:

```go
import (
    "github.com/tinywasm/rbac"
    "github.com/tinywasm/model"
    "github.com/tinywasm/orm"
    "github.com/tinywasm/sqlite"
    "github.com/tinywasm/sqlt"
)

conn, _ := sqlite.Open("app.db")
_ = rbac.Migrate(conn, sqlt.NewCompiler())

db := orm.New(conn)
svc, _ := rbac.New(db)

const projectID = "misitio"

_ = svc.CreateRole(projectID, "role_admin", "admin", "Administrator", "")
_ = svc.CreatePermission(projectID, "service_catalog:crud", "catalog", "service_catalog", model.AllActions)
_ = svc.AssignPermission(projectID, "role_admin", "service_catalog:crud")
_ = svc.AssignRole(projectID, string(subjectID), "role_admin")

if svc.Can(projectID, string(subjectID), "service_catalog", model.Read) {
    // granted
}
```

Empty or unknown subject IDs are denied — rbac never persists a "user" row,
so a subject with no assignments simply resolves to zero permissions, not
an error. Malformed stored actions deny and surface an error (never a
silent `false, nil`).
