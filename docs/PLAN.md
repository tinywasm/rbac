---
PLAN: "feat!: Migrate is explicit — rbac.New stops running schema DDL"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 3878491805577921475
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.
>
> **Companion plan:** `tinywasm/auth` gets the identical change
> (`auth/docs/PLAN.md`, `authority.Migrate`). They are independent — neither
> imports the other — but a consumer needs both published before it can drop
> schema work from its startup path, so they should land together.

# Plan — `tinywasm/rbac`: `Migrate`, called by the deployer, not the constructor

## Why

`rbac.New` runs `initSchema(db)` (module.go:19), which calls
`ddl.New(...).Sync(...)` over four models (migrate.go). In a Cloudflare
Worker that means **four schema round trips on every isolate cold start** —
work whose result is identical every time, on the request path.

Measured in `veltylabs/iam`, whose `main()` builds `authority` + `rbac` +
its own project schema (~14 models total): instrumented with `Date.now()`
deltas, deployed, and the instrumentation reverted (see that repo's two
`debug:` commits, 2026-08-25):

```
timing: d1.NewEdge                0 ms
timing: unixid.NewUnixID          0 ms
timing: NewProductionBackend   8531 ms  /  10407 ms
```

Cloudflare recycles isolates constantly, so real users pay those seconds
regularly. The schema must be reconciled **once at deploy time** instead.
`tinywasm/goflare` already ships the transport for that
(`goflare.NewD1Migrator`, v0.5.22 — a `ddl.Execer` over D1's HTTP API).
What is missing is a way for a deployer to run *this package's* migration
without constructing the service: today the DDL is welded to the constructor.

## Stage 1 — export `Migrate`, drop the implicit call

`migrate.go`: rename `initSchema` to `Migrate` and widen its parameter so a
deployer can pass a migration-only connection.

```go
package rbac

import (
	"github.com/tinywasm/ddl"
	"github.com/tinywasm/model"
)

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
	return ddl.New(conn, ddlCompiler).Sync(sorted...)
}
```

Two behavioral notes the executor must not "tidy away":

- The old `initSchema` silently returned `nil` when
  `db.RawConn().(ddl.Compiler)` failed. That swallow is gone on purpose:
  the compiler is now a required argument, so a caller that cannot provide
  one gets a compile error instead of a migration that quietly did nothing.
- `Migrate` takes the compiler explicitly rather than type-asserting it out
  of the connection, because a `ddl.Execer` carries no compiler at all —
  that is the whole point of `tinywasm/ddl` v0.0.12's `Execer`.

`module.go`: delete the `initSchema` call in `New` (line ~19) and its error
branch. `New` becomes `return &Service{db: db, ucache: newUserCache()}, nil`
— note it can no longer fail, but **keep the `(*Service, error)` signature**:
changing it would break every caller for no benefit, and a future
constructor-time check would want the error back.

## Stage 2 — fix every caller that relied on the implicit migration

This is the breaking half. `New` no longer creates tables, so **anything
that called `rbac.New` against an empty database and then used it will now
fail at the first query** — the error surfaces later, at the query, not at
construction.

Find them: `grep -rn "rbac.New(" --include="*.go" .` across this repo. Every
test fixture that built a service against a fresh in-memory DB must now call
`rbac.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))` first. Do not add a
helper that hides the call — the explicitness is the feature.

## Stage 3 — documentation

- `docs/ARCHITECTURE.md` (and `README.md` if it shows a setup example): the
  setup sequence gains a `Migrate` step, and must state that `New` assumes
  the schema exists.
- `AGENTS.md`: if it describes `New` as initializing the schema, correct it.

## Known risk — verify before publishing

This repo pins `github.com/tinywasm/router v0.1.27`. Router **v0.1.28**
changed `Context.Value` to return `string` instead of `any`. `gopush` bumps
dependencies, so publishing may pull router forward.

Check whether this repo actually uses `router.Context.Value` before
worrying: `grep -rn "\.Value(" --include="*.go" .`. If it does not, the bump
is harmless. If it does, and the cascade is not clean, publish with the
router version held rather than half-migrating the ecosystem — the related
`tinywasm/server` was left unpublished as of 2026-08-25 (local commit only).

## Acceptance criteria

- [ ] `go build ./...` and `go vet ./...` clean.
- [ ] `gotest` green.
- [ ] `grep -rn "initSchema" --include="*.go" .` → empty.
- [ ] `grep -n "Migrate" module.go` → empty (the constructor does not call it).
- [ ] `rbac.Migrate` accepts a `ddl.Execer` — confirm by compiling a
      throwaway snippet that passes something implementing *only*
      `Exec(string, ...any) error`.
- [ ] No test fixture silently depends on `New` creating tables.

| Stage | File(s) | Done when |
|---|---|---|
| 1 | `migrate.go`, `module.go` | `Migrate(conn ddl.Execer, c ddl.Compiler)` exported; `New` no longer runs DDL |
| 2 | test fixtures across the repo | Every caller migrates explicitly; suite green |
| 3 | `docs/ARCHITECTURE.md`, `README.md`, `AGENTS.md` | Setup sequence shows the explicit `Migrate` step |
