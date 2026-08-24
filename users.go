package rbac

import (
	"github.com/tinywasm/fmt"
	"github.com/tinywasm/time"

	"github.com/tinywasm/model"
	"github.com/tinywasm/orm"
)

func createUser(db *orm.DB, ids model.IDGenerator, email, name, phone string) (User, error) {
	id := ids.NewID()
	now := time.Now() / 1e9

	newUser := User{
		Id:        id,
		Email:     email,
		Name:      name,
		Phone:     phone,
		Status:    "active",
		CreatedAt: now,
	}

	if err := db.Create(&newUser); err != nil {
		if isUniqueViolation(err) {
			return User{}, ErrEmailTaken
		}
		return User{}, err
	}
	return newUser, nil
}

func hydrateUser(db *orm.DB, u *User) error {
	// 1. Fetch UserRoles to get Role IDs
	qbUserRoles := db.Query(&UserRole{}).Where(UserRole_.UserId).Eq(u.Id)
	userRoles, err := ReadAllUserRole(qbUserRoles)
	if err != nil {
		return err
	}

	var roleIDs []any
	for _, ur := range userRoles {
		roleIDs = append(roleIDs, ur.RoleId)
	}

	if len(roleIDs) > 0 {
		// 2. Fetch Roles
		qbRoles := db.Query(&Role{}).Where(Role_.Id).In(roleIDs)
		roles, err := ReadAllRole(qbRoles)
		if err != nil {
			return err
		}
		u.Roles = make([]Role, len(roles))
		for i, r := range roles {
			u.Roles[i] = *r
		}

		// 3. Fetch RolePermissions to get Permission IDs
		qbRolePerms := db.Query(&RolePermission{}).Where(RolePermission_.RoleId).In(roleIDs)
		rolePerms, err := ReadAllRolePermission(qbRolePerms)
		if err != nil {
			return err
		}

		var permIDs []any
		for _, rp := range rolePerms {
			permIDs = append(permIDs, rp.PermissionId)
		}

		if len(permIDs) > 0 {
			// 4. Fetch Permissions
			qbPerms := db.Query(&Permission{}).Where(Permission_.Id).In(permIDs)
			perms, err := ReadAllPermission(qbPerms)
			if err != nil {
				return err
			}

			// Deduplicate permissions using slice lookup (no map)
			var uniquePerms []Permission
			for _, p := range perms {
				exists := false
				for _, up := range uniquePerms {
					if up.Id == p.Id {
						exists = true
						break
					}
				}
				if !exists {
					uniquePerms = append(uniquePerms, *p)
				}
			}
			u.Permissions = uniquePerms
		} else {
			u.Permissions = []Permission{}
		}
	} else {
		u.Roles = []Role{}
		u.Permissions = []Permission{}
	}

	return nil
}

func (m *Service) GetUser(id string) (User, error) {
	return getUser(m.db, m.ucache, id)
}

func getUser(db *orm.DB, cache *userCache, id string) (User, error) {
	if cache != nil {
		if cached, ok := cache.Get(id); ok {
			return *cached, nil
		}
	}

	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil {
		return User{}, err
	}
	if len(results) == 0 {
		return User{}, ErrNotFound
	}
	u := results[0]

	if err := hydrateUser(db, u); err != nil {
		return User{}, err
	}

	if cache != nil {
		cache.Set(u.Id, u)
	}
	return *u, nil
}

func getUserByEmail(db *orm.DB, cache *userCache, email string) (User, error) {
	qb := db.Query(&User{}).Where(User_.Email).Eq(email)
	results, err := ReadAllUser(qb)
	if err != nil {
		return User{}, err
	}
	if len(results) == 0 {
		return User{}, ErrNotFound
	}
	u := results[0]

	if cache != nil {
		if cached, ok := cache.Get(u.Id); ok {
			return *cached, nil
		}
	}

	if err := hydrateUser(db, u); err != nil {
		return User{}, err
	}

	if cache != nil {
		cache.Set(u.Id, u)
	}
	return *u, nil
}

func updateUser(db *orm.DB, cache *userCache, id, name, phone string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return ErrNotFound
	}
	u := results[0]
	u.Name = name
	u.Phone = phone
	return db.Update(u, orm.Eq(User_.Id, u.Id))
}

func updateUserAvatar(db *orm.DB, cache *userCache, id, avatar string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return ErrNotFound
	}
	u := results[0]
	u.Avatar = avatar
	return db.Update(u, orm.Eq(User_.Id, u.Id))
}

func suspendUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return ErrNotFound
	}
	u := results[0]
	u.Status = "suspended"
	return db.Update(u, orm.Eq(User_.Id, u.Id))
}

func reactivateUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return ErrNotFound
	}
	u := results[0]
	u.Status = "active"
	return db.Update(u, orm.Eq(User_.Id, u.Id))
}

func listUsers(db *orm.DB) ([]User, error) {
	qb := db.Query(&User{})
	users, err := ReadAllUser(qb)
	if err != nil {
		return nil, err
	}
	var res []User
	for _, u := range users {
		hydrateUser(db, u)
		res = append(res, *u)
	}
	return res, nil
}

func deleteUser(db *orm.DB, cache *userCache, id string) error {
	if cache != nil {
		cache.Delete(id)
	}
	qb := db.Query(&User{}).Where(User_.Id).Eq(id)
	results, err := ReadAllUser(qb)
	if err != nil || len(results) == 0 {
		return ErrNotFound
	}
	u := results[0]
	return db.Delete(u, orm.Eq(User_.Id, u.Id))
}

func isUniqueViolation(err error) bool {
	return fmt.Contains(err.Error(), "UNIQUE constraint failed") ||
		fmt.Contains(err.Error(), "constraint: unique") ||
		fmt.Contains(err.Error(), "duplicate key")
}
