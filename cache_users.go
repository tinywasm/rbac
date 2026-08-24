package rbac

import (
	"sync"
)

const maxCacheUsers = 1000

type cacheKey struct {
	ProjectID string
	SubjectID string
}

type userCacheItem struct {
	key cacheKey
	val *subjectGrants
}

type userCache struct {
	mu    sync.RWMutex
	items []userCacheItem
}

func newUserCache() *userCache {
	return &userCache{
		items: make([]userCacheItem, 0, maxCacheUsers),
	}
}

func (c *userCache) Get(projectID, subjectID string) (*subjectGrants, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	key := cacheKey{projectID, subjectID}
	for _, item := range c.items {
		if item.key == key {
			return item.val, true
		}
	}
	return nil, false
}

func (c *userCache) Set(projectID, subjectID string, g *subjectGrants) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{projectID, subjectID}

	for i, item := range c.items {
		if item.key == key {
			c.items[i].val = g
			return
		}
	}

	if len(c.items) >= maxCacheUsers {
		// Evict oldest (FIFO)
		c.items = c.items[1:]
	}
	c.items = append(c.items, userCacheItem{key: key, val: g})
}

func (c *userCache) Delete(projectID, subjectID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := cacheKey{projectID, subjectID}

	for i, item := range c.items {
		if item.key == key {
			c.items = append(c.items[:i], c.items[i+1:]...)
			return
		}
	}
}

// InvalidateByRole evicts every cached subject holding roleID, regardless
// of project: role ids are meant to be project-scoped by convention, but
// evicting an unrelated project's cache entry on a rare id collision costs
// one extra cache miss, never a correctness bug.
func (c *userCache) InvalidateByRole(roleID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var active []userCacheItem
	for _, item := range c.items {
		hasRole := false
		for _, r := range item.val.Roles {
			if r.Id == roleID {
				hasRole = true
				break
			}
		}
		if !hasRole {
			active = append(active, item)
		}
	}
	c.items = active
}

func (c *userCache) InvalidateByPermission(permID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var active []userCacheItem
	for _, item := range c.items {
		hasPerm := false
		for _, p := range item.val.Permissions {
			if p.Id == permID {
				hasPerm = true
				break
			}
		}
		if !hasPerm {
			active = append(active, item)
		}
	}
	c.items = active
}

func (c *userCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make([]userCacheItem, 0, maxCacheUsers)
}
