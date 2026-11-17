package auth

import (
	"context"
	"sync"
	"time"
)

// Grants 是账号的授权信息。
type Grants struct {
	Disabled    bool     // 账号已停用：拒绝一切请求
	Permissions []string // 已把角色展开后的权限码（可含通配）
}

// PermissionLoader 按账号加载授权信息（使用方实现，如查询账号与角色表）。
type PermissionLoader interface {
	Load(ctx context.Context, subject string) (Grants, error)
}

// PermissionLoaderFunc 让普通函数实现 PermissionLoader。
type PermissionLoaderFunc func(ctx context.Context, subject string) (Grants, error)

// Load 调用 f。
func (f PermissionLoaderFunc) Load(ctx context.Context, subject string) (Grants, error) {
	return f(ctx, subject)
}

const maxPermEntries = 10000

type permEntry struct {
	g  Grants
	at time.Time
}

// permCache 按账号缓存 Grants。多节点之间不同步：改角色后由使用方广播并调用 InvalidatePermissions。
type permCache struct {
	loader PermissionLoader
	ttl    time.Duration
	now    func() time.Time

	mu sync.Mutex
	m  map[string]permEntry
}

func (c *permCache) get(ctx context.Context, subject string, fresh bool) (Grants, error) {
	now := c.now()
	if !fresh {
		c.mu.Lock()
		e, ok := c.m[subject]
		c.mu.Unlock()
		if ok && now.Sub(e.at) < c.ttl {
			return e.g, nil
		}
	}
	g, err := c.loader.Load(ctx, subject)
	if err != nil {
		return Grants{}, err
	}
	c.mu.Lock()
	if len(c.m) >= maxPermEntries {
		for k, e := range c.m {
			if now.Sub(e.at) >= c.ttl {
				delete(c.m, k)
			}
		}
		if len(c.m) >= maxPermEntries {
			clear(c.m)
		}
	}
	c.m[subject] = permEntry{g: g, at: now}
	c.mu.Unlock()
	return g, nil
}

func (c *permCache) invalidate(subject string) {
	c.mu.Lock()
	delete(c.m, subject)
	c.mu.Unlock()
}
