// Package memstore 是 auth.Store 的内存实现：用于测试与单进程应用（进程重启即全部掉线）。
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	auth "github.com/ZhcChen/cc-auth-go"
)

// Store 是内存会话存储，可并发使用。零值不可用，用 New 创建。
type Store struct {
	mu   sync.Mutex
	byID map[string]*auth.Session
}

var (
	_ auth.Store   = (*Store)(nil)
	_ auth.Sweeper = (*Store)(nil)
)

// New 创建空的内存存储。
func New() *Store { return &Store{byID: map[string]*auth.Session{}} }

// Create 实现 auth.Store。
func (m *Store) Create(_ context.Context, s *auth.Session, lim auth.Limits) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.byID[s.ID]; dup {
		return nil, auth.ErrConflict
	}
	m.byID[s.ID] = s.Clone()

	var evicted []string
	// evict 把 others（不含新会话，按登录时间升序）中超出 limit 的最早会话吊销为“被顶替”；新会话本身计入总数。
	evict := func(others []*auth.Session, limit int) {
		for i := 0; i < len(others)+1-limit && i < len(others); i++ {
			v := others[i]
			v.RevokedAt, v.RevokeReason, v.Gen = s.CreatedAt, auth.ReasonReplaced, v.Gen+1
			evicted = append(evicted, v.ID)
		}
	}
	if lim.MaxPerDevice > 0 {
		var same []*auth.Session
		for _, x := range m.liveLocked(s.Subject, s.ID, lim) {
			if x.Device == s.Device {
				same = append(same, x)
			}
		}
		evict(same, lim.MaxPerDevice)
	}
	if lim.MaxTotal > 0 {
		evict(m.liveLocked(s.Subject, s.ID, lim), lim.MaxTotal)
	}
	return evicted, nil
}

// liveLocked 返回账号除 exceptID 外的有效会话（按 CreatedAt、ID 升序），元素指向存储内部对象。
func (m *Store) liveLocked(subject, exceptID string, lim auth.Limits) []*auth.Session {
	var out []*auth.Session
	for _, x := range m.byID {
		if x.Subject != subject || x.ID == exceptID || x.Revoked() || x.LastSeenAt.Before(lim.IdleCutoff) || x.CreatedAt.Before(lim.AbsoluteCutoff) {
			continue
		}
		out = append(out, x)
	}
	sortSessions(out)
	return out
}

// Get 实现 auth.Store。
func (m *Store) Get(_ context.Context, id string) (*auth.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return nil, auth.ErrNotFound
	}
	return s.Clone(), nil
}

// Save 实现 auth.Store。
func (m *Store) Save(_ context.Context, s *auth.Session, expectGen int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.byID[s.ID]
	if !ok {
		return auth.ErrNotFound
	}
	if cur.Gen != expectGen {
		return auth.ErrConflict
	}
	m.byID[s.ID] = s.Clone()
	return nil
}

// Touch 实现 auth.Store。
func (m *Store) Touch(_ context.Context, id string, seen, ifBefore time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok {
		return auth.ErrNotFound
	}
	if s.LastSeenAt.Before(ifBefore) {
		s.LastSeenAt = seen
	}
	return nil
}

// List 实现 auth.Store。
func (m *Store) List(_ context.Context, subject string) ([]*auth.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*auth.Session
	for _, s := range m.byID {
		if s.Subject == subject {
			out = append(out, s.Clone())
		}
	}
	sortSessions(out)
	return out, nil
}

// RevokeSubject 实现 auth.Store。
func (m *Store) RevokeSubject(_ context.Context, subject, exceptID string, reason auth.Reason, at time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.byID {
		if s.Subject == subject && s.ID != exceptID && !s.Revoked() {
			s.RevokedAt, s.RevokeReason, s.Gen = at, reason, s.Gen+1
			n++
		}
	}
	return n, nil
}

// DeleteExpired 实现 auth.Sweeper。
func (m *Store) DeleteExpired(_ context.Context, createdBefore, seenBefore time.Time) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.byID {
		if s.CreatedAt.Before(createdBefore) || s.LastSeenAt.Before(seenBefore) {
			delete(m.byID, id)
			n++
		}
	}
	return n, nil
}

func sortSessions(ss []*auth.Session) {
	sort.Slice(ss, func(i, j int) bool {
		if !ss[i].CreatedAt.Equal(ss[j].CreatedAt) {
			return ss[i].CreatedAt.Before(ss[j].CreatedAt)
		}
		return ss[i].ID < ss[j].ID
	})
}
