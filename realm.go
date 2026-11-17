package auth

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// Realm 是一套独立的登录体系（如运维账号、后台账号、C 端用户）。
// 各 Realm 的令牌前缀、Cookie 名、存储、配置互不干扰。Realm 可被多个 goroutine 并发使用。
type Realm struct {
	name    string
	store   Store
	opt     Options
	devices map[string]bool
	origins map[string]bool
	perms   *permCache // 未配置 Permissions 时为 nil
}

const (
	maxSubjectLen = 128
	maxIPLen      = 64
	maxUALen      = 256
	saveRetries   = 3
)

// New 创建 Realm。name 为 1–32 个小写字母、数字或下划线，以字母开头。
func New(name string, store Store, opt Options) (*Realm, error) {
	if !realmNameRE.MatchString(name) {
		return nil, fmt.Errorf("auth: Realm 名称 %q 不合法", name)
	}
	if store == nil {
		return nil, errors.New("auth: Store 不能为空")
	}
	o, err := opt.normalized(name)
	if err != nil {
		return nil, err
	}
	r := &Realm{name: name, store: store, opt: o, devices: map[string]bool{}, origins: map[string]bool{}}
	for _, d := range o.Devices {
		r.devices[d] = true
	}
	for _, origin := range o.AllowedOrigins {
		r.origins[origin] = true
	}
	if o.Permissions != nil {
		r.perms = &permCache{loader: o.Permissions, ttl: o.PermissionTTL, now: o.Now, m: map[string]permEntry{}}
	}
	return r, nil
}

// Name 返回 Realm 名称。
func (r *Realm) Name() string { return r.name }

// Mode 返回令牌模式。
func (r *Realm) Mode() Mode { return r.opt.Mode }

func (r *Realm) now() time.Time { return r.opt.Now().UTC().Truncate(time.Microsecond) }

func (r *Realm) config() Config { return r.opt.Config().normalized() }

func (r *Realm) expired(s *Session, cfg Config, now time.Time) bool {
	return now.Sub(s.CreatedAt) > cfg.AbsoluteTimeout || now.Sub(s.LastSeenAt) > cfg.IdleTimeout
}

// Login 为已经验证过的账号创建会话并签发令牌。
// 账号密码校验、登录限流由使用方在调用前完成。配置了 Permissions 时，停用账号返回 ErrDisabled。
func (r *Realm) Login(ctx context.Context, subject string, info LoginInfo) (Tokens, error) {
	if subject == "" || len(subject) > maxSubjectLen {
		return Tokens{}, fmt.Errorf("auth: 账号 ID 不能为空且不超过 %d 字节", maxSubjectLen)
	}
	device := info.Device
	if device == "" {
		device = r.opt.Devices[0]
	}
	if !r.devices[device] {
		return Tokens{}, ErrDevice
	}
	if r.perms != nil {
		g, err := r.perms.get(ctx, subject, true)
		if err != nil {
			return Tokens{}, err
		}
		if g.Disabled {
			return Tokens{}, ErrDisabled
		}
	}
	if info.Replace != "" {
		// 防会话固定：请求里带来的旧会话（令牌须与会话相符）直接退出。
		if old, _, err := r.match(ctx, info.Replace); err == nil {
			_ = r.revoke(ctx, old.ID, ReasonLogout, EventLogout)
		}
	}
	id, err := r.opt.NewID(ctx)
	if err != nil {
		return Tokens{}, fmt.Errorf("auth: 生成会话 ID：%w", err)
	}
	if !validID(id) {
		return Tokens{}, errors.New("auth: NewID 返回的会话 ID 不合法")
	}
	access, err := newSecret(r.opt.Rand)
	if err != nil {
		return Tokens{}, err
	}
	now := r.now()
	s := &Session{
		ID: id, Subject: subject, Device: device, IP: truncate(info.IP, maxIPLen), UA: truncate(info.UA, maxUALen),
		CreatedAt: now, LastSeenAt: now, TokenHash: hashSecret(access), RotatedAt: now, Gen: 1,
	}
	var refresh []byte
	if r.opt.Mode == ModeRefresh {
		if refresh, err = newSecret(r.opt.Rand); err != nil {
			return Tokens{}, err
		}
		if s.RotateSalt, err = newSecret(r.opt.Rand); err != nil {
			return Tokens{}, err
		}
		s.RefreshHash = hashSecret(refresh)
	}
	cfg := r.config()
	evicted, err := r.store.Create(ctx, s, Limits{
		MaxPerDevice:   cfg.MaxSessionsPerDevice,
		MaxTotal:       cfg.MaxSessions,
		IdleCutoff:     now.Add(-cfg.IdleTimeout),
		AbsoluteCutoff: now.Add(-cfg.AbsoluteTimeout),
	})
	if err != nil {
		return Tokens{}, err
	}
	r.emit(ctx, Event{Type: EventLogin, Subject: subject, SessionID: id, Device: device, IP: s.IP, At: now})
	for _, e := range evicted {
		r.emit(ctx, Event{Type: EventReplaced, Subject: subject, SessionID: e, At: now})
	}
	return r.tokens(s, cfg, access, refresh), nil
}

func (r *Realm) tokens(s *Session, cfg Config, access, refresh []byte) Tokens {
	abs := s.CreatedAt.Add(cfg.AbsoluteTimeout)
	t := Tokens{SessionID: s.ID, Token: encodeToken(r.opt.TokenPrefix, kindAccess, s.ID, access), TokenExpiresAt: abs}
	if r.opt.Mode == ModeRefresh {
		t.TokenExpiresAt = earlier(s.RotatedAt.Add(r.opt.AccessTTL), abs)
		if refresh != nil {
			t.Refresh = encodeToken(r.opt.TokenPrefix, kindRefresh, s.ID, refresh)
			t.RefreshExpiresAt = abs
		}
	}
	return t
}

// match 按令牌取会话并核对哈希（当前令牌，或仍在有效期内的上一个令牌）；不检查吊销与超时。
// current 表示匹配的是当前令牌。
func (r *Realm) match(ctx context.Context, token string) (s *Session, current bool, err error) {
	id, secret, err := decodeToken(r.opt.TokenPrefix, kindAccess, token)
	if err != nil {
		return nil, false, err
	}
	s, err = r.store.Get(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return nil, false, ErrInvalidToken
	}
	if err != nil {
		return nil, false, err
	}
	h := hashSecret(secret)
	if sameHash(h, s.TokenHash) {
		return s, true, nil
	}
	if sameHash(h, s.PrevTokenHash) && r.now().Before(s.PrevTokenUntil) {
		return s, false, nil
	}
	return nil, false, ErrInvalidToken
}

// Verify 校验会话令牌或访问令牌，返回会话。
// 依次检查：令牌与会话相符、未吊销（返回吊销原因对应的错误）、未超时、访问令牌未过期（双 token）、账号未停用。
// 通过后按节流间隔更新最后活跃时间。
func (r *Realm) Verify(ctx context.Context, token string) (*Session, error) {
	if token == "" {
		return nil, ErrUnauthenticated
	}
	s, current, err := r.match(ctx, token)
	if err != nil {
		return nil, err
	}
	if s.Revoked() {
		return nil, s.RevokeReason.Err()
	}
	now := r.now()
	cfg := r.config()
	if r.expired(s, cfg, now) {
		return nil, ErrExpired
	}
	if r.opt.Mode == ModeRefresh && current && now.Sub(s.RotatedAt) >= r.opt.AccessTTL {
		// 上一个访问令牌由 PrevTokenUntil 约束（match 已检查），这里只约束当前访问令牌。
		return nil, ErrTokenExpired
	}
	if r.perms != nil {
		g, err := r.perms.get(ctx, s.Subject, false)
		if err != nil {
			return nil, err
		}
		if g.Disabled {
			return nil, ErrDisabled
		}
	}
	if iv := cfg.touchInterval(); now.Sub(s.LastSeenAt) > iv {
		if err := r.store.Touch(ctx, s.ID, now, now.Add(-iv)); err == nil {
			s.LastSeenAt = now
		}
	}
	return s, nil
}

// Refresh 用刷新令牌换新的访问令牌与刷新令牌（仅双 token 模式）。
//
//   - 当前刷新令牌：轮换，上一个访问令牌在自然过期前仍有效；
//   - 上一个刷新令牌且在宽限期内：幂等返回同一组新令牌（应对丢响应、并发刷新）；
//   - 上一个刷新令牌且超出宽限期：判定泄露，吊销会话并返回 ErrReused。
func (r *Realm) Refresh(ctx context.Context, refreshToken string) (Tokens, error) {
	if r.opt.Mode != ModeRefresh {
		return Tokens{}, errors.New("auth: 会话模式不支持刷新令牌")
	}
	if refreshToken == "" {
		return Tokens{}, ErrUnauthenticated
	}
	id, secret, err := decodeToken(r.opt.TokenPrefix, kindRefresh, refreshToken)
	if err != nil {
		return Tokens{}, err
	}
	h := hashSecret(secret)
	for range saveRetries {
		s, err := r.store.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return Tokens{}, ErrInvalidToken
		}
		if err != nil {
			return Tokens{}, err
		}
		current, prev := sameHash(h, s.RefreshHash), sameHash(h, s.PrevRefreshHash)
		if !current && !prev {
			return Tokens{}, ErrInvalidToken
		}
		if s.Revoked() {
			return Tokens{}, s.RevokeReason.Err()
		}
		now := r.now()
		cfg := r.config()
		if r.expired(s, cfg, now) {
			return Tokens{}, ErrExpired
		}
		if r.perms != nil {
			g, err := r.perms.get(ctx, s.Subject, false)
			if err != nil {
				return Tokens{}, err
			}
			if g.Disabled {
				return Tokens{}, ErrDisabled
			}
		}
		access, refresh := deriveRotation(s.RotateSalt, secret)
		if prev {
			if now.Sub(s.RotatedAt) <= r.opt.RefreshGrace {
				return r.tokens(s, cfg, access, refresh), nil
			}
			if err := r.revoke(ctx, s.ID, ReasonReused, EventRefreshReused); err != nil {
				return Tokens{}, err
			}
			return Tokens{}, ErrReused
		}
		c := s.Clone()
		c.PrevRefreshHash, c.RefreshHash = s.RefreshHash, hashSecret(refresh)
		c.PrevTokenHash, c.PrevTokenUntil = s.TokenHash, s.RotatedAt.Add(r.opt.AccessTTL)
		c.TokenHash, c.RotatedAt, c.LastSeenAt = hashSecret(access), now, now
		c.Gen = s.Gen + 1
		err = r.store.Save(ctx, c, s.Gen)
		if errors.Is(err, ErrConflict) {
			continue // 并发刷新：重新读取后按“上一个刷新令牌”处理
		}
		if errors.Is(err, ErrNotFound) {
			return Tokens{}, ErrInvalidToken
		}
		if err != nil {
			return Tokens{}, err
		}
		return r.tokens(c, cfg, access, refresh), nil
	}
	return Tokens{}, ErrConflict
}

// Logout 退出指定会话。会话不存在或已吊销时不报错。
func (r *Realm) Logout(ctx context.Context, sessionID string) error {
	return r.revoke(ctx, sessionID, ReasonLogout, EventLogout)
}

// KickoutSession 强制下线指定会话。该会话的后续请求返回 ErrKicked。
func (r *Realm) KickoutSession(ctx context.Context, sessionID string) error {
	return r.revoke(ctx, sessionID, ReasonKicked, EventKicked)
}

// Kickout 强制下线账号除 exceptSessionID 外的全部会话（停用账号时传空；改密时传当前会话以保留本机），
// 并清除该账号的权限缓存。
func (r *Realm) Kickout(ctx context.Context, subject, exceptSessionID string) error {
	now := r.now()
	n, err := r.store.RevokeSubject(ctx, subject, exceptSessionID, ReasonKicked, now)
	if r.perms != nil {
		r.perms.invalidate(subject)
	}
	if err != nil {
		return err
	}
	if n > 0 {
		r.emit(ctx, Event{Type: EventKicked, Subject: subject, At: now})
	}
	return nil
}

func (r *Realm) revoke(ctx context.Context, id string, reason Reason, ev EventType) error {
	for range saveRetries {
		s, err := r.store.Get(ctx, id)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if s.Revoked() {
			return nil
		}
		now := r.now()
		c := s.Clone()
		c.RevokedAt, c.RevokeReason, c.Gen = now, reason, s.Gen+1
		err = r.store.Save(ctx, c, s.Gen)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		r.emit(ctx, Event{Type: ev, Subject: s.Subject, SessionID: s.ID, Device: s.Device, IP: s.IP, At: now})
		return nil
	}
	return ErrConflict
}

// Sessions 返回账号当前有效的会话（未吊销、未超时），按登录时间升序。
func (r *Realm) Sessions(ctx context.Context, subject string) ([]*Session, error) {
	all, err := r.store.List(ctx, subject)
	if err != nil {
		return nil, err
	}
	now, cfg := r.now(), r.config()
	out := all[:0]
	for _, s := range all {
		if !s.Revoked() && !r.expired(s, cfg, now) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Elevate 记录二次验证（使用方已让用户重新输入密码等）。
// 会话模式下同时轮换会话令牌（旧令牌在宽限期内仍有效），返回的新令牌须写回客户端（如 SetCookie）；
// 双 token 模式下只记录时间，返回的 Tokens 只有 SessionID。
func (r *Realm) Elevate(ctx context.Context, sessionID string) (Tokens, error) {
	for range saveRetries {
		s, err := r.store.Get(ctx, sessionID)
		if errors.Is(err, ErrNotFound) {
			return Tokens{}, ErrInvalidToken
		}
		if err != nil {
			return Tokens{}, err
		}
		if s.Revoked() {
			return Tokens{}, s.RevokeReason.Err()
		}
		now, cfg := r.now(), r.config()
		if r.expired(s, cfg, now) {
			return Tokens{}, ErrExpired
		}
		c := s.Clone()
		c.ElevatedAt, c.Gen = now, s.Gen+1
		var access []byte
		if r.opt.Mode == ModeSession {
			if access, err = newSecret(r.opt.Rand); err != nil {
				return Tokens{}, err
			}
			c.PrevTokenHash, c.PrevTokenUntil = s.TokenHash, now.Add(r.opt.RefreshGrace)
			c.TokenHash, c.RotatedAt = hashSecret(access), now
		}
		err = r.store.Save(ctx, c, s.Gen)
		if errors.Is(err, ErrConflict) {
			continue
		}
		if err != nil {
			return Tokens{}, err
		}
		r.emit(ctx, Event{Type: EventElevated, Subject: s.Subject, SessionID: s.ID, Device: s.Device, IP: s.IP, At: now})
		if access == nil {
			return Tokens{SessionID: s.ID}, nil
		}
		return r.tokens(c, cfg, access, nil), nil
	}
	return Tokens{}, ErrConflict
}

// Elevated 报告会话的二次验证是否仍在有效期内。
func (r *Realm) Elevated(s *Session) bool {
	return s != nil && !s.ElevatedAt.IsZero() && r.now().Sub(s.ElevatedAt) <= r.opt.ElevateTTL
}

// Can 判断账号是否拥有权限 perm（具体权限码）。未配置 Permissions 时返回错误。
func (r *Realm) Can(ctx context.Context, subject, perm string) (bool, error) {
	if r.perms == nil {
		return false, errors.New("auth: 未配置 Permissions")
	}
	if !ValidPermission(perm) {
		return false, fmt.Errorf("auth: 权限码 %q 不合法", perm)
	}
	g, err := r.perms.get(ctx, subject, false)
	if err != nil {
		return false, err
	}
	if g.Disabled {
		return false, ErrDisabled
	}
	return Match(g.Permissions, perm), nil
}

// Authorize 与 Can 相同，但没有权限时返回 ErrForbidden。
func (r *Realm) Authorize(ctx context.Context, s *Session, perm string) error {
	if s == nil {
		return ErrUnauthenticated
	}
	ok, err := r.Can(ctx, s.Subject, perm)
	if err != nil {
		return err
	}
	if !ok {
		return ErrForbidden
	}
	return nil
}

// InvalidatePermissions 清除本进程中该账号的权限缓存（改角色后调用；多节点由使用方广播）。
func (r *Realm) InvalidatePermissions(subject string) {
	if r.perms != nil {
		r.perms.invalidate(subject)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// 按字节截断，不切断多字节字符。
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
