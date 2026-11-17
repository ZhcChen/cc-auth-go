package auth_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth "github.com/ZhcChen/cc-auth-go"
	"github.com/ZhcChen/cc-auth-go/memstore"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 3, 1, 8, 0, 0, 0, time.UTC)} }

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recorder struct {
	mu     sync.Mutex
	events []auth.Event
}

func (r *recorder) OnEvent(_ context.Context, e auth.Event) {
	r.mu.Lock()
	r.events = append(r.events, e)
	r.mu.Unlock()
}

func (r *recorder) types() []auth.EventType {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []auth.EventType
	for _, e := range r.events {
		out = append(out, e.Type)
	}
	return out
}

type grants struct {
	mu    sync.Mutex
	m     map[string]auth.Grants
	loads atomic.Int32
}

func (g *grants) Load(_ context.Context, subject string) (auth.Grants, error) {
	g.loads.Add(1)
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.m[subject], nil
}

func (g *grants) set(subject string, v auth.Grants) {
	g.mu.Lock()
	g.m[subject] = v
	g.mu.Unlock()
}

type env struct {
	realm *auth.Realm
	store *memstore.Store
	clock *clock
	cfg   *atomic.Pointer[auth.Config]
	ev    *recorder
	perms *grants
}

func newEnv(t *testing.T, mutate func(*auth.Options)) *env {
	t.Helper()
	e := &env{store: memstore.New(), clock: newClock(), cfg: &atomic.Pointer[auth.Config]{}, ev: &recorder{},
		perms: &grants{m: map[string]auth.Grants{"u1": {Permissions: []string{"config:*", "*:read"}}}}}
	e.cfg.Store(&auth.Config{})
	var seq atomic.Int64
	opt := auth.Options{
		Config:      func() auth.Config { return *e.cfg.Load() },
		Permissions: e.perms,
		Listener:    e.ev,
		Devices:     []string{"web", "app"},
		Now:         e.clock.Now,
		NewID: func(context.Context) (string, error) {
			return strconv.FormatInt(1000+seq.Add(1), 10), nil
		},
	}
	if mutate != nil {
		mutate(&opt)
	}
	r, err := auth.New("worker", e.store, opt)
	if err != nil {
		t.Fatal(err)
	}
	e.realm = r
	return e
}

func (e *env) login(t *testing.T, subject string, info auth.LoginInfo) auth.Tokens {
	t.Helper()
	tok, err := e.realm.Login(context.Background(), subject, info)
	if err != nil {
		t.Fatalf("Login：%v", err)
	}
	return tok
}

func expectErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("期望 %v，实际 %v", want, err)
	}
}

func TestNewValidates(t *testing.T) {
	st := memstore.New()
	bad := []struct {
		name string
		opt  auth.Options
	}{
		{"Worker", auth.Options{}},
		{"worker", auth.Options{Devices: []string{"Web"}}},
		{"worker", auth.Options{AllowedOrigins: []string{"https://a.example.com/path"}}},
		{"worker", auth.Options{Mode: auth.ModeRefresh, Transport: auth.TransportCookie}},
		{"worker", auth.Options{Mode: 9}},
	}
	for _, b := range bad {
		if _, err := auth.New(b.name, st, b.opt); err == nil {
			t.Errorf("New(%q, %+v) 应报错", b.name, b.opt)
		}
	}
	if _, err := auth.New("worker", nil, auth.Options{}); err == nil {
		t.Error("Store 为空应报错")
	}
	if _, err := auth.New("worker", st, auth.Options{}); err != nil {
		t.Errorf("零值 Options 应可用：%v", err)
	}
}

func TestLoginVerifyLogout(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{IP: "198.51.100.1", UA: "test"})
	if tok.Refresh != "" {
		t.Error("会话模式不应签发刷新令牌")
	}
	s, err := e.realm.Verify(ctx, tok.Token)
	if err != nil {
		t.Fatal(err)
	}
	if s.Subject != "u1" || s.Device != "web" || s.IP != "198.51.100.1" || s.ID != tok.SessionID {
		t.Fatalf("会话信息不对：%+v", s)
	}
	if want := e.clock.Now().Add(auth.DefaultAbsoluteTimeout); !tok.TokenExpiresAt.Equal(want) {
		t.Errorf("会话令牌最晚失效时间应为绝对超时：%v", tok.TokenExpiresAt)
	}
	if err := e.realm.Logout(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	_, err = e.realm.Verify(ctx, tok.Token)
	expectErr(t, err, auth.ErrLoggedOut)
	if got := e.ev.types(); len(got) != 2 || got[0] != auth.EventLogin || got[1] != auth.EventLogout {
		t.Errorf("事件：%v", got)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})
	_, err := e.realm.Verify(ctx, "")
	expectErr(t, err, auth.ErrUnauthenticated)
	_, err = e.realm.Verify(ctx, "worker_garbage")
	expectErr(t, err, auth.ErrInvalidToken)
	// 换一个随机部分：会话 ID 正确但凭据不符。
	other := newEnv(t, nil).login(t, "u1", auth.LoginInfo{})
	if other.SessionID != tok.SessionID {
		t.Fatalf("测试前提：两个环境的会话 ID 应相同")
	}
	_, err = e.realm.Verify(ctx, other.Token)
	expectErr(t, err, auth.ErrInvalidToken)
}

func TestIdleAndAbsoluteTimeout(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})

	// 每 20 分钟活跃一次，空闲不超时；满 12 小时仍有效（超过才失效），之后必须重新登录。
	for range 36 {
		e.clock.Add(20 * time.Minute)
		if _, err := e.realm.Verify(ctx, tok.Token); err != nil {
			t.Fatalf("活跃期间不应过期：%v", err)
		}
	}
	e.clock.Add(20 * time.Minute) // 累计 12 小时 20 分钟
	_, err := e.realm.Verify(ctx, tok.Token)
	expectErr(t, err, auth.ErrExpired)

	tok2 := e.login(t, "u1", auth.LoginInfo{})
	e.clock.Add(31 * time.Minute)
	_, err = e.realm.Verify(ctx, tok2.Token)
	expectErr(t, err, auth.ErrExpired)
}

func TestShorterConfigAppliesImmediately(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.login(t, "u1", auth.LoginInfo{})
	e.clock.Add(10 * time.Minute)
	if _, err := e.realm.Verify(context.Background(), tok.Token); err != nil {
		t.Fatal(err)
	}
	e.cfg.Store(&auth.Config{AbsoluteTimeout: 5 * time.Minute})
	_, err := e.realm.Verify(context.Background(), tok.Token)
	expectErr(t, err, auth.ErrExpired)
}

func TestTouchIsThrottled(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})
	created := e.clock.Now()
	e.clock.Add(30 * time.Second)
	s, _ := e.realm.Verify(ctx, tok.Token)
	if !s.LastSeenAt.Equal(created) {
		t.Error("间隔不足 1 分钟不应写入最后活跃时间")
	}
	e.clock.Add(31 * time.Second)
	s, _ = e.realm.Verify(ctx, tok.Token)
	stored, _ := e.store.Get(ctx, s.ID)
	if !s.LastSeenAt.Equal(e.clock.Now()) || !stored.LastSeenAt.Equal(e.clock.Now()) {
		t.Errorf("超过 1 分钟应写入：%v %v", s.LastSeenAt, stored.LastSeenAt)
	}
}

func TestMaxSessionsReplacesOldest(t *testing.T) {
	e := newEnv(t, nil)
	e.cfg.Store(&auth.Config{MaxSessionsPerDevice: 1})
	ctx := context.Background()
	first := e.login(t, "u1", auth.LoginInfo{Device: "web"})
	e.clock.Add(time.Second)
	app := e.login(t, "u1", auth.LoginInfo{Device: "app"})
	e.clock.Add(time.Second)
	second := e.login(t, "u1", auth.LoginInfo{Device: "web"})
	_, err := e.realm.Verify(ctx, first.Token)
	expectErr(t, err, auth.ErrReplaced)
	for _, tok := range []auth.Tokens{app, second} {
		if _, err := e.realm.Verify(ctx, tok.Token); err != nil {
			t.Fatalf("其他设备与新会话应有效：%v", err)
		}
	}
	if got := e.ev.types(); got[len(got)-1] != auth.EventReplaced {
		t.Errorf("应发出被顶替事件：%v", got)
	}
}

func TestKickout(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	a := e.login(t, "u1", auth.LoginInfo{})
	b := e.login(t, "u1", auth.LoginInfo{})
	c := e.login(t, "u1", auth.LoginInfo{})
	if err := e.realm.KickoutSession(ctx, a.SessionID); err != nil {
		t.Fatal(err)
	}
	_, err := e.realm.Verify(ctx, a.Token)
	expectErr(t, err, auth.ErrKicked)
	if err := e.realm.Kickout(ctx, "u1", c.SessionID); err != nil {
		t.Fatal(err)
	}
	_, err = e.realm.Verify(ctx, b.Token)
	expectErr(t, err, auth.ErrKicked)
	if _, err := e.realm.Verify(ctx, c.Token); err != nil {
		t.Fatalf("改密时保留的当前会话应有效：%v", err)
	}
	live, _ := e.realm.Sessions(ctx, "u1")
	if len(live) != 1 || live[0].ID != c.SessionID {
		t.Fatalf("在线会话：%v", live)
	}
}

func TestLoginReplacesCarriedSession(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	old := e.login(t, "u1", auth.LoginInfo{})
	e.login(t, "u1", auth.LoginInfo{Replace: old.Token})
	_, err := e.realm.Verify(ctx, old.Token)
	expectErr(t, err, auth.ErrLoggedOut)
	// 伪造的旧令牌不影响登录。
	e.login(t, "u1", auth.LoginInfo{Replace: "worker_forged"})
}

func TestDisabledAccount(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})
	e.perms.set("u1", auth.Grants{Disabled: true})
	// 权限缓存未过期时仍放行；失效后拒绝。
	if _, err := e.realm.Verify(ctx, tok.Token); err != nil {
		t.Fatalf("缓存期内：%v", err)
	}
	e.realm.InvalidatePermissions("u1")
	_, err := e.realm.Verify(ctx, tok.Token)
	expectErr(t, err, auth.ErrDisabled)
	_, err = e.realm.Login(ctx, "u1", auth.LoginInfo{})
	expectErr(t, err, auth.ErrDisabled)
}

func TestDeviceWhitelist(t *testing.T) {
	e := newEnv(t, nil)
	_, err := e.realm.Login(context.Background(), "u1", auth.LoginInfo{Device: "tv"})
	expectErr(t, err, auth.ErrDevice)
}

func TestPermissionsAndCache(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})
	s, _ := e.realm.Verify(ctx, tok.Token)
	for perm, want := range map[string]bool{"config:write": true, "account:read": true, "account:write": false} {
		if ok, err := e.realm.Can(ctx, "u1", perm); err != nil || ok != want {
			t.Errorf("Can(%s) = %v %v，期望 %v", perm, ok, err, want)
		}
	}
	expectErr(t, e.realm.Authorize(ctx, s, "account:write"), auth.ErrForbidden)
	if _, err := e.realm.Can(ctx, "u1", "config:*"); err == nil {
		t.Error("需要的权限含通配应报错")
	}

	loads := e.perms.loads.Load()
	e.perms.set("u1", auth.Grants{Permissions: []string{"*"}})
	if ok, _ := e.realm.Can(ctx, "u1", "account:write"); ok {
		t.Error("缓存期内应使用旧权限")
	}
	e.clock.Add(auth.DefaultPermissionTTL)
	if ok, _ := e.realm.Can(ctx, "u1", "account:write"); !ok {
		t.Error("缓存过期后应重新加载")
	}
	if e.perms.loads.Load() != loads+1 {
		t.Errorf("应只重新加载一次：%d → %d", loads, e.perms.loads.Load())
	}
}

func TestElevate(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	tok := e.login(t, "u1", auth.LoginInfo{})
	s, _ := e.realm.Verify(ctx, tok.Token)
	if e.realm.Elevated(s) {
		t.Fatal("登录后不应处于二次验证状态")
	}
	nt, err := e.realm.Elevate(ctx, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	if nt.Token == "" || nt.Token == tok.Token {
		t.Fatal("会话模式下二次验证应轮换令牌")
	}
	s2, err := e.realm.Verify(ctx, nt.Token)
	if err != nil || !e.realm.Elevated(s2) {
		t.Fatalf("新令牌应有效且已二次验证：%v", err)
	}
	if _, err := e.realm.Verify(ctx, tok.Token); err != nil {
		t.Fatalf("旧令牌在宽限期内应有效：%v", err)
	}
	e.clock.Add(auth.DefaultRefreshGrace + time.Second)
	_, err = e.realm.Verify(ctx, tok.Token)
	expectErr(t, err, auth.ErrInvalidToken)
	e.clock.Add(auth.DefaultElevateTTL)
	s3, _ := e.realm.Verify(ctx, nt.Token)
	if e.realm.Elevated(s3) {
		t.Error("二次验证应过期")
	}
}

func TestListenerPanicIsIsolated(t *testing.T) {
	e := newEnv(t, func(o *auth.Options) {
		o.Listener = auth.ListenerFunc(func(context.Context, auth.Event) { panic("boom") })
	})
	e.login(t, "u1", auth.LoginInfo{})
}

func newRefreshEnv(t *testing.T) *env {
	return newEnv(t, func(o *auth.Options) { o.Mode = auth.ModeRefresh })
}

func TestRefreshRotation(t *testing.T) {
	e := newRefreshEnv(t)
	ctx := context.Background()
	t1 := e.login(t, "u1", auth.LoginInfo{})
	if t1.Refresh == "" || t1.Refresh == t1.Token {
		t.Fatal("双 token 模式应签发刷新令牌")
	}
	if want := e.clock.Now().Add(auth.DefaultAccessTTL); !t1.TokenExpiresAt.Equal(want) {
		t.Errorf("访问令牌有效期：%v", t1.TokenExpiresAt)
	}
	e.clock.Add(auth.DefaultAccessTTL)
	_, err := e.realm.Verify(ctx, t1.Token)
	expectErr(t, err, auth.ErrTokenExpired)

	t2, err := e.realm.Refresh(ctx, t1.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	if t2.Token == t1.Token || t2.Refresh == t1.Refresh {
		t.Fatal("刷新应轮换两个令牌")
	}
	if _, err := e.realm.Verify(ctx, t2.Token); err != nil {
		t.Fatalf("新访问令牌应有效：%v", err)
	}
	// 宽限期内重放旧刷新令牌：幂等返回同一组。
	again, err := e.realm.Refresh(ctx, t1.Refresh)
	if err != nil || again.Token != t2.Token || again.Refresh != t2.Refresh {
		t.Fatalf("宽限期内应幂等：%v", err)
	}
	// 新刷新令牌可继续轮换。
	e.clock.Add(time.Minute)
	t3, err := e.realm.Refresh(ctx, t2.Refresh)
	if err != nil {
		t.Fatal(err)
	}
	// 超出宽限期重放上一个刷新令牌：判定泄露，整个会话吊销。
	e.clock.Add(auth.DefaultRefreshGrace + time.Second)
	_, err = e.realm.Refresh(ctx, t2.Refresh)
	expectErr(t, err, auth.ErrReused)
	_, err = e.realm.Verify(ctx, t3.Token)
	expectErr(t, err, auth.ErrReused)
	_, err = e.realm.Refresh(ctx, t3.Refresh)
	expectErr(t, err, auth.ErrReused)
	if got := e.ev.types(); got[len(got)-1] != auth.EventRefreshReused {
		t.Errorf("应发出重放事件：%v", got)
	}
}

func TestRefreshKeepsInFlightAccessToken(t *testing.T) {
	e := newRefreshEnv(t)
	ctx := context.Background()
	t1 := e.login(t, "u1", auth.LoginInfo{})
	e.clock.Add(time.Minute)
	if _, err := e.realm.Refresh(ctx, t1.Refresh); err != nil {
		t.Fatal(err)
	}
	if _, err := e.realm.Verify(ctx, t1.Token); err != nil {
		t.Fatalf("刷新后旧访问令牌在自然过期前应有效：%v", err)
	}
	e.clock.Add(auth.DefaultAccessTTL)
	_, err := e.realm.Verify(ctx, t1.Token)
	expectErr(t, err, auth.ErrInvalidToken)
}

func TestRefreshConcurrent(t *testing.T) {
	e := newRefreshEnv(t)
	ctx := context.Background()
	t1 := e.login(t, "u1", auth.LoginInfo{})
	var wg sync.WaitGroup
	results := make([]auth.Tokens, 8)
	errs := make([]error, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = e.realm.Refresh(ctx, t1.Refresh)
		}()
	}
	wg.Wait()
	for i := range results {
		if errs[i] != nil {
			t.Fatalf("并发刷新不应失败：%v", errs[i])
		}
		if results[i].Refresh != results[0].Refresh {
			t.Fatal("并发刷新应得到同一组令牌")
		}
	}
}

func TestRefreshModeElevateKeepsTokens(t *testing.T) {
	e := newRefreshEnv(t)
	ctx := context.Background()
	t1 := e.login(t, "u1", auth.LoginInfo{})
	nt, err := e.realm.Elevate(ctx, t1.SessionID)
	if err != nil || nt.Token != "" {
		t.Fatalf("双 token 模式二次验证只记录时间：%+v %v", nt, err)
	}
	s, err := e.realm.Verify(ctx, t1.Token)
	if err != nil || !e.realm.Elevated(s) {
		t.Fatalf("原访问令牌应有效且已二次验证：%v", err)
	}
}

func TestSessionModeRejectsRefresh(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := e.realm.Refresh(context.Background(), "worker_rt_x"); err == nil {
		t.Fatal("会话模式不支持刷新")
	}
}

func BenchmarkVerify(b *testing.B) {
	st := memstore.New()
	r, err := auth.New("worker", st, auth.Options{})
	if err != nil {
		b.Fatal(err)
	}
	tok, err := r.Login(context.Background(), "u1", auth.LoginInfo{})
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := r.Verify(ctx, tok.Token); err != nil {
			b.Fatal(err)
		}
	}
}
