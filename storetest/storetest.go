// Package storetest 是 auth.Store 的一致性测试套件。
//
// 任何 Store 实现（包括使用方自己写的数据库实现）都应在测试中调用 Run：
//
//	func TestStore(t *testing.T) {
//		storetest.Run(t, func(t *testing.T) auth.Store { return newCleanStore(t) })
//	}
//
// newStore 每次调用都必须返回一个空的存储（或与其他子测试数据隔离的存储）。
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	auth "github.com/ZhcChen/cc-auth-go"
)

// t0 是测试基准时间（UTC，微秒精度）。
var t0 = time.Date(2026, 1, 2, 3, 4, 5, 678901000, time.UTC)

// Options 调整测试数据，使其适配有约束的存储（如会话 ID、账号 ID 为 BIGINT 的数据库表）。
type Options struct {
	// ID 把测试中的会话名（如 "s1"、"a"）映射为会话 ID；nil 表示原样使用。映射须保持字典序且一一对应。
	ID func(name string) string
	// Subject 把测试中的账号名（如 "u1"）映射为账号 ID；nil 表示原样使用。
	Subject func(name string) string
}

// Numeric 把名字映射为定长十进制数字串（保持字典序，最多 15 位），适用于以 BIGINT 为主键的存储。
func Numeric() Options {
	return Options{ID: numeric, Subject: numeric}
}

// numeric：首位 1，之后每个字符两位（0-9 → 10-19，a-z → 20-45，其他 → 46），右侧用 00 补齐到 7 个字符；
// 补齐值 00 小于任何字符编码，所以字典序与原名一致。
func numeric(name string) string {
	const width = 7
	if len(name) > width {
		panic("storetest: 名字过长：" + name)
	}
	b := []byte{'1'}
	for i := 0; i < width; i++ {
		code := 0
		if i < len(name) {
			switch c := name[i]; {
			case c >= '0' && c <= '9':
				code = 10 + int(c-'0')
			case c >= 'a' && c <= 'z':
				code = 20 + int(c-'a')
			default:
				code = 46
			}
		}
		b = append(b, byte('0'+code/10), byte('0'+code%10))
	}
	return string(b)
}

type suite struct {
	st  auth.Store
	opt Options
}

func (s *suite) id(name string) string {
	if s.opt.ID == nil {
		return name
	}
	return s.opt.ID(name)
}

func (s *suite) sub(name string) string {
	if s.opt.Subject == nil {
		return name
	}
	return s.opt.Subject(name)
}

func (s *suite) ids(names ...string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, s.id(n))
	}
	return out
}

// Run 运行全部一致性测试（会话 ID 与账号 ID 原样使用测试中的名字）。
func Run(t *testing.T, newStore func(t *testing.T) auth.Store) {
	RunWith(t, newStore, Options{})
}

// RunWith 按 opt 映射测试数据后运行全部一致性测试。
func RunWith(t *testing.T, newStore func(t *testing.T) auth.Store, opt Options) {
	tests := []struct {
		name string
		fn   func(t *testing.T, s *suite)
	}{
		{"CreateGet", testCreateGet},
		{"GetNotFound", testGetNotFound},
		{"CreateDuplicate", testCreateDuplicate},
		{"SaveCompareAndSet", testSave},
		{"TouchConditional", testTouch},
		{"List", testList},
		{"RevokeSubject", testRevokeSubject},
		{"LimitPerDevice", testLimitPerDevice},
		{"LimitTotal", testLimitTotal},
		{"LimitIgnoresInactive", testLimitIgnoresInactive},
		{"LimitDeviceThenTotal", testLimitDeviceThenTotal},
		{"ConcurrentCreateRespectsLimit", testConcurrentCreate},
		{"DeleteExpired", testDeleteExpired},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { tc.fn(t, &suite{st: newStore(t), opt: opt}) })
	}
}

func hash(seed string) []byte {
	b := make([]byte, 32)
	copy(b, seed)
	return b
}

func (su *suite) newSession(id, subject, device string, created time.Time) *auth.Session {
	return &auth.Session{
		ID: su.id(id), Subject: su.sub(subject), Device: device, IP: "203.0.113.7", UA: "storetest/1.0",
		CreatedAt: created, LastSeenAt: created, TokenHash: hash("token-" + id), RotatedAt: created, Gen: 1,
	}
}

func mustCreate(t *testing.T, st auth.Store, s *auth.Session, lim auth.Limits) []string {
	t.Helper()
	ev, err := st.Create(context.Background(), s, lim)
	if err != nil {
		t.Fatalf("Create(%s)：%v", s.ID, err)
	}
	return ev
}

func mustGet(t *testing.T, st auth.Store, id string) *auth.Session {
	t.Helper()
	s, err := st.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s)：%v", id, err)
	}
	return s
}

// noLimit 不限数量，过期截止时间取很早的时刻。
var noLimit = auth.Limits{IdleCutoff: t0.Add(-24 * time.Hour), AbsoluteCutoff: t0.Add(-24 * time.Hour)}

func equalSession(t *testing.T, want, got *auth.Session) {
	t.Helper()
	diff := func(field string, w, g any) { t.Errorf("%s：期望 %v，实际 %v", field, w, g) }
	if want.ID != got.ID || want.Subject != got.Subject || want.Device != got.Device || want.IP != got.IP || want.UA != got.UA {
		diff("文本字段", fmt.Sprintf("%s/%s/%s/%s/%s", want.ID, want.Subject, want.Device, want.IP, want.UA),
			fmt.Sprintf("%s/%s/%s/%s/%s", got.ID, got.Subject, got.Device, got.IP, got.UA))
	}
	times := []struct {
		name string
		w, g time.Time
	}{
		{"CreatedAt", want.CreatedAt, got.CreatedAt}, {"LastSeenAt", want.LastSeenAt, got.LastSeenAt},
		{"ElevatedAt", want.ElevatedAt, got.ElevatedAt}, {"PrevTokenUntil", want.PrevTokenUntil, got.PrevTokenUntil},
		{"RotatedAt", want.RotatedAt, got.RotatedAt}, {"RevokedAt", want.RevokedAt, got.RevokedAt},
	}
	for _, x := range times {
		if !x.w.Equal(x.g) {
			diff(x.name, x.w, x.g)
		}
	}
	bs := []struct {
		name string
		w, g []byte
	}{
		{"TokenHash", want.TokenHash, got.TokenHash}, {"PrevTokenHash", want.PrevTokenHash, got.PrevTokenHash},
		{"RefreshHash", want.RefreshHash, got.RefreshHash}, {"PrevRefreshHash", want.PrevRefreshHash, got.PrevRefreshHash},
		{"RotateSalt", want.RotateSalt, got.RotateSalt},
	}
	for _, x := range bs {
		if !bytes.Equal(x.w, x.g) {
			diff(x.name, x.w, x.g)
		}
	}
	if want.RevokeReason != got.RevokeReason {
		diff("RevokeReason", want.RevokeReason, got.RevokeReason)
	}
	if want.Gen != got.Gen {
		diff("Gen", want.Gen, got.Gen)
	}
}

func testCreateGet(t *testing.T, su *suite) {
	st := su.st
	s := su.newSession("s1", "u1", "web", t0)
	s.ElevatedAt = t0.Add(time.Second)
	s.PrevTokenHash, s.PrevTokenUntil = hash("prev"), t0.Add(10*time.Second)
	s.RefreshHash, s.PrevRefreshHash, s.RotateSalt = hash("refresh"), hash("prev-refresh"), hash("salt")
	if ev := mustCreate(t, st, s, noLimit); len(ev) != 0 {
		t.Fatalf("不限数量时不应淘汰：%v", ev)
	}
	got := mustGet(t, st, su.id("s1"))
	equalSession(t, s, got)
	if got.Revoked() {
		t.Error("新会话不应是已吊销")
	}
	got.TokenHash[0] ^= 0xFF // 返回值归调用方所有，修改不得影响存储
	equalSession(t, s, mustGet(t, st, su.id("s1")))
}

func testGetNotFound(t *testing.T, su *suite) {
	st := su.st
	if _, err := st.Get(context.Background(), su.id("missing")); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("期望 ErrNotFound，实际 %v", err)
	}
}

func testCreateDuplicate(t *testing.T, su *suite) {
	st := su.st
	mustCreate(t, st, su.newSession("s1", "u1", "web", t0), noLimit)
	if _, err := st.Create(context.Background(), su.newSession("s1", "u2", "web", t0), noLimit); !errors.Is(err, auth.ErrConflict) {
		t.Fatalf("重复 ID 期望 ErrConflict，实际 %v", err)
	}
}

func testSave(t *testing.T, su *suite) {
	st := su.st
	ctx := context.Background()
	mustCreate(t, st, su.newSession("s1", "u1", "web", t0), noLimit)
	c := mustGet(t, st, su.id("s1"))
	c.TokenHash, c.ElevatedAt, c.Gen = hash("new"), t0.Add(time.Minute), 2
	if err := st.Save(ctx, c, 1); err != nil {
		t.Fatalf("Save：%v", err)
	}
	equalSession(t, c, mustGet(t, st, su.id("s1")))

	stale := c.Clone()
	stale.TokenHash, stale.Gen = hash("stale"), 2
	if err := st.Save(ctx, stale, 1); !errors.Is(err, auth.ErrConflict) {
		t.Fatalf("版本不符期望 ErrConflict，实际 %v", err)
	}
	equalSession(t, c, mustGet(t, st, su.id("s1")))

	missing := su.newSession("nope", "u1", "web", t0)
	if err := st.Save(ctx, missing, 1); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("不存在期望 ErrNotFound，实际 %v", err)
	}
}

func testTouch(t *testing.T, su *suite) {
	st := su.st
	ctx := context.Background()
	mustCreate(t, st, su.newSession("s1", "u1", "web", t0), noLimit)
	if err := st.Touch(ctx, su.id("s1"), t0.Add(2*time.Minute), t0.Add(time.Minute)); err != nil {
		t.Fatalf("Touch：%v", err)
	}
	got := mustGet(t, st, su.id("s1"))
	if !got.LastSeenAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("满足条件时应更新 LastSeenAt：%v", got.LastSeenAt)
	}
	if got.Gen != 1 {
		t.Errorf("Touch 不应改变 Gen：%d", got.Gen)
	}
	if err := st.Touch(ctx, su.id("s1"), t0.Add(3*time.Minute), t0.Add(time.Minute)); err != nil {
		t.Fatalf("条件不满足时不应报错：%v", err)
	}
	if got := mustGet(t, st, su.id("s1")); !got.LastSeenAt.Equal(t0.Add(2 * time.Minute)) {
		t.Fatalf("条件不满足时不应更新：%v", got.LastSeenAt)
	}
	if err := st.Touch(ctx, su.id("nope"), t0, t0); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("不存在期望 ErrNotFound，实际 %v", err)
	}
}

func testList(t *testing.T, su *suite) {
	st := su.st
	ctx := context.Background()
	mustCreate(t, st, su.newSession("b", "u1", "web", t0.Add(time.Second)), noLimit)
	mustCreate(t, st, su.newSession("a", "u1", "app", t0.Add(time.Second)), noLimit)
	mustCreate(t, st, su.newSession("c", "u1", "web", t0), noLimit)
	mustCreate(t, st, su.newSession("x", "u2", "web", t0), noLimit)
	if _, err := st.RevokeSubject(ctx, su.sub("u1"), su.id("a"), auth.ReasonKicked, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	list, err := st.List(ctx, su.sub("u1"))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, s := range list {
		ids = append(ids, s.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint(su.ids("c", "a", "b")) {
		t.Fatalf("应按登录时间、ID 升序且包含已吊销会话：%v", ids)
	}
	if empty, err := st.List(ctx, su.sub("nobody")); err != nil || len(empty) != 0 {
		t.Fatalf("无会话的账号应返回空：%v %v", empty, err)
	}
}

func testRevokeSubject(t *testing.T, su *suite) {
	st := su.st
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		mustCreate(t, st, su.newSession(id, "u1", "web", t0), noLimit)
	}
	mustCreate(t, st, su.newSession("x", "u2", "web", t0), noLimit)
	at := t0.Add(time.Hour)
	n, err := st.RevokeSubject(ctx, su.sub("u1"), su.id("b"), auth.ReasonKicked, at)
	if err != nil || n != 2 {
		t.Fatalf("应吊销 2 个：%d %v", n, err)
	}
	for _, id := range []string{"a", "c"} {
		s := mustGet(t, st, su.id(id))
		if !s.RevokedAt.Equal(at) || s.RevokeReason != auth.ReasonKicked || s.Gen != 2 {
			t.Errorf("%s：吊销字段不对 %v %s %d", id, s.RevokedAt, s.RevokeReason, s.Gen)
		}
	}
	if mustGet(t, st, su.id("b")).Revoked() || mustGet(t, st, su.id("x")).Revoked() {
		t.Error("排除的会话与其他账号的会话不应被吊销")
	}
	if n, err := st.RevokeSubject(ctx, su.sub("u1"), "", auth.ReasonLogout, at.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("已吊销的不应重复计数：%d %v", n, err)
	}
	if s := mustGet(t, st, su.id("a")); s.RevokeReason != auth.ReasonKicked || s.Gen != 2 {
		t.Error("已吊销的会话不应被改写")
	}
}

func limits(perDevice, total int) auth.Limits {
	l := noLimit
	l.MaxPerDevice, l.MaxTotal = perDevice, total
	return l
}

func expectEvicted(t *testing.T, su *suite, got []string, want ...string) {
	t.Helper()
	if want = su.ids(want...); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("淘汰：期望 %v，实际 %v", want, got)
	}
}

func expectReplaced(t *testing.T, su *suite, id string, at time.Time) {
	t.Helper()
	s := mustGet(t, su.st, su.id(id))
	if s.RevokeReason != auth.ReasonReplaced || !s.RevokedAt.Equal(at) || s.Gen != 2 {
		t.Fatalf("%s 应被吊销为 replaced（时间 %v，Gen 2），实际 %s %v %d", id, at, s.RevokeReason, s.RevokedAt, s.Gen)
	}
}

func testLimitPerDevice(t *testing.T, su *suite) {
	st := su.st
	mustCreate(t, st, su.newSession("a", "u1", "web", t0), limits(2, 0))
	mustCreate(t, st, su.newSession("b", "u1", "web", t0.Add(time.Second)), limits(2, 0))
	mustCreate(t, st, su.newSession("m", "u1", "app", t0.Add(2*time.Second)), limits(2, 0))
	c := su.newSession("c", "u1", "web", t0.Add(3*time.Second))
	expectEvicted(t, su, mustCreate(t, st, c, limits(2, 0)), "a")
	expectReplaced(t, su, "a", c.CreatedAt)
	if mustGet(t, st, su.id("b")).Revoked() || mustGet(t, st, su.id("m")).Revoked() || mustGet(t, st, su.id("c")).Revoked() {
		t.Error("只应淘汰同设备最早的一个")
	}
}

func testLimitTotal(t *testing.T, su *suite) {
	st := su.st
	mustCreate(t, st, su.newSession("a", "u1", "web", t0), noLimit)
	mustCreate(t, st, su.newSession("b", "u1", "app", t0.Add(time.Second)), noLimit)
	mustCreate(t, st, su.newSession("c", "u1", "h5", t0.Add(2*time.Second)), noLimit)
	mustCreate(t, st, su.newSession("o", "u2", "web", t0), noLimit)
	d := su.newSession("d", "u1", "mp", t0.Add(3*time.Second))
	expectEvicted(t, su, mustCreate(t, st, d, limits(0, 2)), "a", "b")
	expectReplaced(t, su, "a", d.CreatedAt)
	expectReplaced(t, su, "b", d.CreatedAt)
	if mustGet(t, st, su.id("o")).Revoked() {
		t.Error("不应影响其他账号")
	}
}

func testLimitIgnoresInactive(t *testing.T, su *suite) {
	st := su.st
	ctx := context.Background()
	lim := limits(1, 0)
	lim.IdleCutoff, lim.AbsoluteCutoff = t0.Add(time.Hour), t0.Add(-time.Hour)

	idle := su.newSession("idle", "u1", "web", t0) // LastSeenAt 早于 IdleCutoff
	mustCreate(t, st, idle, noLimit)
	old := su.newSession("old", "u1", "web", t0.Add(-2*time.Hour)) // CreatedAt 早于 AbsoluteCutoff
	old.LastSeenAt = t0.Add(2 * time.Hour)
	mustCreate(t, st, old, noLimit)
	gone := su.newSession("gone", "u1", "web", t0.Add(2*time.Hour))
	mustCreate(t, st, gone, noLimit)
	if _, err := st.RevokeSubject(ctx, su.sub("u1"), su.id("idle"), auth.ReasonLogout, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// 此时 idle 未吊销但已空闲过期，old 已绝对过期且被吊销，gone 已吊销：都不计入。
	expectEvicted(t, su, mustCreate(t, st, su.newSession("new", "u1", "web", t0.Add(3*time.Hour)), lim))
	if mustGet(t, st, su.id("idle")).Revoked() {
		t.Error("已过期的会话不计入上限，也不应被淘汰")
	}
}

func testLimitDeviceThenTotal(t *testing.T, su *suite) {
	st := su.st
	mustCreate(t, st, su.newSession("w1", "u1", "web", t0), noLimit)
	mustCreate(t, st, su.newSession("a1", "u1", "app", t0.Add(time.Second)), noLimit)
	mustCreate(t, st, su.newSession("w2", "u1", "web", t0.Add(2*time.Second)), noLimit)
	w3 := su.newSession("w3", "u1", "web", t0.Add(3*time.Second))
	// 设备上限 2：淘汰 w1；随后总数上限 2：剩 a1、w2、w3，再淘汰 a1。
	expectEvicted(t, su, mustCreate(t, st, w3, limits(2, 2)), "w1", "a1")
}

func testConcurrentCreate(t *testing.T, su *suite) {
	st := su.st
	const n, limit = 20, 3
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := su.newSession(fmt.Sprintf("s%02d", i), "u1", "web", t0.Add(time.Duration(i)*time.Millisecond))
			if _, err := st.Create(context.Background(), s, limits(limit, 0)); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("并发创建：%v", err)
	}
	list, err := st.List(context.Background(), su.sub("u1"))
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	for _, s := range list {
		if !s.Revoked() {
			live++
		}
	}
	if len(list) != n || live != limit {
		t.Fatalf("并发创建后应共 %d 个、有效 %d 个，实际共 %d 个、有效 %d 个", n, limit, len(list), live)
	}
}

func testDeleteExpired(t *testing.T, su *suite) {
	st := su.st
	sw, ok := st.(auth.Sweeper)
	if !ok {
		t.Skip("未实现 auth.Sweeper")
	}
	ctx := context.Background()
	mustCreate(t, st, su.newSession("old", "u1", "web", t0.Add(-48*time.Hour)), noLimit)
	idle := su.newSession("idle", "u1", "web", t0.Add(-time.Hour))
	idle.LastSeenAt = t0.Add(-time.Hour)
	mustCreate(t, st, idle, noLimit)
	mustCreate(t, st, su.newSession("live", "u1", "web", t0), noLimit)
	n, err := sw.DeleteExpired(ctx, t0.Add(-24*time.Hour), t0.Add(-30*time.Minute))
	if err != nil || n != 2 {
		t.Fatalf("应删除 2 个：%d %v", n, err)
	}
	if _, err := st.Get(ctx, su.id("old")); !errors.Is(err, auth.ErrNotFound) {
		t.Error("绝对过期的应被删除")
	}
	mustGet(t, st, su.id("live"))
}
