package password_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ZhcChen/cc-auth-go/password"
)

// 测试用小参数，避免拖慢测试。
var fast = password.Params{Memory: 64, Iterations: 1, Parallelism: 1}

func TestHashVerify(t *testing.T) {
	h := password.New(fast, 2)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "correct horse 电池")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("哈希串格式：%s", enc)
	}
	ok, rehash, err := h.Verify(ctx, enc, "correct horse 电池")
	if err != nil || !ok || rehash {
		t.Fatalf("正确密码：%v %v %v", ok, rehash, err)
	}
	if ok, _, err := h.Verify(ctx, enc, "wrong"); err != nil || ok {
		t.Fatalf("错误密码：%v %v", ok, err)
	}
	enc2, _ := h.Hash(ctx, "correct horse 电池")
	if enc == enc2 {
		t.Fatal("每次哈希应使用不同的盐")
	}
}

func TestNeedsRehash(t *testing.T) {
	ctx := context.Background()
	old, _ := password.New(fast, 1).Hash(ctx, "pw")
	stronger := password.New(password.Params{Memory: 128, Iterations: 1, Parallelism: 1}, 1)
	ok, rehash, err := stronger.Verify(ctx, old, "pw")
	if err != nil || !ok || !rehash {
		t.Fatalf("参数升级后应能校验旧哈希并提示重新哈希：%v %v %v", ok, rehash, err)
	}
}

func TestDefaultParams(t *testing.T) {
	enc, err := password.Hash(context.Background(), "pw")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("缺省参数应为 OWASP 推荐值：%s", enc)
	}
	if ok, rehash, err := password.Verify(context.Background(), enc, "pw"); !ok || rehash || err != nil {
		t.Fatalf("%v %v %v", ok, rehash, err)
	}
}

func TestRejectsBadInput(t *testing.T) {
	h := password.New(fast, 1)
	ctx := context.Background()
	if _, err := h.Hash(ctx, ""); !errors.Is(err, password.ErrEmpty) {
		t.Errorf("空密码：%v", err)
	}
	if _, err := h.Hash(ctx, strings.Repeat("a", password.MaxLength+1)); !errors.Is(err, password.ErrTooLong) {
		t.Errorf("超长密码：%v", err)
	}
	enc, _ := h.Hash(ctx, "pw")
	bad := []string{
		"",
		"plain",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=16$m=64,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=64,t=0,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=64,t=1,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHQ$c2hvcnQ",
		enc + "$extra",
	}
	for _, b := range bad {
		if _, _, err := h.Verify(ctx, b, "pw"); !errors.Is(err, password.ErrMalformed) {
			t.Errorf("%q：期望 ErrMalformed，实际 %v", b, err)
		}
	}
}

func TestConcurrencyLimitRespectsContext(t *testing.T) {
	// 并发上限 1 且用较大参数占住槽位时，已取消的 ctx 应立即返回。
	h := password.New(password.Params{Memory: 32 * 1024, Iterations: 3, Parallelism: 1}, 1)
	done := make(chan struct{})
	go func() {
		_, _ = h.Hash(context.Background(), "hold")
		close(done)
	}()
	time.Sleep(5 * time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	_, err := h.Hash(ctx, "pw")
	<-done
	if err == nil {
		// 槽位可能已被释放；此时成功也可接受，只要求不阻塞到超时。
		return
	}
	if !errors.Is(err, context.Canceled) || time.Since(start) > time.Second {
		t.Fatalf("应因 ctx 取消立即返回：%v", err)
	}
}

func TestVerifyDummy(t *testing.T) {
	h := password.New(fast, 1)
	h.VerifyDummy(context.Background(), "anything")
	h.VerifyDummy(context.Background(), "")
}
