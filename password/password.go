// Package password 是 argon2id 密码哈希。
//
// 哈希串使用 PHC 格式：$argon2id$v=19$m=<KiB>,t=<迭代>,p=<并行>$<盐>$<哈希>（无填充的标准 base64）。
// argon2id 故意又慢又占内存，所以 Hasher 自带并发上限，超出的调用排队（受 ctx 控制），
// 防止大量并发登录瞬间耗尽内存。
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// MaxLength 是密码的最大字节数（防止超长输入消耗资源）。
const MaxLength = 1024

var (
	// ErrEmpty 表示密码为空。
	ErrEmpty = errors.New("password: 密码为空")
	// ErrTooLong 表示密码超过 MaxLength。
	ErrTooLong = errors.New("password: 密码过长")
	// ErrMalformed 表示哈希串格式不对或参数超出允许范围。
	ErrMalformed = errors.New("password: 哈希串格式不对")
)

// Params 是 argon2id 参数。零值字段取 DefaultParams 中的值。
type Params struct {
	Memory      uint32 // 内存（KiB）
	Iterations  uint32 // 迭代次数
	Parallelism uint8  // 并行度
	SaltLen     uint32 // 盐长度（字节）
	KeyLen      uint32 // 哈希长度（字节）
}

// DefaultParams 是 OWASP 推荐的 argon2id 参数：19 MiB 内存、2 次迭代、并行度 1。
var DefaultParams = Params{Memory: 19 * 1024, Iterations: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}

// 解析哈希串时允许的参数上限（防止被篡改的哈希串造成资源耗尽）。
const (
	maxMemory     = 1024 * 1024 // 1 GiB
	maxIterations = 64
	maxKeyLen     = 128
	maxSaltLen    = 64
)

func (p Params) normalized() Params {
	d := DefaultParams
	if p.Memory == 0 {
		p.Memory = d.Memory
	}
	if p.Iterations == 0 {
		p.Iterations = d.Iterations
	}
	if p.Parallelism == 0 {
		p.Parallelism = d.Parallelism
	}
	if p.SaltLen == 0 {
		p.SaltLen = d.SaltLen
	}
	if p.KeyLen == 0 {
		p.KeyLen = d.KeyLen
	}
	return p
}

// Hasher 计算与校验密码哈希，可并发使用。
type Hasher struct {
	p   Params
	sem chan struct{}

	dummyOnce sync.Once
	dummy     string
}

// New 创建 Hasher。maxConcurrent 是同时计算的上限，0 表示 CPU 核数。
func New(p Params, maxConcurrent int) *Hasher {
	if maxConcurrent <= 0 {
		maxConcurrent = runtime.NumCPU()
	}
	return &Hasher{p: p.normalized(), sem: make(chan struct{}, maxConcurrent)}
}

// Default 是使用 DefaultParams、并发上限为 CPU 核数的 Hasher。
var Default = New(Params{}, 0)

// Hash 计算 Default 的哈希。
func Hash(ctx context.Context, plain string) (string, error) { return Default.Hash(ctx, plain) }

// Verify 用 Default 校验。
func Verify(ctx context.Context, encoded, plain string) (ok, needsRehash bool, err error) {
	return Default.Verify(ctx, encoded, plain)
}

// VerifyDummy 用 Default 做一次等时的假校验。
func VerifyDummy(ctx context.Context, plain string) { Default.VerifyDummy(ctx, plain) }

func checkPlain(plain string) error {
	if plain == "" {
		return ErrEmpty
	}
	if len(plain) > MaxLength {
		return ErrTooLong
	}
	return nil
}

func (h *Hasher) acquire(ctx context.Context) error {
	select {
	case h.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hasher) release() { <-h.sem }

// Hash 计算密码的 PHC 格式哈希串（随机盐）。
func (h *Hasher) Hash(ctx context.Context, plain string) (string, error) {
	if err := checkPlain(plain); err != nil {
		return "", err
	}
	salt := make([]byte, h.p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	if err := h.acquire(ctx); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plain), salt, h.p.Iterations, h.p.Memory, h.p.Parallelism, h.p.KeyLen)
	h.release()
	return encode(h.p, salt, key), nil
}

// Verify 校验密码。ok 表示匹配；needsRehash 表示哈希串的参数与当前参数不同，
// 校验通过后应用 Hash 重新计算并保存。哈希串格式不对返回 ErrMalformed。
func (h *Hasher) Verify(ctx context.Context, encoded, plain string) (ok, needsRehash bool, err error) {
	if err := checkPlain(plain); err != nil {
		return false, false, err
	}
	p, salt, key, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	if err := h.acquire(ctx); err != nil {
		return false, false, err
	}
	got := argon2.IDKey([]byte(plain), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLen)
	h.release()
	if subtle.ConstantTimeCompare(got, key) != 1 {
		return false, false, nil
	}
	return true, p != h.p, nil
}

// VerifyDummy 对一个固定的假哈希做一次校验并丢弃结果。账号不存在时调用，
// 让“账号不存在”与“密码错误”的耗时一致，避免通过响应时间探测账号。
func (h *Hasher) VerifyDummy(ctx context.Context, plain string) {
	h.dummyOnce.Do(func() {
		salt := make([]byte, h.p.SaltLen)
		key := make([]byte, h.p.KeyLen)
		h.dummy = encode(h.p, salt, key)
	})
	if checkPlain(plain) != nil {
		plain = "x"
	}
	_, _, _ = h.Verify(ctx, h.dummy, plain)
}

var b64 = base64.RawStdEncoding

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(s string) (p Params, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, nil, nil, ErrMalformed
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return p, nil, nil, ErrMalformed
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrMalformed
	}
	if p.Memory == 0 || p.Memory > maxMemory || p.Iterations == 0 || p.Iterations > maxIterations || p.Parallelism == 0 {
		return p, nil, nil, ErrMalformed
	}
	if salt, err = b64.Strict().DecodeString(parts[4]); err != nil || len(salt) == 0 || len(salt) > maxSaltLen {
		return p, nil, nil, ErrMalformed
	}
	if key, err = b64.Strict().DecodeString(parts[5]); err != nil || len(key) < 16 || len(key) > maxKeyLen {
		return p, nil, nil, ErrMalformed
	}
	p.SaltLen, p.KeyLen = uint32(len(salt)), uint32(len(key))
	return p, salt, key, nil
}
