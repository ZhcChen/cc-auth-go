package auth

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestTokenRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, secretLen)
	for _, kind := range []tokenKind{kindAccess, kindRefresh} {
		for _, id := range []string{"1", "7319283746512384", strings.Repeat("x", maxIDLen)} {
			tok := encodeToken("worker", kind, id, secret)
			gotID, gotSecret, err := decodeToken("worker", kind, tok)
			if err != nil || gotID != id || !bytes.Equal(gotSecret, secret) {
				t.Fatalf("kind=%d id=%q：往返失败 %v", kind, id, err)
			}
		}
	}
}

func TestTokenFormat(t *testing.T) {
	secret := make([]byte, secretLen)
	if tok := encodeToken("worker", kindAccess, "abc", secret); !strings.HasPrefix(tok, "worker_") || strings.HasPrefix(tok, "worker_rt_") {
		t.Errorf("访问令牌前缀不对：%s", tok)
	}
	if tok := encodeToken("worker", kindRefresh, "abc", secret); !strings.HasPrefix(tok, "worker_rt_") {
		t.Errorf("刷新令牌前缀不对：%s", tok)
	}
}

func TestTokenRejectsMalformed(t *testing.T) {
	secret := make([]byte, secretLen)
	good := encodeToken("worker", kindAccess, "abc", secret)
	refresh := encodeToken("worker", kindRefresh, "abc", secret)
	cases := map[string]struct {
		kind  tokenKind
		token string
	}{
		"空":          {kindAccess, ""},
		"前缀不符":       {kindAccess, "admin_" + strings.TrimPrefix(good, "worker_")},
		"刷新令牌当访问令牌用": {kindAccess, refresh},
		"访问令牌当刷新令牌用": {kindRefresh, good},
		"截断":         {kindAccess, good[:len(good)-2]},
		"多余字符":       {kindAccess, good + "AA"},
		"非法 base64":  {kindAccess, "worker_!!!!"},
		"超长":         {kindAccess, "worker_" + strings.Repeat("A", 500)},
		"ID 长度为 0":   {kindAccess, encodeRaw("worker_", 0, "", secret)},
		"ID 含非法字符":   {kindAccess, encodeToken("worker", kindAccess, "a/b", secret)},
	}
	for name, c := range cases {
		if _, _, err := decodeToken("worker", c.kind, c.token); !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s：期望 ErrInvalidToken，实际 %v", name, err)
		}
	}
}

func encodeRaw(prefix string, n byte, id string, secret []byte) string {
	b := append([]byte{n}, id...)
	b = append(b, secret...)
	return prefix + base64.RawURLEncoding.EncodeToString(b)
}

func TestDeriveRotationDeterministic(t *testing.T) {
	salt, old := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	a1, r1 := deriveRotation(salt, old)
	a2, r2 := deriveRotation(salt, old)
	if !bytes.Equal(a1, a2) || !bytes.Equal(r1, r2) {
		t.Fatal("同一输入应派生同一组令牌")
	}
	if bytes.Equal(a1, r1) || len(a1) != secretLen || len(r1) != secretLen {
		t.Fatal("访问与刷新随机数应不同且为 32 字节")
	}
	a3, _ := deriveRotation(bytes.Repeat([]byte{9}, 32), old)
	if bytes.Equal(a1, a3) {
		t.Fatal("不同盐应派生不同令牌")
	}
}

func TestTruncateKeepsUTF8(t *testing.T) {
	if got := truncate("ab中文", 4); got != "ab" {
		t.Errorf("不应切断多字节字符：%q", got)
	}
	if got := truncate("ab中文", 5); got != "ab中" {
		t.Errorf("完整字符应保留：%q", got)
	}
	if got := truncate("short", 64); got != "short" {
		t.Errorf("未超长不应截断：%q", got)
	}
}

func TestConfigNormalized(t *testing.T) {
	c := Config{}.normalized()
	if c.IdleTimeout != DefaultIdleTimeout || c.AbsoluteTimeout != DefaultAbsoluteTimeout {
		t.Errorf("零值应取缺省：%+v", c)
	}
	if c := (Config{IdleTimeout: 1}).normalized(); c.IdleTimeout != MinIdleTimeout {
		t.Errorf("低于下限应钳制：%v", c.IdleTimeout)
	}
	if iv := (Config{IdleTimeout: DefaultIdleTimeout}).normalized().touchInterval(); iv != maxTouchInterval {
		t.Errorf("30 分钟空闲的写入间隔应为 1 分钟：%v", iv)
	}
	if iv := (Config{IdleTimeout: MinIdleTimeout}).normalized().touchInterval(); iv != MinIdleTimeout/10 {
		t.Errorf("5 分钟空闲的写入间隔应为 30 秒：%v", iv)
	}
}
