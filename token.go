package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"io"
	"strings"
)

// 令牌格式：
//
//	会话令牌、访问令牌：<前缀>_<base64url(len(ID) ‖ ID ‖ 32 字节随机数)>
//	刷新令牌：          <前缀>_rt_<base64url(len(ID) ‖ ID ‖ 32 字节随机数)>
//
// 会话 ID 不保密，用来按主键找到会话；随机数是真正的凭据，存储里只保存它的 SHA-256。
// base64url 的首字符由 len(ID)（1–64）决定，只会是 A–Q，因此 "rt_" 不会与访问令牌混淆。

const refreshMarker = "rt_"

type tokenKind int

const (
	kindAccess tokenKind = iota // 会话令牌或访问令牌
	kindRefresh
)

func encodeToken(prefix string, kind tokenKind, id string, secret []byte) string {
	b := make([]byte, 0, 1+len(id)+len(secret))
	b = append(b, byte(len(id)))
	b = append(b, id...)
	b = append(b, secret...)
	p := prefix + "_"
	if kind == kindRefresh {
		p += refreshMarker
	}
	return p + base64.RawURLEncoding.EncodeToString(b)
}

// decodeToken 解析令牌，返回会话 ID 与随机部分。任何格式问题都返回 ErrInvalidToken。
func decodeToken(prefix string, kind tokenKind, token string) (id string, secret []byte, err error) {
	rest, ok := strings.CutPrefix(token, prefix+"_")
	if !ok {
		return "", nil, ErrInvalidToken
	}
	isRefresh := strings.HasPrefix(rest, refreshMarker)
	if isRefresh != (kind == kindRefresh) {
		return "", nil, ErrInvalidToken
	}
	if isRefresh {
		rest = rest[len(refreshMarker):]
	}
	if len(rest) > base64.RawURLEncoding.EncodedLen(1+maxIDLen+secretLen) {
		return "", nil, ErrInvalidToken
	}
	b, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(b) < 1 {
		return "", nil, ErrInvalidToken
	}
	n := int(b[0])
	if n == 0 || n > maxIDLen || len(b) != 1+n+secretLen {
		return "", nil, ErrInvalidToken
	}
	id = string(b[1 : 1+n])
	if !validID(id) {
		return "", nil, ErrInvalidToken
	}
	return id, b[1+n:], nil
}

func newSecret(r io.Reader) ([]byte, error) {
	b := make([]byte, secretLen)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func hashSecret(secret []byte) []byte {
	h := sha256.Sum256(secret)
	return h[:]
}

// sameHash 常量时间比较；want 为空时视为不匹配。
func sameHash(got, want []byte) bool {
	return len(want) > 0 && subtle.ConstantTimeCompare(got, want) == 1
}

// deriveRotation 由旧刷新令牌的随机部分与会话内盐派生下一组访问、刷新随机数。
// 宽限期内重放旧刷新令牌时可以重算出同一组令牌；没有盐无法推出。
func deriveRotation(salt, oldRefresh []byte) (access, refresh []byte) {
	mac := func(label string) []byte {
		h := hmac.New(sha256.New, salt)
		h.Write([]byte(label))
		h.Write(oldRefresh)
		return h.Sum(nil)
	}
	return mac("access"), mac("refresh")
}
