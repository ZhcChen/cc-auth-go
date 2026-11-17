package auth

import (
	"errors"
	"net/http"
)

// 鉴权与授权的哨兵错误，调用方用 errors.Is 判断。错误文本不含令牌、账号或存储细节。
var (
	// ErrNotFound 表示存储中没有该会话（Store 实现返回）。
	ErrNotFound = errors.New("auth: 会话不存在")
	// ErrConflict 表示保存时版本不符，会话已被并发修改（Store 实现返回）。
	ErrConflict = errors.New("auth: 会话已被并发修改")

	// ErrUnauthenticated 表示请求没有携带令牌。
	ErrUnauthenticated = errors.New("auth: 未登录")
	// ErrInvalidToken 表示令牌格式错误、不存在或与会话不符。
	ErrInvalidToken = errors.New("auth: 令牌无效")
	// ErrExpired 表示会话已超过空闲超时或绝对超时，需要重新登录。
	ErrExpired = errors.New("auth: 登录已过期")
	// ErrTokenExpired 表示双 token 模式下访问令牌已过期，应使用刷新令牌换新。
	ErrTokenExpired = errors.New("auth: 访问令牌已过期")
	// ErrLoggedOut 表示会话已退出登录。
	ErrLoggedOut = errors.New("auth: 已退出登录")
	// ErrKicked 表示会话已被强制下线。
	ErrKicked = errors.New("auth: 已被强制下线")
	// ErrReplaced 表示超出在线会话上限，会话被新的登录顶替。
	ErrReplaced = errors.New("auth: 已在其他设备登录")
	// ErrReused 表示刷新令牌被重复使用，判定泄露，整个会话已吊销。
	ErrReused = errors.New("auth: 刷新令牌被重复使用，会话已吊销")
	// ErrDisabled 表示账号已停用。
	ErrDisabled = errors.New("auth: 账号已停用")

	// ErrForbidden 表示已登录但没有所需权限。
	ErrForbidden = errors.New("auth: 没有权限")
	// ErrElevationRequired 表示敏感操作需要先重新验证身份（二次验证）。
	ErrElevationRequired = errors.New("auth: 需要重新验证身份")
	// ErrCSRF 表示 Cookie 模式下的跨站写请求被拒绝。
	ErrCSRF = errors.New("auth: 跨站请求被拒绝")
	// ErrDevice 表示登录的设备类型不在允许列表中。
	ErrDevice = errors.New("auth: 设备类型不在允许列表中")
)

// Code 返回错误的稳定代码，供接口响应与前端判断；未知错误返回 "internal"。
func Code(err error) string {
	for _, c := range codes {
		if errors.Is(err, c.err) {
			return c.code
		}
	}
	return "internal"
}

// HTTPStatus 返回错误对应的 HTTP 状态码：需要（重新）登录为 401，已登录但被拒绝为 403，其余为 500。
func HTTPStatus(err error) int {
	for _, c := range codes {
		if errors.Is(err, c.err) {
			return c.status
		}
	}
	return http.StatusInternalServerError
}

var codes = []struct {
	err    error
	code   string
	status int
}{
	{ErrUnauthenticated, "unauthenticated", http.StatusUnauthorized},
	{ErrInvalidToken, "invalid_token", http.StatusUnauthorized},
	{ErrExpired, "expired", http.StatusUnauthorized},
	{ErrTokenExpired, "token_expired", http.StatusUnauthorized},
	{ErrLoggedOut, "logged_out", http.StatusUnauthorized},
	{ErrKicked, "kicked", http.StatusUnauthorized},
	{ErrReplaced, "replaced", http.StatusUnauthorized},
	{ErrReused, "reused", http.StatusUnauthorized},
	{ErrDisabled, "disabled", http.StatusUnauthorized},
	{ErrForbidden, "forbidden", http.StatusForbidden},
	{ErrElevationRequired, "elevation_required", http.StatusForbidden},
	{ErrCSRF, "csrf", http.StatusForbidden},
	{ErrDevice, "device", http.StatusBadRequest},
}
