package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type sessionKey struct{}

// WithSession 把会话放入 ctx。
func WithSession(ctx context.Context, s *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

// FromContext 取出 Authenticate 放入的会话。
func FromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok && s != nil
}

// TokenFromRequest 按 Transport 读取令牌：请求头 Authorization: Bearer，或 Cookie。
// fromCookie 表示令牌来自 Cookie（写请求需要校验来源）。
func (r *Realm) TokenFromRequest(req *http.Request) (token string, fromCookie bool) {
	t := r.opt.Transport
	if t == TransportHeader || t == TransportBoth {
		if scheme, v, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
			if v = strings.TrimSpace(v); v != "" {
				return v, false
			}
		}
	}
	if t == TransportCookie || t == TransportBoth {
		if c, err := req.Cookie(r.opt.CookieName); err == nil && c.Value != "" {
			return c.Value, true
		}
	}
	return "", false
}

// CheckOrigin 校验写请求的来源（防 CSRF）：安全方法直接放行；否则要求
// Sec-Fetch-Site 为 same-origin，或 Origin 在 AllowedOrigins 中，两者都不满足返回 ErrCSRF。
// 不与 Host 比较（前置 CDN 或代理可能改写 Host）。Cookie 模式的登录接口也应调用它（防登录 CSRF）。
func (r *Realm) CheckOrigin(req *http.Request) error {
	switch req.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return nil
	}
	if req.Header.Get("Sec-Fetch-Site") == "same-origin" {
		return nil
	}
	if o := req.Header.Get("Origin"); o != "" && r.origins[o] {
		return nil
	}
	return ErrCSRF
}

// AuthenticateRequest 读取并校验请求中的令牌（Cookie 携带时先校验来源），返回会话。
// 供各框架适配层使用；net/http 直接用 Authenticate 中间件。
func (r *Realm) AuthenticateRequest(req *http.Request) (*Session, error) {
	token, fromCookie := r.TokenFromRequest(req)
	if token == "" {
		return nil, ErrUnauthenticated
	}
	if fromCookie {
		if err := r.CheckOrigin(req); err != nil {
			return nil, err
		}
	}
	return r.Verify(req.Context(), token)
}

// Authenticate 是 net/http 中间件：校验通过后把会话放入请求 ctx，失败时用 OnError 输出。
func (r *Realm) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s, err := r.AuthenticateRequest(req)
		if err != nil {
			r.WriteError(w, req, err)
			return
		}
		next.ServeHTTP(w, req.WithContext(WithSession(req.Context(), s)))
	})
}

// Require 返回要求权限 perm 的中间件（须在 Authenticate 之后）。perm 不合法时 panic（属于代码错误）。
func (r *Realm) Require(perm string) func(http.Handler) http.Handler {
	if !ValidPermission(perm) {
		panic(fmt.Sprintf("auth: 权限码 %q 不合法", perm))
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			s, _ := FromContext(req.Context())
			if err := r.Authorize(req.Context(), s, perm); err != nil {
				r.WriteError(w, req, err)
				return
			}
			next.ServeHTTP(w, req)
		})
	}
}

// RequireElevated 是要求二次验证仍在有效期内的中间件（须在 Authenticate 之后）。
func (r *Realm) RequireElevated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		s, ok := FromContext(req.Context())
		if !ok {
			r.WriteError(w, req, ErrUnauthenticated)
			return
		}
		if !r.Elevated(s) {
			r.WriteError(w, req, ErrElevationRequired)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// WriteError 用 Options.OnError 输出鉴权错误。
func (r *Realm) WriteError(w http.ResponseWriter, req *http.Request, err error) {
	r.opt.OnError(w, req, err)
}

func defaultOnError(w http.ResponseWriter, _ *http.Request, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(HTTPStatus(err))
	_, _ = fmt.Fprintf(w, `{"code":%q}`, Code(err))
}

// SetCookie 把会话令牌写入 Cookie（HttpOnly、Secure、SameSite=Strict、Path=/）。
func (r *Realm) SetCookie(w http.ResponseWriter, t Tokens) {
	maxAge := int(t.TokenExpiresAt.Sub(r.now()) / time.Second)
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name: r.opt.CookieName, Value: t.Token, Path: "/", Expires: t.TokenExpiresAt, MaxAge: maxAge,
		HttpOnly: true, Secure: !r.opt.InsecureCookie, SameSite: http.SameSiteStrictMode,
	})
}

// ClearCookie 删除会话 Cookie（退出登录时调用）。
func (r *Realm) ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: r.opt.CookieName, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: !r.opt.InsecureCookie, SameSite: http.SameSiteStrictMode,
	})
}
