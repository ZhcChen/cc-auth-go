// Package ginauth 是 cc-auth-go 的 Gin 适配：对核心包 net/http 能力的薄包装。
//
//	r.Use(ginauth.Authenticate(realm))
//	r.POST("/configs/:key", ginauth.Require(realm, "config:write"), h)
//	r.POST("/migrations/run", ginauth.Require(realm, "migration:run"), ginauth.RequireElevated(realm), h)
//
// 失败时用 Realm 的 OnError 输出并中止后续处理。
package ginauth

import (
	"fmt"

	"github.com/gin-gonic/gin"

	auth "github.com/ZhcChen/cc-auth-go"
)

// Authenticate 读取并校验令牌（Cookie 携带时先校验来源），把会话放入请求 ctx。
func Authenticate(r *auth.Realm) gin.HandlerFunc {
	return func(c *gin.Context) {
		s, err := r.AuthenticateRequest(c.Request)
		if err != nil {
			fail(c, r, err)
			return
		}
		c.Request = c.Request.WithContext(auth.WithSession(c.Request.Context(), s))
		c.Next()
	}
}

// Require 要求权限 perm（须在 Authenticate 之后）。perm 不合法时 panic（属于代码错误）。
func Require(r *auth.Realm, perm string) gin.HandlerFunc {
	if !auth.ValidPermission(perm) {
		panic(fmt.Sprintf("ginauth: 权限码 %q 不合法", perm))
	}
	return func(c *gin.Context) {
		s, _ := auth.FromContext(c.Request.Context())
		if err := r.Authorize(c.Request.Context(), s, perm); err != nil {
			fail(c, r, err)
			return
		}
		c.Next()
	}
}

// RequireElevated 要求二次验证仍在有效期内（须在 Authenticate 之后）。
func RequireElevated(r *auth.Realm) gin.HandlerFunc {
	return func(c *gin.Context) {
		s, ok := auth.FromContext(c.Request.Context())
		if !ok {
			fail(c, r, auth.ErrUnauthenticated)
			return
		}
		if !r.Elevated(s) {
			fail(c, r, auth.ErrElevationRequired)
			return
		}
		c.Next()
	}
}

// Session 返回 Authenticate 放入的会话。
func Session(c *gin.Context) (*auth.Session, bool) {
	return auth.FromContext(c.Request.Context())
}

func fail(c *gin.Context, r *auth.Realm, err error) {
	r.WriteError(c.Writer, c.Request, err)
	c.Abort()
}
