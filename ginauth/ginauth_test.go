package ginauth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	auth "github.com/ZhcChen/cc-auth-go"
	"github.com/ZhcChen/cc-auth-go/ginauth"
	"github.com/ZhcChen/cc-auth-go/memstore"
)

func setup(t *testing.T) (*auth.Realm, *gin.Engine, auth.Tokens) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	loader := auth.PermissionLoaderFunc(func(context.Context, string) (auth.Grants, error) {
		return auth.Grants{Permissions: []string{"config:read"}}, nil
	})
	r, err := auth.New("ops", memstore.New(), auth.Options{Transport: auth.TransportHeader, Permissions: loader})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := r.Login(context.Background(), "u1", auth.LoginInfo{})
	if err != nil {
		t.Fatal(err)
	}
	e := gin.New()
	g := e.Group("/", ginauth.Authenticate(r))
	ok := func(c *gin.Context) {
		s, _ := ginauth.Session(c)
		c.String(http.StatusOK, s.Subject)
	}
	g.GET("/read", ginauth.Require(r, "config:read"), ok)
	g.GET("/write", ginauth.Require(r, "config:write"), ok)
	g.GET("/danger", ginauth.RequireElevated(r), ok)
	return r, e, tok
}

func do(e *gin.Engine, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

func TestGinMiddlewares(t *testing.T) {
	r, e, tok := setup(t)
	if rec := do(e, "/read", ""); rec.Code != 401 {
		t.Fatalf("未登录：%d", rec.Code)
	}
	if rec := do(e, "/read", tok.Token); rec.Code != 200 || rec.Body.String() != "u1" {
		t.Fatalf("有权限：%d %s", rec.Code, rec.Body)
	}
	if rec := do(e, "/write", tok.Token); rec.Code != 403 || !strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatalf("无权限：%d %s", rec.Code, rec.Body)
	}
	if rec := do(e, "/danger", tok.Token); rec.Code != 403 || !strings.Contains(rec.Body.String(), "elevation_required") {
		t.Fatalf("未二次验证：%d %s", rec.Code, rec.Body)
	}
	if _, err := r.Elevate(context.Background(), tok.SessionID); err != nil {
		t.Fatal(err)
	}
	if rec := do(e, "/danger", tok.Token); rec.Code != 200 {
		t.Fatalf("二次验证后：%d %s", rec.Code, rec.Body)
	}
}

func TestRequirePanicsOnBadPermission(t *testing.T) {
	r, _, _ := setup(t)
	defer func() {
		if recover() == nil {
			t.Fatal("不合法的权限码应 panic")
		}
	}()
	ginauth.Require(r, "config:*")
}
