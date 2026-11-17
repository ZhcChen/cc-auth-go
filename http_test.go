package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	auth "github.com/ZhcChen/cc-auth-go"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := auth.FromContext(r.Context())
		if !ok {
			http.Error(w, "no session", http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(s.Subject))
	})
}

func serve(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func withCookie(req *http.Request, r *auth.Realm, tok auth.Tokens) *http.Request {
	rec := httptest.NewRecorder()
	r.SetCookie(rec, tok)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.login(t, "u1", auth.LoginInfo{})
	rec := httptest.NewRecorder()
	e.realm.SetCookie(rec, tok)
	cs := rec.Result().Cookies()
	if len(cs) != 1 {
		t.Fatalf("应写入 1 个 Cookie：%v", cs)
	}
	c := cs[0]
	if c.Name != "__Host-worker_sid" || c.Path != "/" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Domain != "" {
		t.Fatalf("Cookie 属性不对：%+v", c)
	}
	rec = httptest.NewRecorder()
	e.realm.ClearCookie(rec)
	if c := rec.Result().Cookies()[0]; c.MaxAge >= 0 || c.Value != "" {
		t.Fatalf("清除 Cookie 应设 MaxAge<0：%+v", c)
	}
}

func TestAuthenticateCookieAndCSRF(t *testing.T) {
	e := newEnv(t, func(o *auth.Options) { o.AllowedOrigins = []string{"https://admin.example.com"} })
	tok := e.login(t, "u1", auth.LoginInfo{})
	h := e.realm.Authenticate(okHandler())

	cases := []struct {
		name   string
		method string
		header map[string]string
		want   int
		code   string
	}{
		{"GET 不校验来源", http.MethodGet, nil, 200, ""},
		{"POST 同源", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, 200, ""},
		{"POST 白名单 Origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://admin.example.com"}, 200, ""},
		{"POST 跨站", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.net"}, 403, "csrf"},
		{"POST 无来源信息", http.MethodPost, nil, 403, "csrf"},
		{"DELETE 非白名单 Origin", http.MethodDelete, map[string]string{"Origin": "https://admin.example.com.evil.net"}, 403, "csrf"},
	}
	for _, c := range cases {
		req := withCookie(httptest.NewRequest(c.method, "/x", nil), e.realm, tok)
		for k, v := range c.header {
			req.Header.Set(k, v)
		}
		rec := serve(h, req)
		if rec.Code != c.want {
			t.Errorf("%s：状态 %d，期望 %d（%s）", c.name, rec.Code, c.want, rec.Body)
			continue
		}
		if c.code != "" && !strings.Contains(rec.Body.String(), `"code":"`+c.code+`"`) {
			t.Errorf("%s：响应体 %s", c.name, rec.Body)
		}
		if c.want == 200 && rec.Body.String() != "u1" {
			t.Errorf("%s：应把会话放入 ctx", c.name)
		}
	}
}

func TestAuthenticateErrors(t *testing.T) {
	e := newEnv(t, nil)
	h := e.realm.Authenticate(okHandler())
	rec := serve(h, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"unauthenticated"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("未登录：%d %s", rec.Code, rec.Body)
	}
	// Cookie 模式不读请求头。
	tok := e.login(t, "u1", auth.LoginInfo{})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok.Token)
	if rec := serve(h, req); rec.Code != 401 {
		t.Fatalf("Cookie 模式不应接受请求头令牌：%d", rec.Code)
	}
}

func TestHeaderTransportSkipsCSRF(t *testing.T) {
	e := newEnv(t, func(o *auth.Options) { o.Transport = auth.TransportHeader })
	tok := e.login(t, "u1", auth.LoginInfo{})
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("Authorization", "bearer "+tok.Token)
	if rec := serve(e.realm.Authenticate(okHandler()), req); rec.Code != 200 {
		t.Fatalf("请求头模式不校验来源：%d %s", rec.Code, rec.Body)
	}
}

func TestRequireAndElevated(t *testing.T) {
	e := newEnv(t, nil)
	tok := e.login(t, "u1", auth.LoginInfo{})
	get := func(h http.Handler, tok auth.Tokens) *httptest.ResponseRecorder {
		return serve(e.realm.Authenticate(h), withCookie(httptest.NewRequest(http.MethodGet, "/x", nil), e.realm, tok))
	}
	if rec := get(e.realm.Require("config:write")(okHandler()), tok); rec.Code != 200 {
		t.Fatalf("有权限：%d", rec.Code)
	}
	if rec := get(e.realm.Require("account:write")(okHandler()), tok); rec.Code != 403 || !strings.Contains(rec.Body.String(), "forbidden") {
		t.Fatalf("无权限：%d %s", rec.Code, rec.Body)
	}
	elevated := e.realm.RequireElevated(okHandler())
	if rec := get(elevated, tok); rec.Code != 403 || !strings.Contains(rec.Body.String(), "elevation_required") {
		t.Fatalf("未二次验证：%d %s", rec.Code, rec.Body)
	}
	nt, err := e.realm.Elevate(context.Background(), tok.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if rec := get(elevated, nt); rec.Code != 200 {
		t.Fatalf("二次验证后：%d %s", rec.Code, rec.Body)
	}
	defer func() {
		if recover() == nil {
			t.Error("不合法的权限码应 panic")
		}
	}()
	e.realm.Require("config:*")
}

func TestCustomOnError(t *testing.T) {
	e := newEnv(t, func(o *auth.Options) {
		o.OnError = func(w http.ResponseWriter, _ *http.Request, err error) {
			w.WriteHeader(auth.HTTPStatus(err))
			_, _ = w.Write([]byte("custom:" + auth.Code(err)))
		}
	})
	rec := serve(e.realm.Authenticate(okHandler()), httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Body.String() != "custom:unauthenticated" {
		t.Fatalf("应使用自定义输出：%s", rec.Body)
	}
}

func TestCodeAndStatus(t *testing.T) {
	cases := map[error]struct {
		code   string
		status int
	}{
		auth.ErrExpired:           {"expired", 401},
		auth.ErrTokenExpired:      {"token_expired", 401},
		auth.ErrReplaced:          {"replaced", 401},
		auth.ErrForbidden:         {"forbidden", 403},
		auth.ErrElevationRequired: {"elevation_required", 403},
		context.Canceled:          {"internal", 500},
	}
	for err, want := range cases {
		if auth.Code(err) != want.code || auth.HTTPStatus(err) != want.status {
			t.Errorf("%v：%s %d", err, auth.Code(err), auth.HTTPStatus(err))
		}
	}
}
