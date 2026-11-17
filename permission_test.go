package auth_test

import (
	"testing"

	auth "github.com/ZhcChen/cc-auth-go"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		granted []string
		need    string
		want    bool
	}{
		{[]string{"*"}, "config:write", true},
		{[]string{"config:*"}, "config:write", true},
		{[]string{"config:*"}, "account:write", false},
		{[]string{"*:read"}, "config:read", true},
		{[]string{"*:read"}, "config:write", false},
		{[]string{"config:read"}, "config:read", true},
		{[]string{"config:read"}, "config:write", false},
		{[]string{"*:*"}, "x.y:z-1", true},
		{nil, "config:read", false},
		{[]string{"bad grant", "config:read"}, "config:read", true},
		// 需要的权限不能含通配，也不能不合法。
		{[]string{"*"}, "config:*", false},
		{[]string{"*"}, "*:read", false},
		{[]string{"*"}, "*", false},
		{[]string{"*"}, "Config:read", false},
		{[]string{"*"}, "config", false},
		{[]string{"*"}, "config:read:extra", false},
	}
	for _, c := range cases {
		if got := auth.Match(c.granted, c.need); got != c.want {
			t.Errorf("Match(%v, %q) = %v，期望 %v", c.granted, c.need, got, c.want)
		}
	}
}

func TestValidPermissionAndGrant(t *testing.T) {
	for p, want := range map[string]bool{"config:read": true, "a.b_c-d:e1": true, "config:*": false, "*": false, ":read": false, "1a:read": false} {
		if auth.ValidPermission(p) != want {
			t.Errorf("ValidPermission(%q) 应为 %v", p, want)
		}
	}
	for p, want := range map[string]bool{"*": true, "config:*": true, "*:read": true, "config:read": true, "config": false, "": false} {
		if auth.ValidGrant(p) != want {
			t.Errorf("ValidGrant(%q) 应为 %v", p, want)
		}
	}
}
