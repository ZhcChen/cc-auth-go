package auth

import "strings"

// 权限码格式为“资源:动作”，两段都由小写字母、数字、下划线、点、连字符组成，以字母开头。
// 授予的权限可以用通配：
//
//	*          全部权限
//	config:*   config 资源的全部动作
//	*:read     全部资源的 read 动作
//
// 需要的权限（Require、Can 的参数）必须是具体权限码，不能含通配。

// Match 判断授予的权限中是否有一项覆盖 need。need 不是合法的具体权限码时返回 false。
func Match(granted []string, need string) bool {
	res, act, ok := splitPermission(need)
	if !ok || res == "*" || act == "*" {
		return false
	}
	for _, g := range granted {
		if g == "*" || g == need {
			return true
		}
		gr, ga, ok := splitPermission(g)
		if !ok {
			continue
		}
		if (gr == "*" || gr == res) && (ga == "*" || ga == act) {
			return true
		}
	}
	return false
}

// ValidPermission 判断 p 是否为合法的具体权限码（不含通配）。
func ValidPermission(p string) bool {
	res, act, ok := splitPermission(p)
	return ok && res != "*" && act != "*"
}

// ValidGrant 判断 p 是否为合法的授予权限（允许通配）。
func ValidGrant(p string) bool {
	if p == "*" {
		return true
	}
	_, _, ok := splitPermission(p)
	return ok
}

func splitPermission(p string) (res, act string, ok bool) {
	res, act, found := strings.Cut(p, ":")
	if !found || !validSegment(res) || !validSegment(act) {
		return "", "", false
	}
	return res, act, true
}

func validSegment(s string) bool {
	if s == "*" {
		return true
	}
	if s == "" || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}
