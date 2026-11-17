package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// Mode 是令牌模式。
type Mode int

const (
	// ModeSession 会话模式：一个会话令牌，适合同域后台、运维控制台（缺省）。
	ModeSession Mode = iota
	// ModeRefresh 双 token 模式：短期访问令牌 + 轮换的刷新令牌，适合 H5、小程序、App。
	ModeRefresh
)

// Transport 是令牌在请求中的位置。
type Transport int

const (
	// TransportDefault 按模式选择：会话模式用 Cookie，双 token 模式用请求头。
	TransportDefault Transport = iota
	// TransportCookie 令牌放 HttpOnly Cookie；写请求校验来源（CSRF）。
	TransportCookie
	// TransportHeader 令牌放 Authorization: Bearer 请求头。
	TransportHeader
	// TransportBoth 先读请求头，没有再读 Cookie（Cookie 携带时同样校验来源）。
	TransportBoth
)

// 缺省值与下限。
const (
	DefaultIdleTimeout     = 30 * time.Minute // 空闲超时：后台类应用的常见取值
	MinIdleTimeout         = 5 * time.Minute  // 空闲超时下限：低于它活跃时间节流会让会话频繁误判过期
	DefaultAbsoluteTimeout = 12 * time.Hour   // 绝对超时：一个工作日
	DefaultAccessTTL       = 5 * time.Minute  // 双 token 访问令牌有效期
	DefaultElevateTTL      = 5 * time.Minute  // 二次验证有效期
	DefaultRefreshGrace    = 10 * time.Second // 轮换宽限期：容忍丢响应与并发刷新
	DefaultPermissionTTL   = 30 * time.Second // 权限缓存时长
	maxTouchInterval       = time.Minute      // 最后活跃时间最多每分钟写一次
	secretLen              = 32               // 令牌随机部分字节数（256 位）
	maxIDLen               = 64
)

// Config 是运行时可调的配置。每次使用都通过 Options.Config 取最新值，零值字段使用缺省值。
type Config struct {
	IdleTimeout          time.Duration // 多久不活跃即失效；缺省 30 分钟，下限 5 分钟
	AbsoluteTimeout      time.Duration // 登录多久后必须重新登录；缺省 12 小时
	MaxSessionsPerDevice int           // 同一账号同类设备最多在线会话数；0 不限
	MaxSessions          int           // 同一账号全部设备最多在线会话数；0 不限
}

func (c Config) normalized() Config {
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.IdleTimeout < MinIdleTimeout {
		c.IdleTimeout = MinIdleTimeout
	}
	if c.AbsoluteTimeout <= 0 {
		c.AbsoluteTimeout = DefaultAbsoluteTimeout
	}
	if c.MaxSessionsPerDevice < 0 {
		c.MaxSessionsPerDevice = 0
	}
	if c.MaxSessions < 0 {
		c.MaxSessions = 0
	}
	return c
}

// touchInterval 是最后活跃时间的写入间隔：min(1 分钟, 空闲超时/10)。误差方向是略早过期。
func (c Config) touchInterval() time.Duration {
	return min(maxTouchInterval, c.IdleTimeout/10)
}

// Options 是写在代码里、启动后不变的选项。全部可省略。
type Options struct {
	Mode      Mode
	Transport Transport

	// Config 返回运行时配置；nil 表示全部用缺省值。会被频繁调用，应只读内存。
	Config func() Config
	// Permissions 加载账号的停用状态与权限；nil 表示只做登录校验、不判权限。
	Permissions PermissionLoader
	// Listener 接收登录、退出、踢下线等事件；nil 表示不发事件。
	Listener Listener
	// NewID 生成会话 ID（1–64 个字符，只含字母、数字、下划线、连字符）；nil 表示随机生成。
	NewID func(ctx context.Context) (string, error)

	// Devices 是允许的设备类型；缺省 ["web"]。
	Devices []string
	// AllowedOrigins 是 Cookie 模式下允许跨源写请求的 Origin（如 "https://admin.example.com"）。
	// 同源请求由浏览器的 Sec-Fetch-Site 识别，不需要登记。
	AllowedOrigins []string

	// TokenPrefix 是令牌前缀；缺省为 Realm 名称。
	TokenPrefix string
	// CookieName 是 Cookie 名称；缺省 "__Host-<realm>_sid"（InsecureCookie 时为 "<realm>_sid"）。
	CookieName string
	// InsecureCookie 去掉 Secure 属性与 __Host- 前缀，只用于本地 http 开发。
	InsecureCookie bool

	AccessTTL     time.Duration // 双 token 访问令牌有效期；缺省 5 分钟
	ElevateTTL    time.Duration // 二次验证有效期；缺省 5 分钟
	RefreshGrace  time.Duration // 轮换宽限期；缺省 10 秒
	PermissionTTL time.Duration // 权限缓存时长；缺省 30 秒

	// OnError 输出鉴权失败的响应；nil 时输出 {"code": Code(err)} 与 HTTPStatus(err)。
	OnError func(w http.ResponseWriter, r *http.Request, err error)

	// Now 返回当前时间（测试注入）；缺省 time.Now。
	Now func() time.Time
	// Rand 是随机源（测试注入）；缺省 crypto/rand。
	Rand io.Reader
}

var (
	realmNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	deviceRE    = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,15}$`)
	originRE    = regexp.MustCompile(`^https?://[^/\s]+$`)
)

func (o Options) normalized(name string) (Options, error) {
	if o.Mode != ModeSession && o.Mode != ModeRefresh {
		return o, fmt.Errorf("auth: 未知的令牌模式 %d", o.Mode)
	}
	if o.Transport == TransportDefault {
		o.Transport = TransportCookie
		if o.Mode == ModeRefresh {
			o.Transport = TransportHeader
		}
	}
	if o.Transport < TransportCookie || o.Transport > TransportBoth {
		return o, fmt.Errorf("auth: 未知的令牌位置 %d", o.Transport)
	}
	if o.Mode == ModeRefresh && o.Transport != TransportHeader {
		return o, errors.New("auth: 双 token 模式只支持请求头携带令牌")
	}
	if o.Config == nil {
		o.Config = func() Config { return Config{} }
	}
	if len(o.Devices) == 0 {
		o.Devices = []string{"web"}
	}
	for _, d := range o.Devices {
		if !deviceRE.MatchString(d) {
			return o, fmt.Errorf("auth: 设备类型 %q 不合法", d)
		}
	}
	for _, origin := range o.AllowedOrigins {
		if !originRE.MatchString(origin) {
			return o, fmt.Errorf("auth: Origin %q 不合法（形如 https://host[:port]，不带路径）", origin)
		}
	}
	if o.TokenPrefix == "" {
		o.TokenPrefix = name
	}
	if !realmNameRE.MatchString(o.TokenPrefix) {
		return o, fmt.Errorf("auth: 令牌前缀 %q 不合法", o.TokenPrefix)
	}
	if o.CookieName == "" {
		o.CookieName = name + "_sid"
		if !o.InsecureCookie {
			o.CookieName = "__Host-" + o.CookieName
		}
	}
	if o.AccessTTL <= 0 {
		o.AccessTTL = DefaultAccessTTL
	}
	if o.ElevateTTL <= 0 {
		o.ElevateTTL = DefaultElevateTTL
	}
	if o.RefreshGrace <= 0 {
		o.RefreshGrace = DefaultRefreshGrace
	}
	if o.PermissionTTL <= 0 {
		o.PermissionTTL = DefaultPermissionTTL
	}
	if o.OnError == nil {
		o.OnError = defaultOnError
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Rand == nil {
		o.Rand = rand.Reader
	}
	if o.NewID == nil {
		rnd := o.Rand
		o.NewID = func(context.Context) (string, error) {
			b := make([]byte, 16)
			if _, err := io.ReadFull(rnd, b); err != nil {
				return "", err
			}
			return base64.RawURLEncoding.EncodeToString(b), nil
		}
	}
	return o, nil
}

func validID(id string) bool {
	if id == "" || len(id) > maxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
