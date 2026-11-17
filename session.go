package auth

import (
	"bytes"
	"time"
)

// Reason 是会话被吊销的原因。
type Reason string

// 吊销原因。
const (
	ReasonLogout   Reason = "logout"   // 主动退出
	ReasonKicked   Reason = "kicked"   // 被管理员或系统强制下线（停用账号、改密等）
	ReasonReplaced Reason = "replaced" // 超出在线上限，被新的登录顶替
	ReasonReused   Reason = "reused"   // 刷新令牌被重复使用，判定泄露
)

// Err 返回该原因对应的哨兵错误。
func (r Reason) Err() error {
	switch r {
	case ReasonLogout:
		return ErrLoggedOut
	case ReasonKicked:
		return ErrKicked
	case ReasonReplaced:
		return ErrReplaced
	case ReasonReused:
		return ErrReused
	default:
		return ErrInvalidToken
	}
}

// Session 是一次登录（一个设备上的一次登录）。
//
// 只记录事实时间（登录、最后活跃、二次验证、轮换），是否过期在每次校验时按当前配置计算。
// 令牌只存 SHA-256 哈希。被吊销的会话保留到自然过期，以便告诉客户端吊销原因。
type Session struct {
	ID      string // 会话 ID（Options.NewID 生成），不保密
	Subject string // 账号 ID
	Device  string // 设备类型（白名单内）
	IP      string // 登录时的客户端 IP（最长 64 字节）
	UA      string // 登录时的 User-Agent（最长 256 字节）

	CreatedAt  time.Time // 登录时间
	LastSeenAt time.Time // 最后活跃时间（按节流间隔更新）
	ElevatedAt time.Time // 最近一次二次验证时间；零值表示没有

	TokenHash      []byte    // 当前会话令牌或访问令牌的哈希
	PrevTokenHash  []byte    // 上一个会话令牌或访问令牌的哈希（轮换后短暂有效）
	PrevTokenUntil time.Time // 上一个令牌的失效时间

	RefreshHash     []byte    // 当前刷新令牌的哈希（双 token 模式）
	PrevRefreshHash []byte    // 上一个刷新令牌的哈希（用于宽限期幂等与重放检测）
	RotatedAt       time.Time // 最近一次签发访问令牌的时间
	RotateSalt      []byte    // 刷新轮换派生新令牌用的会话内随机盐

	RevokedAt    time.Time // 吊销时间；零值表示有效
	RevokeReason Reason    // 吊销原因

	Gen int64 // 乐观锁版本：每次 Save 加一
}

// Revoked 报告会话是否已被吊销。
func (s *Session) Revoked() bool { return !s.RevokedAt.IsZero() }

// Clone 返回深拷贝。
func (s *Session) Clone() *Session {
	c := *s
	c.TokenHash = bytes.Clone(s.TokenHash)
	c.PrevTokenHash = bytes.Clone(s.PrevTokenHash)
	c.RefreshHash = bytes.Clone(s.RefreshHash)
	c.PrevRefreshHash = bytes.Clone(s.PrevRefreshHash)
	c.RotateSalt = bytes.Clone(s.RotateSalt)
	return &c
}

// LoginInfo 是登录时记录的信息。
type LoginInfo struct {
	Device string // 设备类型；空表示允许列表中的第一个
	IP     string
	UA     string
	// Replace 是请求中携带的旧令牌（如有）。登录时将其所属会话退出，防止会话固定。
	Replace string
}

// Tokens 是签发给客户端的令牌。令牌明文只在这里出现一次。
type Tokens struct {
	SessionID string
	// Token 是会话令牌（会话模式）或访问令牌（双 token 模式）。
	Token string
	// TokenExpiresAt 是 Token 的最晚失效时间（会话模式为绝对超时；双 token 为访问令牌有效期）。
	TokenExpiresAt time.Time
	// Refresh 是刷新令牌，只在双 token 模式下有值。
	Refresh string
	// RefreshExpiresAt 是刷新令牌的最晚失效时间（绝对超时）。
	RefreshExpiresAt time.Time
}
