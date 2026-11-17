package auth

import (
	"context"
	"time"
)

// Store 保存会话。每个实例只服务一个 Realm。
//
// 实现须通过 storetest.Run 一致性测试。时间按调用方传入的值原样保存（Realm 已截断到微秒、UTC）。
type Store interface {
	// Create 保存新会话。lim 中的上限大于 0 时，在同一原子操作内把该账号超出上限的最早的
	// 有效会话吊销为 ReasonReplaced（时间取 s.CreatedAt，Gen 加一），返回被吊销的会话 ID。
	// 有效会话指未吊销、LastSeenAt 不早于 lim.IdleCutoff、CreatedAt 不早于 lim.AbsoluteCutoff 的会话；
	// 新会话本身计入。先按设备上限淘汰，再按总数上限淘汰；同一时刻创建的按 ID 排序。
	// ID 已存在时返回 ErrConflict。
	Create(ctx context.Context, s *Session, lim Limits) (evicted []string, err error)

	// Get 按 ID 读取会话；不存在返回 ErrNotFound。返回值归调用方所有。
	Get(ctx context.Context, id string) (*Session, error)

	// Save 整体保存会话：仅当存储中的 Gen 等于 expectGen 时写入 s（s.Gen 已由调用方设为新值），
	// 否则返回 ErrConflict；不存在返回 ErrNotFound。
	Save(ctx context.Context, s *Session, expectGen int64) error

	// Touch 仅当存储中的 LastSeenAt 早于 ifBefore 时把它更新为 seen（不改 Gen）；
	// 不存在返回 ErrNotFound，条件不满足时不报错。
	Touch(ctx context.Context, id string, seen, ifBefore time.Time) error

	// List 返回账号的全部会话（含已吊销、已过期但尚未清理的），按 CreatedAt、ID 升序。
	List(ctx context.Context, subject string) ([]*Session, error)

	// RevokeSubject 吊销账号除 exceptID 外全部未吊销的会话（Gen 加一），返回吊销数量。
	RevokeSubject(ctx context.Context, subject, exceptID string, reason Reason, at time.Time) (int, error)
}

// Limits 是创建会话时的在线上限。上限为 0 表示不限。
type Limits struct {
	MaxPerDevice   int
	MaxTotal       int
	IdleCutoff     time.Time // LastSeenAt 早于它的会话已空闲过期，不计入
	AbsoluteCutoff time.Time // CreatedAt 早于它的会话已绝对过期，不计入
}

// Sweeper 是可选接口：删除已过期的会话。依赖 TTL 自动过期的存储可以不实现。
type Sweeper interface {
	// DeleteExpired 删除 CreatedAt 早于 createdBefore 或 LastSeenAt 早于 seenBefore 的会话，返回删除数量。
	DeleteExpired(ctx context.Context, createdBefore, seenBefore time.Time) (int, error)
}
