package auth

import (
	"context"
	"time"
)

// EventType 是事件类型。
type EventType string

// 事件类型。
const (
	EventLogin         EventType = "login"
	EventLogout        EventType = "logout"
	EventKicked        EventType = "kicked"         // 强制下线；SessionID 为空表示整个账号
	EventReplaced      EventType = "replaced"       // 被新的登录顶替
	EventRefreshReused EventType = "refresh_reused" // 刷新令牌重放，会话已吊销
	EventElevated      EventType = "elevated"       // 二次验证通过
)

// Event 是鉴权事件。不含令牌。
type Event struct {
	Type      EventType
	Realm     string
	Subject   string
	SessionID string
	Device    string
	IP        string
	At        time.Time
}

// Listener 接收事件。同步调用，尽力而为：监听器的 panic 会被吞掉，不影响主流程。
// 需要可靠审计的操作应由使用方在自己的事务里记录。
type Listener interface {
	OnEvent(ctx context.Context, e Event)
}

// ListenerFunc 让普通函数实现 Listener。
type ListenerFunc func(ctx context.Context, e Event)

// OnEvent 调用 f。
func (f ListenerFunc) OnEvent(ctx context.Context, e Event) { f(ctx, e) }

func (r *Realm) emit(ctx context.Context, e Event) {
	if r.opt.Listener == nil {
		return
	}
	e.Realm = r.name
	defer func() { _ = recover() }()
	r.opt.Listener.OnEvent(ctx, e)
}
