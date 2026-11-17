// Package auth 是嵌入业务进程的鉴权与授权库：服务端会话、双 token、权限码 RBAC。
//
// 库只管“登录状态”和“权限判断”：账号表、账号密码校验、登录限流属于使用方，
// Login 只接收已经验证过的账号 ID。存储可换（内存、数据库、Valkey），
// 所有实现都须通过 storetest 一致性测试。
package auth
