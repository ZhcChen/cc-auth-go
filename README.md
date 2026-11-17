# cc-auth-go

[![test](https://github.com/ZhcChen/cc-auth-go/actions/workflows/test.yml/badge.svg)](https://github.com/ZhcChen/cc-auth-go/actions/workflows/test.yml)

嵌入业务进程的 Go 鉴权与授权库：服务端会话、双 token（刷新轮换与重放检测）、权限码 RBAC（通配匹配）、argon2id 密码哈希。存储可换（内存、数据库、Valkey），核心只依赖标准库。

库只管“登录状态”和“权限判断”；账号表、账号密码校验、登录限流由使用方负责，`Login` 只接收已经验证过的账号 ID。

> 开发中，尚未发布版本，API 可能变化。
