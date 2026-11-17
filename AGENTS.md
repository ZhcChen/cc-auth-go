## 项目说明

- 本仓库是公开的 Go 库 `github.com/ZhcChen/cc-auth-go`：嵌入业务进程的鉴权与授权组件（服务端会话、双 token、权限码 RBAC、密码哈希）。体验参考 Sa-Token：一行登录、一行校验、一行判权限；但保持小而简单。
- 库**不管账号表、不校验账号密码、不做登录限流**：这些属于使用方。库只管“登录状态”和“权限判断”，`Login` 只接收已经验证过的账号 ID。
- 使用方目前是 keel 模板（worker 运维账号、api 后台账号）。库内不得出现任何具体公司、项目或业务名称，也不得依赖使用方的代码。

## 文档位置

- 设计、取舍、计划、复核记录全部放 Obsidian `我的/项目/cc-auth-go/`（`README.md` 为索引；架构设计在 `10-项目文档/02-规格与架构/架构设计.md`）。仓库只有一份面向 GitHub 访客的简短 `README.md`（定位、安装、包一览，不写设计与用法细节），不新增 docs；其余只保留本文件、`doc.go` 包文档与代码注释（对外说明以 pkg.go.dev 显示的包文档为准）。
- 修改公共 API 或安全语义前，先读架构设计并同步更新；设计与代码不一致时以确认过的设计为准，先讨论再改。

## 目录与依赖

- 仓库根目录：核心包 `auth`（导入路径即 module 路径 `github.com/ZhcChen/cc-auth-go`）。Realm（账号体系）、Session、Store 接口、权限码通配匹配、`net/http` 中间件。**只依赖标准库。**
- `password/`：argon2id 哈希与校验。只依赖标准库与 `golang.org/x/crypto`。
- `memstore/`：内存存储（测试与单进程）。只依赖标准库。
- `storetest/`：存储一致性测试套件，任何 Store 实现（含使用方自己的数据库实现）都用它验证。只依赖标准库。
- `ginauth/`：Gin 适配，**独立 go module**（`github.com/ZhcChen/cc-auth-go/ginauth`），只做对 `net/http` 中间件的薄包装。
- `valkeystore/`：Valkey 存储，**独立 go module**，依赖 Valkey 官方 Go 客户端。
- 根 module 的 `go.mod` 只允许 `golang.org/x/crypto`（及其间接依赖）。新增依赖须先在设计中说明理由。
- 缓存产品在代码、注释、测试名中一律写 Valkey，不写其他同类产品名称。

## 代码规则

- 注释、错误说明使用简体中文；标识符、包名使用英文。导出标识符必须有文档注释。
- 安全：
  - 随机数只用 `crypto/rand`；令牌比较只用 `crypto/subtle`。
  - 令牌明文只在签发时返回一次，存储里只存哈希；日志、错误、事件中不得出现令牌、密码或哈希值。
  - 不写死时间：一律通过 `Options.Now` 取当前时间，便于测试。
  - 过期判断按“事实时间 + 当前配置”计算，不在存储里写过期时刻（存储侧 TTL 只作为清理兜底）。
- 配置零值可用：所有时长、数量的零值都表示“用缺省值”，缺省值集中定义并有注释说明理由。
- 错误用导出的哨兵错误（`ErrNotFound`、`ErrExpired`、`ErrKicked` 等），调用方用 `errors.Is` 判断。
- 公共 API 遵循语义化版本：v0 阶段允许不兼容变更，但须在提交说明中写明；v1 之后不兼容变更只进下一个主版本。
- 新功能必须同时有测试；Store 相关行为必须进 `storetest`，让所有实现一起受约束。

## Git

- 任务开始先执行 `git status --short --branch`，保留已有改动。
- 默认分支 `main`；较大改动用 `dev/<主题>` 分支。
- 任务完成并通过相应检查后，精确暂存相关路径并提交；提交说明首行为“类型: 中文说明”，类型取 feat、fix、docs、chore、refactor、test、perf、build、ci、style、revert。
- 对话结束前，将已完成的提交推送到当前分支对应远端。
- 不使用 `--no-verify`，不做 `reset --hard`、`clean`、强制推送。

## 开发与验证

- 本机只做编辑、格式化和纯文本检查；不在本机执行 `go build`、`go test`、`go mod tidy`。
- 检查与测试在远端开发主机 qfy-test2 运行：`make test`（格式、`go mod tidy -diff`、vet、单元、竞态）、`make bench`（基准）、`make tidy`（远端 `go mod tidy` 并取回 `go.mod`、`go.sum`）。实现见 `scripts/dev/remote.sh`：同步工作区到 `/opt/qfy-dev/<库名>/<分支键>/`，用一次性容器执行，只接入 `dev-shared-network`，不发布端口，同一分支串行。不使用 GitHub Actions。
- `go.mod`、`go.sum` 只用 `make tidy` 生成，不手编。
- 汇报验证结果时区分通过、失败、跳过、未覆盖；没跑过的写“未验证”。

## 发布

- 用 Git 标签发布（`vX.Y.Z`）；使用方接入调试期间用预发布标签（`v0.1.0-alpha.N`）。
- 打标签前 `make test` 必须通过；独立 module 的标签带目录前缀（如 `ginauth/v0.1.0`）。
- 标签一经推送不得删除或移动；有问题发新版本。
