# v-local-key-provider 审计日志

> 本文是非规范性的时点记录。运行时契约、目标态和当前能力门禁以 [`KEY_ACQUISITION_AGENT_ORCHESTRATION.md`](KEY_ACQUISITION_AGENT_ORCHESTRATION.md) 为唯一依据；旧方案迁移 provenance 见 [`MIGRATION_FROM_LEGACY.md`](MIGRATION_FROM_LEGACY.md)。

审计条目按时间倒序记录。每条结论只对其标明的代码基线成立；后续复核可以取代旧结论，但不得静默改写历史。

## 2026-08-27 PR #3 跨平台集成门禁修复

迁移基线 `8124ca3` 推送后，首轮远端 Audit gates 暴露了两个本地环境未覆盖的跨平台问题；竞态与依赖漏洞门禁同时通过。修复不改变 Provider 能力声明或发布证据状态。

- macOS runner 的 SIP 实际为 disabled，root 的 discovery-budget 测试因此被更高优先级的 SIP 恢复规则接管。测试现在通过既有 `PlatformDriver` seam 注入中性平台诊断，只验证其声明拥有的发现超时行为；生产 outcome 顺序和 SIP fail-closed 恢复纪律保持不变。
- Windows runner 的系统临时目录使用 8.3 短路径，`realpath` 返回长路径后被 npm installer 的文本比较误判为 junction。安装目录验证现在逐级 `lstat` 实际祖先和每个新建层级，仍拒绝 symlink/junction，同时不把同一目录的短名/长名别名伪装成 reparse evidence。
- 修复后 Windows 定向 discovery-budget 测试、WSL `go test -count=1 ./...` 和 Provider npm 13/13 均通过；最终远端状态以 PR #3 的新提交 checks 为准。

## 2026-08-26 D-1 workflow/package migration completion

本轮从 `f780f76` 之后多次中断的工作树继续。每次先核对未提交 diff、编译引用和 owner tests，再按独立 commit 收尾；没有发现留在生产路径中的半写函数。工作集中在通用 workflow 的最后四个 root owner，并未改写任何 Phase 3/4 真机能力或 Phase 5 发布声明。

### 实际迁移结果

- `a2d6095` 将 prepare/observe/finalize/cancel、增量 acquisition、响应组装和 session runtime 移入 `internal/session`；根 `session_workflow.go`、`session_response.go`、`session_acquire.go` 删除。
- `8354923` 将 coverage/classification、Darwin Shadow/SIP fallback、single outcome finalization 和稳定 platform defaults 移入 `internal/diagnostics`。session 直接消费 owner finalizer，不再通过 root callback；旧 `diagnostic_finalize.go` 删除。
- `1550174` 建立共享 `internal/acquisition.Options`、path/scope/catalog-key parser 和 one-shot workflow。session 通过类型 alias 复用同一 DTO；旧 root `acquisition.go` 删除，catalog-key ownership、discovery timing、platform request、account binding 和 final response assembly 均有内部 owner tests。
- `4cad6f0` 新增 `internal/command`，拥有平台无关的 one-shot 与 security-posture revalidation；secret publication policy 从 session 提升到 `internal/protocol`，one-shot/session 使用同一 fail-closed 决策。
- `0bc98b6` 把 finalizer、outcome、scope coverage 和 publication policy 的重复 root/session 测试迁到 package owner，删除只为旧测试存在的 facade。根 `phase_regression_test.go` 只保留真正的 root catalog integration regression。
- 架构回归现在同时约束 daemon、session、diagnostics、acquisition、command/protocol publication 及 Darwin/Windows 实现边界，禁止内部 package 反向 import Provider 或 workflow 回流 root。根目录生产 Go 文件从审查起点 93 个降为 51 个；最新切片由 56 个降为 51 个。

### 根目录保留判定

不继续为追求“零根文件”机械搬运。51 个文件只允许属于两类：

1. command wiring、schema alias、runtime/policy callback 注入与薄 `*_adapter.go`；
2. build-tagged caller/runtime trust、签名、路径/file identity、crash hardening、helper/daemon launch 与 OS 原生边界。

`TestProviderRootProductionFilesStayOnCompositionAllowlist` 使用完整 manifest 阻止新增平铺文件；有意新增或删除边界必须在同一变更中解释并更新测试。通用 DTO、状态机、finalizer、响应 publication、平台 acquisition/hook/native scan 均不得回流 root。

### 本轮阶段验证

| 检查 | 结果 |
| --- | --- |
| Windows 原生 | `internal/platform/windows`、diagnostics/acquisition/command/protocol/session 全部 `-count=1` 执行通过；`go vet ./...` 与 `go build ./...` 通过。宿主 App Control 仍会随机阻止新生成的 root 测试 EXE，因此 root 的最终实际执行由 WSL 全包矩阵承担；Windows 编译与此前受影响 root 测试均已通过，不把被策略拦截的启动冒充断言结果。 |
| WSL Go | 原生 `/tmp`/Go cache 下 `go test -count=1 ./...`、`go vet ./...`、`go test -race -count=1 ./...` 全包通过，覆盖新增 workflow、publication policy 和 root architecture manifest。 |
| build tags | `CGO_ENABLED=0 go build ./...` 在 Windows/macOS/Linux 的 amd64、arm64 共六组目标全部通过。Darwin CGO-disabled 只验证 fallback/build-tag 边界，不冒充 Mach/LLDB cgo 编译或真机执行。 |
| npm | Provider installer/候选与 promotion manifest/双架构资产/固定目录/下载与回滚测试 13/13 通过。 |
| 静态 | `gofmt`、`git diff --check`、owner import boundary、旧 facade/旧根文件禁止项与 root allowlist 通过。 |

以上通用检查不解除空生产 registry、Windows x64/ARM64 candidate evidence、Darwin Intel/Apple Silicon cgo/Mach/LLDB 真机、最终签名/notarization、外部 promotion 或 Trusted Publishing 门禁。

## 2026-08-25 D-1 Darwin hook / evidence 平台垂直切片续作

本轮从 Darwin Mach 切片提交 `4261435` 的干净工作树继续，核对两次中断均未留下半写文件后，迁移剩余 dynamic LLDB hook、目标 binary evidence 与 session process fingerprint；没有改写 Phase 3 能力声明或 Phase 5 发布门禁。

### 实际迁移结果

- `internal/platform/darwin.EvidenceCollector` 现在统一拥有 PID-bound executable 解析、bundle version/build、目标实际架构与 Rosetta 状态、macOS 版本、codesign Team ID/designated requirement、可执行文件 fingerprint、prelaunch target 选择及稳定 process instance ID。Provider 根只注入 daemon 的 PID image resolver、有界命令、路径安全/canonical policy、可执行文件摘要和敏感缓冲清理。
- `internal/platform/darwin.HookDriver` 现在拥有 direct/wait-for LLDB capture、临时脚本权限与清理、同版本 watchdog/liveness FD、进程组有界终止、断点 readiness、捕获 PID 与 binary evidence 重验证、PBKDF/raw-key 候选消费、persistent session 合并/关闭以及超时后的目标恢复。平台专属 signal/process-group 原语隔离在 `hook_process_darwin.go`；通用生命周期和 owner tests 可在非 macOS runner 编译执行。
- 原根 `platform_darwin_hook.go`、`session_process_darwin.go`、`darwin_hook_protocol_adapter.go`、`darwin_process_policy_adapter.go` 及重复 owner test 已删除，不保留双实现。`platform_darwin.go` 是 74 行 composition adapter，集中构造 evidence/native/hook runtime 并注入 release registry/policy、SIP 与敏感内存机制。
- 架构回归会阻止上述旧根文件复活，要求 Mach、evidence、LLDB lifecycle/protocol 均留在 `internal/platform/darwin`，并继续禁止内部包反向 import Provider。root 生产 Go 文件由 60 个降至 56 个，根测试由 24 个降至 23 个；`internal/platform/darwin` 由 8 个生产文件/4 个测试文件增至 13 个生产文件/6 个测试文件。
- 新 owner tests 覆盖 bundle 空格路径、证据采集策略、resolved breakpoint/Weixin wait-for、capture 必须绑定 PID、rounds=2 XOR-salt raw key、无关 PBKDF 拒绝、输出上限/清零、snapshot 合并与 watchdog 参数 fail-closed。迁移中测试发现并修正了内部敏感输出缓冲 fallback 的长度分配错误；生产注入路径未使用该 fallback，但现在两条路径都受回归约束。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Windows 原生 | 固定工作区 Go cache/temp 下 `go test ./... -count=1` 全包通过；`go vet ./...` 通过；root 与内部 Darwin 测试二进制编译检查通过。 |
| WSL Go | 原生私有 `/tmp` 下 `go test ./... -count=1`、`go vet ./...`、`go test -race ./... -count=1` 全包通过。首次误把 `TMPDIR` 放到 `/mnt/d` 时 daemon 私有目录测试按设计拒绝 NTFS 权限语义，改用原生 `/tmp` 后全绿，不把环境失败计为通过。 |
| build tags / 静态 CGO | Darwin amd64/arm64（`CGO_ENABLED=0`）与 Windows/ARM64 全包构建通过；Darwin amd64/arm64 `CGO_ENABLED=1 go list` 无 package error，arm64 清单确认 `native_memory_darwin.go` 是唯一 CGO 文件，其余 evidence/hook/Mach orchestration 均作为普通 Go 文件归属内部包。该检查不是 macOS CGO 编译或 LLDB/Mach 真机执行。 |
| npm / 静态 | Provider npm 13/13 通过；`git diff --check`、格式、旧根实现/原生 primitive、内部反向依赖与固定 subprocess policy 回归通过。 |

这次切片完成了当前已知的 Darwin acquisition/hook 平台实现下沉，但不解除空生产 registry、Intel/Apple Silicon CGO runner、Mach/LLDB 授权真机 acquisition、最终签名件、notarization 或 Trusted Publishing 门禁。目录所有权与 mock/race 结果不得冒充 macOS 真机能力证据。

## 2026-08-25 D-1 Darwin Mach 平台垂直切片续作

本轮以 Windows 平台切片提交 `6b9a5b7` 为起点，迁移 Darwin acquisition pipeline、进程发现与 Mach 只读内存实现；没有改写 Phase 3 能力声明或 Phase 5 发布门禁。

### 实际迁移结果

- `internal/platform/darwin` 现在拥有 acquisition driver、线性 hook/refresh/static/finalize/assemble pipeline、`ps -> launchctl` 有界进程发现、进程/native seam、Mach task-port 生命周期、虚拟内存区域遍历与进程隔离 collector。fake `NativeDriver` 可在非 Darwin runner 上验证编排、扫描生命周期和 registry 深拷贝。
- 根 `platform_darwin.go` 从 613 行实现收敛为 58 行 composition adapter，只注入 acquisition runtime、发布 registry/policy、受限命令执行器、代码身份/摘要证据、动态 hook、SIP 状态与敏感内存回调。旧 `darwinAcquisitionPipeline`、`scanDarwinProcess` 和根层 `task_for_pid`/`mach_vm_*` 实现已删除，不保留双实现。
- Mach 扫描的 read buffer、完整 tail backing storage 与每个 combined chunk 现在都登记为敏感内存，并在退出或每轮消费后清零；tail 使用完整 backing storage 登记后再建立零长度视图，避免只清理当前长度。
- 原根 `platform_darwin_test.go` 中重复的 process parser 测试由内部 owner 覆盖，唯一的 bundle 空格路径回归迁入 hook 测试；根测试由 25 个降至 24 个。`internal/platform/darwin` 由 3 个生产文件/2 个测试文件增至 8 个生产文件/4 个测试文件。
- 动态 LLDB hook、目标 binary evidence 采集及 session process fingerprint 仍为 build-tagged 根实现，本轮通过 callback 接入内部 driver；`platform_darwin_hook.go` 由 912 行降至 863 行。它们是下一独立切片，不把本次 Mach/pipeline 迁移误报为整个 Darwin God-file 已清零。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Windows 原生 | 固定工作区 Go cache/temp 下 `go test -count=1 ./...` 全包通过；`go vet ./...` 通过。 |
| WSL Go | 原生 `/tmp` 下 `go test -race ./...` 全包通过；包含可移植 fake Darwin `NativeDriver` 编排回归。 |
| build tags / 静态 CGO | Darwin amd64/arm64（`CGO_ENABLED=0`）与 Windows/ARM64 全包构建通过；Darwin/arm64 `CGO_ENABLED=1 go list` 将 `native_memory_darwin.go` 识别为唯一内部 CGO 文件且无 invalid Go file。后者只是 build-tag/语法解析，不是 CGO 编译或 Mach 执行。 |
| npm / 静态 | Provider npm 13/13；`git diff --check`、受控 `gofmt -l`、根适配器 native primitive 扫描和内部反向依赖扫描通过。 |

这次切片没有解除空生产 registry、Darwin amd64/arm64 CGO runner、Mach 真机 acquisition、签名/notarization、最终发布件或 Trusted Publishing 门禁。提交可证明通用编排与所有权边界，但不得作为 macOS 真机正确性证据。

## 2026-08-25 D-1 Windows 原生平台垂直切片续作

本轮以 acquisition 切片提交 `7dd3607` 为起点，落实上一节约定的 process/memory driver seam，并选择 Windows 一侧整体迁移；没有改写 Phase 0-5 的能力或发布门禁。

### 实际迁移结果

- `internal/platform/windows` 现在统一拥有 Windows acquisition 编排、进程模型与稳定实例 ID、Toolhelp 发现、进程句柄生命周期、可执行文件版本/产品证据、账号路径绑定、Config.Cipher 模块扫描以及分阶段虚拟内存扫描。`NativeDriver` 把进程/内存输入输出从平台编排中隔离，可用 fake driver 在非 Windows runner 上验证。
- 根 `windows_acquisition_windows.go` 从 345 行实现收敛为 29 行 composition adapter，只注入 acquisition runtime、发布 registry/policy、安全可执行文件哈希、WinTrust primary signer 证据与敏感内存回调。原 `windows_binary_evidence_windows.go`、`windows_config_cipher_windows.go`、`windows_memory_scan_windows.go`、`windows_process_binding_windows.go`、两个对应 policy adapter 及 `session_process_windows.go` 已删除，不保留双实现。
- missing-required Catalog 规则进入 `internal/catalog`，missing-only page 与 profile-compatible target subset 由 `internal/acquisition` 组装，session 与 Windows driver 共用同一过滤语义。Windows 平台测试跟随实现迁入内部包；新增架构回归，禁止原生 handle/memory 实现回流根适配器或内部包反向 import Provider。
- 扫描重叠 tail 改为先登记完整 backing storage，再使用零长度视图；Config.Cipher 与通用 memory stage 都会在退出时清零并解除完整 storage 的敏感内存跟踪。
- 根目录生产 Go 文件由 67 个降至 60 个，根测试由 26 个降至 25 个；`internal/platform/windows` 现包含 11 个生产文件与 6 个测试文件。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Windows 原生 | 固定工作区 Go cache/temp 下 `go test ./...` 全包通过；`go vet ./...` 通过。首次使用新的临时目录时有一个测试二进制被宿主 Application Control 拒绝，改回此前已验证的固定目录后全绿，不是断言或编译失败。 |
| WSL Go | 原生 `/tmp` 下 `go test ./...` 与 `go test -race ./...` 全包通过；包含可移植 fake `NativeDriver` 编排回归。 |
| 跨平台 build tags | Darwin amd64/arm64（`CGO_ENABLED=0`）与 Windows/ARM64 全包构建通过；仍只是编译检查，不冒充 Darwin cgo 或真机执行。 |
| npm / 静态 | Provider npm 13/13；`git diff --check`、受控 `gofmt -l`、根适配器 native primitive 扫描和内部反向依赖扫描通过。 |

这次切片没有解除空生产 registry、Windows 真机 candidate evidence、Darwin cgo/真机、最终签名件、notarization 或 Trusted Publishing 门禁。若继续降低根目录密度，下一步应对 Darwin 做同样的原生平台垂直切片；由于其 Mach/cgo 路径不能由无 cgo 交叉编译替代，提交前仍须明确保留 Darwin cgo runner/真机门禁。

## 2026-08-25 D-1 acquisition 垂直切片续作

本轮以 daemon 切片提交 `b2677f0` 为起点，落实上一节约定的 `internal/acquisition` 模型与 platform driver seam；没有改写 Phase 0-5 的能力门禁。

### 实际迁移结果

- 新增 `internal/acquisition`，统一拥有 database targets/page、media evidence、candidate collector、模式与盐邻域扫描、数据库/媒体验证、passphrase/KDF 调度、credential 组装、database/media discovery，以及同步 platform session。原 root `candidate_collector.go`、`candidate_patterns.go`、`database_validator.go`、`media_validator.go`、`discovery.go` 已删除，不保留双实现。
- collector 的 profile registry、敏感内存登记/清零/克隆和 opaque ID 生成由 `Runtime` 注入；database discovery 的 file identity、link/reparse 与 canonical path policy 仍由进程边界注入。`internal/acquisition` 不 import Provider 根包。
- 收尾回归确认显式非 nil 空 profile registry 不会在归一化或隔离 collector 时恢复默认值；XOR 变换中因重复或上限被丢弃的已登记临时缓冲区也会立即清零。
- Darwin/Windows 平台代码不再读取 collector 私有字段，只通过目标绑定验证、扫描、隔离 collector、已验真合并、诊断快照和 credential 组装方法交互。Darwin rounds=2 PBKDF 证据的 XOR-salt/profile 验证也进入 acquisition 所有者，避免平台层平行实现 raw-key 验证。
- `PlatformDriver`/`PlatformRequest` 成为 one-shot 与增量 session 的共同入口；build-tagged `platformAcquire` 只由单一 root adapter 调用。新增可替换 driver 回归，证明 prepared acquisition 不会绕过 seam。
- collector/discovery/validator/credential/page-header 的单测、benchmark 与 fuzz 跟随所有者迁入 `internal/acquisition` 或 `internal/crypto`。根目录生产 Go 文件由 71 个降至 67 个，根测试由 32 个降至 26 个；新增包含 10 个生产文件与 8 个测试文件。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Windows 原生 | 固定工作区 Go cache/temp 下 `go test ./...` 全包通过；`go vet ./...` 通过。 |
| WSL Go | 原生 `/tmp` 下 `go test ./...` 与 `go test -race ./...` 全包通过。首次把 Go temp 放在 NTFS 挂载目录时，daemon 的 Unix owner/mode 回归按设计拒绝该目录；这不是代码断言回归。 |
| 跨平台 build tags | Darwin amd64/arm64（`CGO_ENABLED=0`）与 Windows/ARM64 全包构建通过；仍只是编译检查，不冒充 Darwin cgo 或真机执行。 |
| npm / 静态 | Provider npm 13/13；`git diff --check`、受控 `gofmt -l` 与 seam/私有字段依赖扫描通过。 |

这次切片没有解除空生产 registry、Darwin cgo/真机、最终签名件、notarization 或 Trusted Publishing 门禁。若继续降低根目录密度，下一步应以完整原生平台垂直切片推进：先定义 process/memory driver 输入输出，再选择 Windows 或 Darwin 一侧整体迁移；不应继续搬零散 adapter 或仅为减少文件数改名。

## 2026-08-25 D-1 daemon 垂直切片续作

本轮以本地全绿 checkpoint `c71cc37`（`refactor: complete phase 0-5 review checkpoint`）为起点。审计落款写入前的代码 tree 为 `22cf0c10f220ea0ba4a341d55ffa0ea9c341c480`（183 个非忽略文件）；其后只追加本节记录，没有再修改生产代码或测试。

### 实际迁移结果

- 新增 `internal/daemon`，统一拥有 daemon 命令帧、endpoint 发布与清理、连接认证时限、server idle/shutdown 生命周期、stdio 入口、Darwin Unix socket、Windows named pipe、peer PID/用户/进程镜像读取，以及 Unix owner/mode 和 Windows owner/DACL 校验。
- root `daemon_adapter.go` 只注入 session backend、runtime component 身份、release CLI 信任、link/reparse 与 canonical path policy、敏感内存登记/清零；`internal/daemon` 不 import Provider 根包，也不认识 `acquisitionSessionStore`、`candidateCollector`、`databaseTargets` 或 `acquireOptions`。
- Provider 的 session store 通过窄 `Backend` 函数字段注入，具体类型保持私有；helper role 在创建 backend 之前完成 runtime identity 复核。Darwin/Windows one-shot 与 hook 调用方改用 daemon 包拥有的进程镜像查询，不保留平行 native 实现。
- 根目录生产 Go 文件由 78 个降至 71 个；daemon 生产文件由 10 个完整实现收敛为 `daemon_adapter.go` 与两个 build-tagged helper launch wiring 文件。新增架构回归，禁止 daemon server/transport/security 实现重新回流根目录或 `internal/daemon` 反向 import Provider。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| WSL Go | `go test ./... -count=1`、`go vet ./...` 全包通过。 |
| race | `go test -race ./internal/daemon ./internal/session . -count=1` 通过。 |
| Windows 原生 | 固定工作区路径生成并运行 root 与 `internal/daemon` 测试二进制，均 `PASS`；`go vet ./...` 通过。首次由系统 Temp 执行 daemon 测试时被 Application Control 拦截，固定路径复验排除了断言失败。 |
| 跨平台 build tags | Darwin amd64/arm64（`CGO_ENABLED=0`）与 Windows/ARM64 全包编译通过；这是编译检查，不冒充 Darwin cgo 或真实目标执行。 |
| npm / 静态 | Provider npm 13/13；`gofmt -l`、`git diff --check` 与架构依赖检查通过。 |

这次结构续作不解除空生产 registry、Darwin cgo/真机、最终签名件、notarization 或 Trusted Publishing 门禁。下一轮如继续收敛根目录，应先建立 `internal/acquisition` 的模型与 platform driver seam，再整体迁移 collector/discovery/validator；不得按单文件搬迁制造新的 root adapter 网。

## 2026-08-25 D-1 最终 wiring 与 native 边界续作

本节取代下一节“尚未迁移的边界”现状判断，但保留其第二阶段历史记录。

本节最终验证落款写入前的完整工作树快照为 Provider tree `acfb94655980f883c857dc60199d73c7a126a982`（177 个非忽略文件），契约对端 CLI 仍为 tree `4a41fd9fc0ad7b886732c2395750dfa41768b040`（191 个非忽略文件）。两者均由临时 Git index 纳入未追踪文件生成，真实 index 保持不变；生成后只追加本段落款，没有再修改生产代码、测试、workflow 或发布文档。

### 本轮完成项

- `internal/releaseevidence` 现在拥有 promotion/evidence 严格 JSON、内容寻址、候选 Provider/helper 摘要绑定和 eligible registry 全覆盖验证；原 `release_contract_test.go` 中 340 多行自成一套的验证实现已删除，签名构建门禁通过 root 投影调用同一生产验证器。
- `internal/session` 现在拥有 session record/store、过期清理、账号互斥、receipt/retry 原子转换、begin/commit/delete 与敏感状态清理。root workflow 只接收深拷贝快照；并发 cancel 不再能清空仍被进行中请求引用的 live record，新增竞态边界回归。
- `internal/platform/windows` 新增进程主从/绑定排序、内存区域与 fallback stage 策略，并实际持有 `VirtualQueryEx`/`ReadProcessMemory` 的有界遍历、分块重叠和敏感缓冲清理；root 只注入 deadline 与候选 collector 回调。`internal/platform/darwin` 新增 `ps`/`launchctl` 进程发现解析，避免纯解析逻辑被 cgo build tag 隔离。
- 仓库根包已由 `main` 改为可导入、可测试的 `provider`，原 `main.go`/`main_test.go` 按领域改为 `command.go`/`command_test.go`；唯一 `package main` 位于 `cmd/v-local-key-provider`。Windows/macOS builder、普通 CI 和 README 均改为构建该命令路径。
- linker 信任标记仍注入命令包的 `main.buildMode`、`main.releaseSignerSHA256`、`main.releasePromotionSHA256`，再通过 `BuildConfig` 显式传给 Provider；本轮用注入后的 `main.version=cmd-wiring-test` 实际构建并运行 `--version`，确认入口移动没有让 `-X main.*` 静默失效。

### 仍保留的原生边界

- Darwin `task_for_pid`/Mach region read、LLDB 进程控制和 helper 原生生命周期仍是 `darwin && cgo` Provider adapter；Windows 仍有进程句柄打开、模块/handle 枚举和目标二进制 TOCTOU 复核 adapter。它们直接持有 OS/cgo 类型，只有在对应 Intel/Apple Silicon/Windows runner 可编译并运行时才适合继续物理下沉。
- 因此 D-1 的推荐领域目录和最终 command wiring 已落地，但“所有 native adapter 均位于 internal 子包”仍不能记为完成。D-2 已完成：生产文件不存在 `phase3_`/`phase4_` 前缀，根命令文件也不再沿用含混的 `main.go` 名称。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Provider WSL `go test ./... -count=1` / `go vet ./...` | 全包通过，包含新增 `internal/releaseevidence`、session store、Darwin process discovery 和 Windows memory policy 测试。 |
| session race | WSL `go test -race ./internal/session . -count=1` 通过。 |
| cmd/linker/cross-build | 注入 `main.version` 的命令实跑通过；Windows/ARM64、Darwin/ARM64 nocgo command 构建通过；Windows/amd64 root/internal 测试二进制及 candidate command 交叉编译通过。交叉编译不冒充 Windows/Darwin 真机执行。 |
| CLI 契约 | WSL 私有 umask 下 `go test ./... -count=1` 与 `go vet ./...` 通过。 |
| npm / 静态门禁 | Provider 13/13、CLI 12/12；PowerShell AST、`build-macos.sh` 语法、4 份 workflow YAML 和 `git diff --check` 通过。 |

上述结构迁移不解除空生产 registry、Darwin cgo/四架构真机、最终签名件、notarization 或 Trusted Publishing 门禁。

## 2026-08-25 D-1/D-2 第二阶段实施与复核

本节取代下一节“D-1 / D-2 状态”中的第一阶段现状判断，但不改写其当时记录。

本节最终验证落款写入前的完整工作树快照为 Provider tree `0ca576b7ccd6f7c3eff7d9a33203606c91367de3`（163 个非忽略文件），契约对端 CLI tree `4a41fd9fc0ad7b886732c2395750dfa41768b040`（191 个非忽略文件）。两者均用临时 Git index 纳入未追踪文件生成，真实 index 保持不变；生成后只追加本段审计落款，没有再修改生产代码、测试、workflow 或发布文档。

### 实际迁移结果

- `internal/protocol` 现在同时拥有 request/response v1 wire DTO、严格 JSON 解码和 workflow 不变量；transport 验证得到的 `PeerIdentity` 使用 `json:"-"`，不能从请求体注入。root 只保留名称兼容适配。
- 原 `internal/cryptokdf` 已合并为 `internal/crypto`，profile registry 模型、PBKDF2-HMAC-SHA512、首页解密和 HMAC 验证只有一个实现；root 注入 deadline/cancellation 与敏感内存登记/清零回调。旧空目录已移除。
- `internal/catalog` 拥有 catalog DTO、分类、内容标识和安全遍历；文件身份、reparse/link 判断与平台路径规范作为 fail-closed policy 注入。`internal/credential` 拥有结构化凭据 DTO、multi-salt root promotion、override 与进程实例证据策略。
- `internal/diagnostics` 拥有唯一 schema、穷尽 merge policy 和 19 条有序 outcome 规则；`internal/session` 拥有 action receipt 机器状态绑定、有限重试、missing-catalog rebinding、结果/credential 合并与 secret publication policy。
- `internal/platform` 拥有共享 hook evidence；Darwin 包除 route registry 外，新增可跨平台测试的 LLDB 脚本/输出协议；Windows 包新增 `Config.Cipher` 有界解析和 observed-path 账号绑定策略。native attach、进程句柄和内存读取仍由 build-tagged root adapter 掌握。
- root 编排文件已按领域拆分：`main.go` 只保留命令入口与协议写出（188 行），acquisition/diagnostic finalize、session store/workflow/acquire/response、candidate collector/pattern/database/media validator、Windows acquisition/memory scan 分文件。生产文件中不再存在 `phase3_`/`phase4_` 前缀；D-2 已完成。

### 尚未迁移的边界

- D-1 仍不能记为“全部完成”：`acquisitionSessionStore` 的并发编排、Darwin cgo attach/native scan、Windows handle/native scan 和最终 `cmd/v-local-key-provider` wiring 仍在 root `main` 包；release evidence validator 也尚未成为 `internal/releaseevidence` 生产包。
- 这些剩余项直接持有 OS handle、cgo 类型、敏感 collector 或长事务锁。继续下沉需要先把 native callback/interface 变成不反向依赖 command 的窄接口，并在 Darwin Intel/Apple Silicon cgo runner 上验证；目录移动本身不能替代该证据。

### 第二阶段验证

| 检查 | 结果 |
| --- | --- |
| Provider WSL `go test ./... -count=1` / `go vet ./...` | 全包通过，包含新增的 catalog/credential/crypto/diagnostics/platform/protocol/session 包。 |
| Provider Windows 原生 | 本轮较早的全量测试通过；Windows acquisition/memory 拆分后的定向测试及后续 main/diagnostics 定向测试通过。最终全量重跑时根 `.test.exe` 被宿主 Application Control 阻止；所有内部包仍通过，当前 `go vet ./...` 通过。该环境拒绝不是断言失败，也不记作最终 Windows 全量绿灯。 |
| Provider candidate / cross-build | 当前源码以 `-X main.buildMode=candidate` 成功构建 Windows/amd64（SHA-256 `bde8570b8b90e3050e2a09cd360db20f2a7bbcddec8d3c2f5cfb0669be286743`）；Windows/ARM64 与 Darwin/ARM64 nocgo `go build ./...` 通过。完整 `build.ps1 -Candidate` 的测试前置门在宿主 App Control 处停止。 |
| CLI Go 契约 | WSL `umask 077` 下 `go test ./... -count=1` 与 `go vet ./...` 全包通过；Windows/ARM64 cross-build 通过。首次未设私有 umask 的失败来自 checkpoint 目录权限契约，修正测试环境后消失。 |
| npm | Provider 13/13、CLI 12/12 通过。 |
| 静态门禁 | 4 份 workflow YAML 可解析；`build-macos.sh` 按 `.gitattributes` 规范为 LF 后通过 `/bin/sh -n`；PowerShell AST 与 `git diff --check` 通过。 |

上述结果不解除空生产 registry、Darwin cgo/四架构真机、最终签名件、notarization 或 Trusted Publishing 门禁。

## 2026-08-25 Phase 5 中断续审与 D-1/D-2 第一阶段实施

### 中断状态核对

- 本节验证落款写入前的完整工作树快照：Provider tree `73b39722af6354ca53f48db85eed7b63a78d21b9`；契约对端 CLI tree `4a41fd9fc0ad7b886732c2395750dfa41768b040`。两者均由临时 Git index 纳入全部非忽略文件后生成，不修改真实 index、不提交工作树；其后只追加本节的验证记录，没有再改生产代码、测试、workflow 或发布文档。
- 未发现被截断的 Go/JavaScript/PowerShell/shell/YAML 文件，也没有只写出声明、缺少调用方的语法级半成品。
- 中断点确有一个逻辑层面的未闭环项：旧发布链要求 evidence 绑定候选 Provider 摘要，却没有可信候选下载与来源验证，且把 evidence 摘要编回 registry 会形成 `binary -> evidence -> compiled binary` 自引用。下述外部 promotion 链已取代本日志稍后 B5-3 的“未解除”时点结论。
- 中断前的大量实现仍只在工作树中，未提交、未推送；本条结论只描述当前工作树，不把远端旧 HEAD 当成已验证实现。

### Phase 5 闭环结果

- `Release candidate` 以 `buildMode=candidate` 生成四目标 Provider/helper 集合及 `candidate-manifest.json`，精确绑定源码提交、workflow run id、固定资产名和 SHA-256，并生成 GitHub artifact attestation。
- `Phase 3-4 live regression` 按 run id 跨 workflow 下载该集合，校验全部候选摘要并执行 `gh attestation verify`；真机 runner 直接运行下载件，禁止本地重建，输出 schema v2 内容寻址 evidence。
- 外部 `compatibility-evidence/promotions/<release-tag>.json` 把四目标候选集合与 evidence 摘要绑定。签名 workflow 验证候选提交是 release tag 祖先，且候选之后只允许 `compatibility-evidence/**` 变化；随后按 promotion 的 run id 重新下载候选并以 signer workflow + source digest 复验全部资产 attestation。Windows/macOS builder 校验 promotion 后只把其 SHA-256 注入 release 二进制。
- release route 只有在编译期 promotion 摘要有效时才输出 `real_device_evidence_present + registry_exact_match + release_promotion_verified`；candidate route 只输出 `registry_candidate_entry + registry_exact_match`。CLI release build 会拒绝 candidate 标记，开发 CLI 则允许它用于受控真机验收。
- promotion 工具拒绝非普通文件、非内容寻址文件、重复 evidence、错来源提交/run、错 Provider/helper 摘要和缺目标；Go release gate继续严格核对 target identity、route、coverage、profiles 及 eligible registry 全覆盖。

### 本轮验证

| 检查 | 结果 |
| --- | --- |
| Provider `go test ./... -count=1` / `go vet ./...` | Ubuntu WSL（原生私有 `TMPDIR`）全量通过；包含新的 `internal/platform/darwin`、`internal/platform/windows` 包。Windows 本轮较早的全量与拆包后定向测试通过，最终重跑被宿主 Application Control 阻止新临时 `.test.exe`，沙箱外重试结果相同；不是断言失败。 |
| CLI `go test ./... -count=1` / `go vet ./...` | 全包通过。 |
| Provider npm `npm test` | 13/13 通过，包含候选清单、promotion、重复 evidence 负例。 |
| Windows candidate build | `scripts/build.ps1 -Candidate -Arch amd64` 通过；manifest 为 `candidate`，未伪报 evidence-ready/promotion。 |
| release 缺 promotion 负例 | Windows 与 macOS builder 均在签名或正式编译前 fail closed。 |
| 空生产 registry release gate | WSL 中按预期失败，并精确报告 `no complete candidate entry for target`。 |
| Windows/ARM64 与 Darwin/ARM64 nocgo cross-build | 通过；不冒充 Darwin cgo 或对应架构真机证据。 |
| PowerShell AST、`sh -n`、workflow YAML 解析、`git diff --check` | 通过。 |

这些自动化结果不解除空生产 registry、四架构真实目标验证、Darwin cgo 真机、最终签名 prerelease 干净机复验、notarization 或 Trusted Publishing 门禁。

### D-1 / D-2 状态

- D-2 的两个 Phase 编号文件已移除：根适配层统一为 `darwin_route_registry.go`、`windows_route_registry.go`，测试文件同步按领域命名。
- D-1 的平台 route registry 第一阶段已实际完成：纯策略分别迁入 `internal/platform/darwin/route_registry.go` 与 `internal/platform/windows/route_registry.go`；root 只注入 build mode、promotion readiness 和 profile registry，避免 internal 包反向依赖 `main`。
- Unix daemon 测试夹具现在显式把 endpoint 父目录设为 `0700`，endpoint 等待逻辑会直接报告 daemon 提前退出错误，不再把目录权限问题伪装成统一的 3 秒超时。
- D-1 整体仍是分阶段迁移，不得误报“全部完成”：`protocol/catalog/credential/session/diagnostics` 及 Darwin hook、Windows native collector 等剩余边界尚未迁移。安全发布修复与 90+ 文件大搬迁不应合并成一个不可审查改动；后续按本日志的六阶段映射逐包推进。

## 2026-08-25 Phase 0–5 深审（代码审查完成；外部发布门禁未解除）

### 审查基线

- 分支：`codex/release-readiness`。
- HEAD：`6e65e536ac25fddde202aa015eebd7e33a1157d5`。
- 完整工作树 tree：`a29d869d7fa7a33c7bb8640e87589db9bc43a5f7`。该 tree 由临时 Git index 生成，纳入全部非忽略文件，不移动、不清理且不提交工作树。
- 快照规模：119 个文件，其中 93 个 `.go`；HEAD 仅追踪 25 个 `.go`。
- 后续 `file:line` 发现均须绑定上述 tree；未绑定旧引用只视为历史线索。
- 契约对端 `v-local-cli`：HEAD `7263a744c6584a92325f1421356c3bd5e5ab77e6`；本轮契约修复后的完整工作树 tree `a7730900ca8405849b4c278a2f776cc5512edd3a`。

### 本机验证证据

| 检查 | 结果 | 解释 |
| --- | --- | --- |
| `go build ./...` | 通过（exit 0） | 使用仓库内已忽略的 `.codex-temp/audit-gocache`；默认用户级 cache 在沙箱内不可写。 |
| `go vet ./...` | 通过（exit 0） | 同上。 |
| `go test ./... -count=1` | 通过（exit 0） | 把 `GOCACHE` 与 `GOTMPDIR` 都放在工作区后，根包、`internal/cryptokdf`、`internal/workbudget` 全部通过；此前失败是用户 cache、系统临时目录与 App Control 的执行环境限制。该结果仍不替代 macOS 真机或 release evidence 门禁。 |
| Windows/ARM64 与 Darwin/ARM64 nocgo cross-build | 通过（exit 0） | `GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build ./...` 与 `GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build ./...` 均通过；后者不覆盖 Darwin cgo 路径。 |
| Provider npm `npm test` | 11/11 通过 | 覆盖固定下载域、独占 descriptor、固定安装目录、symlink/junction 拒绝、随机临时文件和 Provider/helper 集合回滚。 |
| CLI `go build ./...` / `go vet ./...` | 通过（exit 0） | 使用 CLI 仓库内独立 cache/temp；Windows/ARM64 cross-build 也通过。 |
| CLI `go test ./... -count=1` | 变更相关包通过；1 个环境阻断 | `internal/provider` 及其余已执行包通过；`internal/inbox` 测试二进制被本机 Application Control policy 拒绝执行，单包重试结果相同。该项不是测试断言失败，但不能记为全绿。 |
| CLI npm `npm test` | 12/12 通过 | 下载、摘要、安装目录、原子替换和 Skill 清单测试全部通过。 |
| 文档与脚本静态校验 | 通过 | 8 份 Markdown 的 fenced code block 与本地链接通过；PowerShell AST 与 Git `sh -n` 均通过；`git diff --check` 无 whitespace error。 |
| macOS cgo | 本机不可验证 | 必须在 Intel 与 Apple Silicon 对应 runner 编译并做授权真机验证。 |

当前 tree 尚未提交或推送，因此不能用远端 CI 验证这个精确快照；在此之前触发旧 HEAD 的 CI 不可作为替代证据。

### 当前能力门禁静态复核

| 门禁 | 当前代码证据 | 结论 |
| --- | --- | --- |
| Windows 生产 registry | `windowsCompatibilityRegistry` 是空切片 | 保持 `build_only`；不得读取目标进程内存或宣称支持。 |
| macOS 生产 registry / 真机 | `darwinCompatibilityRegistry` 是空切片；本机不能验证 cgo | 保持 `build_only` / 未验证。 |
| Shadow | `newDiagnostics` 与 macOS 路径默认 `unavailable_in_build` | 未实现，不得冒充 `attempted_failed` 或可用。 |
| cipher profile | `profileRegistry` 只有一个证据项，多 profile 仅有 fixture 回归 | 未获真实历史/迁移库证据前不得扩充生产声明。 |
| A1 包边界 | `internal/` 只有 `workbudget`、`cryptokdf` | catalog/session/platform 全量拆包未完成。 |

以上静态复核只确认门禁仍然关闭，不是解除门禁的正向证据。普通 CI、mock、交叉编译、历史记录、签名或 notarization 均不能单独升级这些状态。

### 待核销的历史自评

2026-08-24 条目中 A3、A4、A5、A6 的“完成”以及“零 P0、零 P1”均视为待代码复核的历史声明。本轮审计完成前不得把它们当作当前结论。

### 已确认并修复的发现

| 编号 | 级别 | 位置（绑定基线） | 失败场景 | 修复与验证 | 与历史自评冲突 |
| --- | --- | --- | --- | --- | --- |
| X5-1 | P1 | Provider tree `a29d869…`：`diagnosticOutcomeRules` 的 `wechat_not_running`、`process_identity_untrusted`、`hook_relogin_required`；CLI `validBlockingReason` | Provider 分别产出 `wechat_not_running`、`process_identity_untrusted`、`login_time_derivation_required`，但 CLI 白名单缺少这三项，导致合法 v1 响应被拒为 `ProtocolContractError`；常见的微信未运行、身份拒绝与 relogin 升级链均会失去结构化编排。 | CLI 补齐三项，并新增覆盖 Provider 当前全部 blocking reason 生产者的契约测试；`go test ./internal/provider -count=1` 通过。 | 是；推翻“F-P3-1 relogin 全部接线后跨 Provider/CLI 可用”的完成读法，也证明旧“零 P0/P1”不能延续。 |

### X-2 / X-5 核销进度

- X-2：root `pbkdf2SHA512` 只向 `internal/cryptokdf.PBKDF2SHA512Key32` 注入 `atomic.Bool`、budget 与敏感内存登记；root `budget` 只适配 `internal/workbudget.Budget`。两者均无重复算法实现，属于必要的 main-package seam；root `pbkdf2_test.go` 继续保留。
- X-5：`classificationUnsupportedProfile` 与 `unsupported_profile_count` 已从生产代码删除，catalog 维持 profile-neutral。核心 result code、workflow status、next action、Shadow status 与 route 集合在 Provider/CLI 间一致；blocking reason 差集暴露并修复 X5-1。Shadow 的未来状态值属于 1.1 明示的保留目标态，不按死枚举删除。

### X-1 / A3–A6 核销进度

- A3（状态裁决）：acquisition evidence 的结果选择确实集中在单一、有序的 `diagnosticOutcomeRules`，规则顺序有显式测试；session 管理态与 posture-only revalidation 不属于 acquisition-evidence 裁决，因此不应硬塞进该规则表。本轮把这些固定协议态统一收口到 `applyFixedDiagnosticOutcome`，现在 `result_code`、`workflow_status`、`next_action` 只在 `applyDiagnosticOutcome` 一处写入。无阻断原因时保持非 nil 空数组，新增回归后 `go test ./... -count=1` 通过。历史“A3 完成”只能解释为“裁决与写入边界已收敛”，不能解释为所有状态都来自同一规则列表。
- A4（collector）：`candidateScanCounters` 通过单一 `merge` 合并计数；逐库候选以 `databaseCandidates map[string]map[string]*databaseCandidateInfo` 统一承载，没有再发现三张同键平行 map 或直接修改 `targets.pages`。该具体结构声明核实通过。
- A5（Darwin pipeline）：`darwinAcquisitionPipeline` 已按 `runHookStage`、`refreshProcessStage`、`runStaticScanStage`、`finalizeProcessAccessStatus`、`assemble` 组织线性阶段，hook 结果只使用 `platformHookSnapshot`。但 `platform_darwin_hook.go` 仍为 1174 行，`platform_darwin.go` 为 726 行；“pipeline stage 化”核实通过，“God-file 拆分完成”不成立，继续列为未竟质量重构。
- A6（platform seam）：外部 seam 已是 `acquisitionPlatformSession` interface；`synchronizedPlatformSession` 作为同步 concrete adapter 统一锁、snapshot 与 close 语义，其内部函数钩子是实现细节而非对外 DTO。该结构声明核实通过。

当前大文件规模仍为：`platform_darwin_hook.go` 1174 行、`main.go` 1124 行、`session.go` 1172 行、`pattern.go` 1033 行、`platform_darwin.go` 726 行。A3/A4/A5 的局部结构改善不等于 A1 或 God-file 负债已清零。

### X-3 / X-4 核销结果

- X-3：所有生产响应从 `newDiagnostics` 建立非 nil 集合/map 与平台默认值；session merge 由 `sessionDiagnosticMergePolicies` 覆盖 `diagnostics` 的全部字段。`validateSessionDiagnosticMergePolicies` 同时检查字段数、字段名和策略/Go 类型兼容性，重复分配会 panic；`TestSessionDiagnosticMergePolicyIsExhaustiveAndSemanticallyTyped` 钉住该约束。扁平 v1 God-DTO 仍大，但“新增字段静默漏合并”这一结构风险已收敛。
- X-4：生产代码只保留 `platformHookSnapshot`；未发现 `darwinHookResult`、`recordHook`/`recordPersistentHook` 双 DTO/双写路径。该历史整改声明核实通过。

### Track B Phase 0–5 复核结论

| Phase | 结论 | 本轮关键证据 |
| --- | --- | --- |
| 0 协议/Catalog/验证器 | 修复后通过静态与自动化复核 | catalog 发现错误 fail closed；raw/passphrase 均走解密+首页 HMAC；同 salt 仅复用派生；不同 effective key 同验一个物理页一律计为 validator conflict。 |
| 1 结构化 Credential | 核实通过 | `global_passphrase` 只由完整 KDF 调用证据且跨至少两个不同 salt 的逐文件 HMAC 提升；单库/单 salt/静态候选留在 per-database override；CLI 仅在完整 generation 验真后持久化，refresh 默认不访问微信进程。 |
| 2 Daemon/状态机 | 修复后通过本机回归 | prepare/observe/finalize 的 catalog 双绑定、一次性 secret、receipt/retry 与 result-code 单一裁决成立；补齐 cached-finalize secret policy 与 shutdown/prepare 生命周期竞态。 |
| 3 macOS | 静态契约通过，真机门禁未解除 | 目标进程架构/ABI、CommonCrypto/PBKDF、rounds=2 XOR salt、relogin 链、Shadow/SIP 门禁和禁止命令均核实；LLDB resolved-location 与 bundle path 解析已修。Windows 本机不能验证 darwin cgo、Intel/Apple Silicon 真机行为。 |
| 4 Windows | 修复后通过 Windows 自动化；真机门禁未解除 | 目标身份、同 handle 复核、per-process collector、账号绑定和资源上限成立；修复跨架构 fallback 授权与 Authenticode primary signer 绑定；生产 registry 仍为空。 |
| 5 发布安全 | 运行时/安装链核实；正式发布继续阻断 | 固定安装、签名、同用户 IPC、Provider/helper 版本、下载 descriptor、完整发行集合与回滚成立；release evidence 的字段绑定已收紧，但候选摘要需要两阶段外部 attestation/promotion 才能解除门禁。 |

### 本轮新增发现与处置

| 编号 | 级别 | 位置（相对初始 tree `a29d869…`） | 失败场景 | 处置与验证 | 状态 |
| --- | --- | --- | --- | --- | --- |
| B0-1 | P2 | `pattern.go: candidateCollector.databaseKeys` | 同一物理数据库的两个不同 effective key 经不同 profile 路径同时通过时，只记 `ambiguous`，没有记 validator/file-drift 冲突；结果仍 fail closed，但诊断违反 Phase 0 不变量。 | 只要同路径存在两个不同已验 key 就递增 `validatorConflictCount`，新增 `TestDifferentKeysAcrossProfilesAreValidatorConflict`。 | 已修复 |
| B2-1 | P1 | `session.go: diagnosticsPermitSecrets` 与 cached finalize | `session.Latest` 可保留已经验真的 secret；首次 observe 会清除，但 cached terminal finalize 曾绕过统一 policy，因而 failed/ambiguous 等不允许发布的终态可能返回已累积 secret。旧 policy 同时错误丢弃合法 `deadline_exhausted` partial 与完整 SIP-restoration 结果。 | 所有 finalize 出口统一调用 `enforceResponseSecretPolicy`；terminal 仅允许 complete/partial/deadline，非 terminal 仅允许 requested scopes 全 complete 的 `reenable_sip/restoration_required`。补齐允许/拒绝矩阵测试。 | 已修复 |
| B2-2 | P2 | `session.go: acquisitionSessionStore.prepare/closeAll`、`daemon_server.go` | shutdown 在无 session 时可判 idle，同时 handler 正进行昂贵 prepare；`closeAll` 后该 handler仍能注册新 session，造成 daemon 生命周期和资源清理竞态。 | store 增加锁内 `closing`，prepare 在昂贵工作前后检查并清理 provisional 资源；daemon 统计 active handlers，idle exit 不越过 handler。新增 close 后 prepare 回归。 | 已修复 |
| B3-1 | P2 | `platform_darwin_hook.go` | LLDB breakpoint 只要 `IsValid()` 就计为已安装；尚无 resolved location 的 pending breakpoint 会伪造 hook-ready，影响 wait-for/动作诊断。 | Python source 改为检查 resolved locations，并在 attach/wait 后显式报告；Go 聚合保留报告中的最大 resolved 数。新增 source/order/status 回归。 | 已修复；darwin 真机待验 |
| B3-2 | P2 | `platform_darwin.go: darwinProcessExecutable` | `ps` 文本 fallback 以空格切分，应用 bundle 路径含空格时会截断，导致错误 binary identity/route。 | 优先 PID-bound executable path；fallback 识别固定 `Contents/MacOS/{WeChat,Weixin,微信}` 后缀并保留空格。 | 已修复；darwin 真机待验 |
| B4-1 | P1 | `phase4_windows_route.go: windowsTrustedFallbackSigner` | fallback signer 只要出现在任一 eligible registry 条目就可授权，x64 证据可能外溢到 ARM64 目标，违反架构独立门禁。 | signer 查询同时要求目标实际 architecture，新增架构隔离回归。 | 已修复 |
| B4-2 | P1 | `windows_binary_evidence_windows.go` | Authenticode evidence 曾枚举 PKCS#7 内任意证书；非 primary 证书若碰巧匹配 registry，可把“签名有效”误当成目标 signer 身份。 | 在 WinTrust state 关闭前调用 `verifiedWindowsSignerSHA256` 读取实际 primary signer；删除任意证书枚举路径，增加静态契约回归。 | 已修复 |
| B5-1 | P1 | Provider `daemon_transport_{windows,darwin}.go` | server 端虽校验 CLI 进程镜像，但没有显式证明 peer 属于当前 OS 用户；ACL/权限配置退化时，另一个用户的同路径签名 CLI 可能触达 daemon。 | Windows 比较 peer process token `TokenUser`，Darwin 同时读取 `LOCAL_PEERPID`/`LOCAL_PEERCRED` 并比较 `geteuid`；release contract 与 Windows 回归覆盖。 | 已修复；darwin 真机待验 |
| B5-2 | P1 | `release_contract_test.go: validateReleaseEvidenceArtifacts` | `provider_binary_sha256` 只做格式检查，从未与本次已验收候选比较；此外 profile 允许 evidence 超集，runner arch/provider version/Windows route 状态也未完整绑定。发布门禁可以接受“目标微信证据正确、Provider 候选却不是这一份”的 artifact。 | exact profile set、runner arch、当前 Provider version、平台 route/status 已严格绑定；validator 现在还必须接收外部候选 SHA-256 并逐 artifact 精确比较，构建脚本缺该值即失败。新增 mismatch 变体测试。 | 逻辑漏洞已封闭；发布仍阻断 |
| B5-3 | P1 发布阻断 | compiled registry + `compatibility-evidence/<digest>.json` + evidence 内 `provider_binary_sha256` | 若把 evidence 内容摘要编译进 registry，再要求 evidence 记录该重建后二进制摘要，会形成 `binary hash -> evidence hash -> compiled binary` 自引用环；当前单阶段流程无法诚实生成 exact candidate binding。 | 主规范、README、RELEASING 与 evidence README 明示门禁；Windows/macOS release builder 强制要求外部两阶段候选摘要，不再默许只做格式检查。解除条件是把 candidate attestation/promotion 映射移到不参与候选编译的外部、来源证明约束层，并对最终签名 prerelease 复验。 | 未解除；fail closed |

### Phase 5 其余核实项

- Provider npm 安装器从固定 HTTPS host 下载，跨 redirect 保留最初 `O_EXCL` descriptor；Windows/macOS 双架构清单精确，Provider/helper 全部 stage+hash 后作为一个集合提交，失败时反向回滚。
- 固定 Provider 安装目录从 `%LOCALAPPDATA%` 或 `~/Library/Application Support` 出发，逐层 `lstat`、realpath 文本一致性、owner/权限检查；release CLI 拒绝显式/环境路径 override。CLI 自身的 package-local npm 安装目录不是 Provider 固定路径信任边界，不把 npm 可能使用的包链接误判为同一要求。
- CLI 连接 daemon 后验证 endpoint 私有文件、256-bit token、transport、server PID、实际进程镜像、固定 Provider/helper 路径和发行签名；Provider 端验证 peer 用户与 CLI 镜像。macOS Provider 启动 helper 时传入 launcher version，helper 必须与自身嵌入 version 完全一致后才发布 endpoint。

### D-1 / D-2 目录迁移提案

不建议在本轮安全修复中直接搬动 90+ 个 main-package 文件。推荐按依赖方向分六个可独立回滚的提交，先抽纯类型/纯函数，再移动 OS 实现：

| 顺序 | 目标目录 | 首批迁入内容 | 边界要求 |
| --- | --- | --- | --- |
| 1 | `internal/protocol`、`internal/diagnostics` | request/response DTO、枚举、schema 校验、outcome/merge policy | 不 import platform/session；保持 v1 JSON golden tests。 |
| 2 | `internal/crypto`、`internal/catalog` | profile、PBKDF/HMAC/page validator、catalog/file identity | 合并现有 `internal/cryptokdf`；catalog 只返回证据，不决定 workflow outcome。 |
| 3 | `internal/credential` | global/per-DB/mixed promotion、secret publication policy | secret 使用 byte-oriented owner API；不得依赖 CLI 或具体 OS。 |
| 4 | `internal/platform/darwin`、`internal/platform/windows` | process identity、route registry、hook/config cipher、runtime trust | 共享 interface/DTO 放上层；build-tag 只留在各平台包，禁止 phase 编号进入包名。 |
| 5 | `internal/session` | store、action receipt、catalog rebinding、diagnostic merge | 依赖 protocol/catalog/platform interface，不反向 import `cmd`。 |
| 6 | `cmd/v-local-key-provider`、`internal/releaseevidence` | CLI/daemon wiring；release evidence 解析与两阶段 attestation gate | `main` 仅组装；release validator 从 `_test.go` 中抽成可复用纯包，但签名发布仍由 CI 掌权。 |

D-2 命名映射：`phase3_darwin_route.go` → `internal/platform/darwin/route_registry.go`，`phase4_windows_route.go` → `internal/platform/windows/route_registry.go`；`session.go` 拆为 `store.go`、`actions.go`、`secret_policy.go`、`diagnostic_merge.go`；`pattern.go` 拆为 `candidate_collector.go`、`database_validator.go`、`media_validator.go`；`platform_darwin_hook.go` 拆为 `lldb_source.go`、`dynamic_session.go`、`pbkdf_capture.go`。Phase 是交付过程，不作为长期目录或文件前缀。

## 2026-08-24 Phase 4–5 深审与实施结果

### 条目状态

这是当日实现记录；其中实现完成声明正由 2026-08-25 审计重新核销。能力门禁的当前值已迁到主规范 §1.1，本节不再是状态单一真源。

### Phase 4：Windows

深审否定了“只要 Authenticode 有效即可做通用内存 fallback”的隐含授权：机器信任不等于目标产品授权。现在 fixed-layout 与 fallback 均由至少一个完整、精确、带真机证据的 registry 条目锚定；生产 registry 为空时不读取目标进程内存，也不宣称支持。

- 进程身份绑定 signed version metadata（original filename/product/company）、目标可执行 SHA-256、签名叶证书 SHA-256 与实际进程架构；任一不完整即 fail closed。
- 打开进程后从同一 handle 重新核对文件身份、签名与进程实例，避免 discovery→open TOCTOU；候选按进程 collector 隔离，只合并已逐库 HMAC 验真的结果。
- 账号绑定只接受进程实际打开的、位于精确 `db_dir` 下且形态为数据库的路径；其他账号与 unknown 单独计数，mismatch 优先于 partial。
- `Config.Cipher` 读取按实际字节数累计，所有 native buffer、地址数、结构数、候选数、单进程/总扫描量和阶段 deadline 都有硬上限并清零敏感内容。
- x64 与 ARM64 registry/真机证据独立；当日均没有合格生产条目，所以状态为 `build_only`。

### Phase 5：发布与运行时信任

- npm 下载只允许固定 HTTPS host，无凭据/自定义端口；重定向保留最初 `O_EXCL` descriptor；Provider/helper 作为同一发行集合验证、提交并在失败时整体回滚。
- 未验证本地二进制必须同时提供显式路径、`DEVELOPMENT=1` 和 allow 开关；release 构建拒绝全部路径 override。
- 固定安装目录逐层创建并验证，拒绝 symlink/junction/reparse 祖先；CLI 运行时 canonical path 使用文本规范路径比较，不再用会跟随 junction 的 SameFile 结果冒充固定路径。
- Windows daemon named pipe 与 macOS Unix socket 均绑定同用户 peer 和实际进程镜像；macOS 还验证 Developer ID identifier/Team ID。Provider/helper 启动握手要求完全相同版本。
- macOS helper 只走固定绝对工具路径、clean environment、超时和输出上限；release 不接受未验证 helper 或隐式提权路径，SIP 只读解析且 Provider 永不执行状态修改。
- 签名构建前运行 `TestReleaseCompatibilityEvidenceGate`：每个目标架构必须有 eligible registry 条目，且 `compatibility-evidence/<sha256>.json` 的内容摘要、目标 fingerprint/签名、route、完整 coverage 和 profiles 与条目一致。空 registry 或缺证据会有意阻止 release。

### 当日尚未解除的能力门禁

当日记录为：生产 Windows/macOS registry 为空；macOS cgo 路径需在对应 Intel/Apple Silicon runner 编译并做授权真机验证；Shadow 为 `unavailable_in_build`；生产 cipher profile 只包含已有证据项；A1 的 catalog/session/platform 全量拆包尚未完成。当前值及升级条件以主规范 §1.1 为准。

## 2026-08-24 Phase 0–3 初始审计与同日复核

### 条目状态

本条目的“初始总体结论”已被同条目后部的“Phase 0–3 复核结论”明确取代。保留它只为审计可追溯性，不得继续引用为当前结论。

### 范围与方法

- 范围：Phase 0（协议/Catalog/验证器）、Phase 1（结构化 Credential，provider 侧）、Phase 2（Daemon 与状态机）、Phase 3（macOS 三模式）。Phase 4（Windows）、Phase 5（发布安全）未在初始深审内，仅在与 Phase 0-3 交叉处核对。
- 方法：整文件静态审读 + `go build ./...` / `go vet ./...`（当日均干净）。本机 `go test` 被 Windows App Control 拦截，测试正确性依赖 CI；只审读测试充分性。darwin 为 cgo，本机无法交叉编译，Phase 3 为静态契约审读，真机正确性依赖 CI。

### 初始总体结论（已被后续复核取代）

当日初始结论为：“中断没有伤到核心：零 P0、零 P1。”其依据是 fail-closed catalog、逐文件 HMAC、validator-conflict、凭据提升门槛、IPC、secret 三段纪律、SIP 机器验证、helper 信任链与 §12.10 禁止行为等静态审读。后续复核认为该结论对跨 Provider/CLI、daemon transport、session finalize 的集成缝评价过高，因此不能继续作为当前审计结论。

### 初始契约符合性发现

以下位置是当日线索，未绑定 2026-08-25 tree，引用前必须重新定位。

| # | 阶段 | 级别 | 位置 | 摘要 |
| --- | --- | --- | --- | --- |
| F1 | 0 | P2 | `catalog.go:26`、`main.go:598` | `classificationUnsupportedProfile` 定义并计数但从不赋值，`unsupported_profile_count` 恒 0；异 profile 库表现为普通 missing。 |
| F2 | 0 | P2 | `profile.go:35-54` | `profileRegistry` 单条目；§19.1“不同 profile 的历史/迁移数据库”验收无法通过。fail-closed，非正确性 bug。 |
| F3 | 0 | P2 | `main.go:787-790` | 预算耗尽覆写的排除列表不全，会把若干阻塞终态改标为 `deadline_exhausted`，削弱 `result_code` 权威。 |
| P2-1 | 2 | P2 | `session.go:696-699,779,849-866` | 无回执 finalize 曾把待处理账号 mismatch 改写成 `partial` + `user_declined_action`，违反 mismatch 优先级。 |
| F-P3-1 | 3 | P3 | `platform_darwin.go:497-501` | `relogin_wechat` 在回执白名单与预算内，但当时不产出为 `next_action`。 |
| CC-1 | 跨切面 | P3 | `credential.go:60,72` | 凭据内 hex secret 是不可擦除 Go string，仅序列化后的 payload 被清零；JSON + hex v1 下残余风险低但存在。 |

F1 与 F2 是同一个“异 profile 库”故事；F1、F-P3-1、CC-1 同属定义后半接线的中断残留，与 F3、P2-1 的诊断失真相互独立。

### 初始设计与实现质量评估

当日判断是正确性与安全性较强，但可维护性与可审计性负债集中：

- A1：单一 `main` 包、缺少足够 `internal/` 边界。
- A2：`diagnostics` 为 100+ 扁平字段的 God-DTO，构造与默认值曾分散。
- A3：状态机曾是排序敏感的巨型 switch，会话层另有并行裁决。
- A4：collector 曾用三张同键并行 map 与约 20 个重复传播的内联计数器。
- A5：`platformAcquire` 曾把进程发现、路由、hook、静态扫描、口令兜底与组装揉在一个 God-function，并以平行类型重复建模 hook snapshot。
- A6：平台 seam 曾使用函数指针 struct 而非 interface。

当日同时记录了 `mergeSessionDiagnosticEvidence` 手工逐字段合并、输入切片原地修改、budget slice 别名和 session×finalize 集成缝覆盖不足等风险。

### 当日建议的重构着力点

1. 按主规范 §10.6 拆分 `platformAcquire`，把完成不变量与短路点显式化。
2. 将 collector 计数器收敛为单一 `Merge()`，合并平行 map。
3. 状态裁决单一化，并增加枚举生产者/消费者穷尽性检查。
4. 合并平行 hook 结果类型。
5. 移除输入切片原地修改；评估 platform seam interface。

F1 的初始修复建议经复核被否定：密文没有 authenticated profile marker，“无候选命中”不能证明 profile 不受支持；正确方向是删除死枚举/计数器、保持 catalog profile-neutral，并用有界 registry 逐项验证。

### Phase 0–3 同日复核结论与整改记录

初始“零 P0、零 P1”只能保留为当时的静态审读快照。跨 Provider/CLI、daemon transport、session finalize 的复核发现，孤立单测通过不足以证明集成缝安全。整改记录如下；“实施结果”是当日声明，仍须由 2026-08-25 审计核销。

| 项目 | 复核 | 当日实施结果声明 |
| --- | --- | --- |
| F1 `unsupported_profile` | 发现属实，但“无匹配即产出 unsupported”不安全 | 删除 Provider/CLI 死枚举与恒零计数；catalog 不预填默认 profile；新增非默认 registry profile 可达性测试。 |
| F2 单条生产 profile | 属实，是尚未取得历史/迁移库证据的能力缺口 | 参数化机制与多 profile 路径已有回归；生产 registry 仍只含已证明项。 |
| F3 budget 覆写终态 | 属实 | 终态进入有序 rule 裁决，budget 仅在更高优先级规则均不匹配时生效。 |
| P2-1 mismatch 被 `stop_and_report` 改写 | 属实 | session 不再把账号切换动作降格为 partial，并补跨 session/finalize 集成测试。 |
| F-P3-1 relogin 半接线 | 属实 | `trigger -> restart -> relogin` 产出、receipt 和有限重试接线。 |
| CC-1 Go string 不可擦除 | 属实且无法由 JSON/hex v1 完全消除 | secret 不进入 observe/blocked/cancelled/endpoint/resume；可变缓冲登记 WER 排除并在序列化后清零。 |

同日还声明修复了这些集成问题：CLI 不再把 `ProtocolContractError` 降级为普通 provider-unavailable；daemon 在 token 之外绑定 peer PID、进程镜像和平台签名身份；session 绑定首个已验证 peer；Provider/helper 版本精确一致；blocked/cancelled/observe 路径不返回 credential secret。

### A1–A6 同日整改记录（待本轮核销）

| 项目 | 当日状态声明 | 当日结构性约束声明 |
| --- | --- | --- |
| A1 包边界 | 部分完成 | 新增 `internal/workbudget` 与 `internal/cryptokdf`；其余 platform/session/catalog 拆包仍需分阶段执行。 |
| A2 diagnostics God-DTO | 协议形状保留、构造风险已收敛 | v1 扁平 JSON 不变；所有生产响应从 `newDiagnostics` 初始化；反射穷尽测试覆盖 session merge policy。 |
| A3 状态机 | 完成 | 单一 ordered rule 列表、显式优先级测试；session 不再另起 result-code 裁决。 |
| A4 collector | 完成 | 三张并行 map 合并为 `candidateInfo`；计数器集中为带单一 `merge` 的子结构。 |
| A5 Darwin pipeline | 完成（待 macOS cgo CI/真机） | `discover/route/hook/refresh/static/finalize/assemble` 分 stage；两种 hook snapshot 合一。 |
| A6 platform seam | 完成 | 函数指针 DTO 改为 interface，由同步 concrete session 统一锁和 close 语义。 |

当日还声明：`mergeSessionDiagnosticEvidence` 已改为穷尽、类型校验的策略表；budget slice 别名已复制隔离；候选上限为 512；KDF 每 4096 轮检查预算/取消；同 salt 只复用派生结果、每个物理文件仍单独 HMAC；若干关键集成缝已新增回归。以上均由 2026-08-25 Track B 逐项复核。
