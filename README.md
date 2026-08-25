# v-local-key-provider

`v-local-key-provider` 是独立安装的本地密钥候选 Provider。它通过首发的 `v-local-key-provider/v1` JSON 协议，在用户明确授权后读取本人微信进程中的候选密钥。默认入口由 CLI 启动当前用户专属的本地 acquisition daemon；Provider 对每个数据库执行完整首页 HMAC，调用方在 generation 构建前再次独立验证文件身份和密钥。

本程序只适用于处理本人拥有或已获明确授权访问的数据。它不联网、不发送微信消息、不修改微信进程或文件，也不负责保存、解密或查询最终数据。

## 支持范围

| 平台 | 架构 | 状态 | 说明 |
| --- | --- | --- | --- |
| Windows | amd64 | 实验性、可构建 | Phase 4 路径与专用真机门禁已具备；当前仍为 `build_only`。 |
| Windows | arm64 | 实验性、可构建 | 独立发布资产和真机回归入口已具备；未取得 ARM64 微信真机证据前保持 `build_only`。 |
| macOS | amd64（Intel） | 历史验证、当前 `build_only` | 4.1.11 有未绑定当前候选件的历史记录；正式版须重新取得内容寻址的精确 registry 证据。 |
| macOS | arm64（Apple Silicon） | 实验性、可构建 | 尚无合格的 Apple Silicon 真机证据，正式版保持 fail closed。 |
| 其他平台 | 不适用 | 不支持自动获取候选密钥 | 可以继续使用调用方提供的候选文件。 |

Windows 会先读取正在运行的 Weixin/WeChat 进程的实际架构、可执行文件 SHA-256、Authenticode
签名者证书 SHA-256、文件版本/build 和产品身份。只有这些字段与带独立真机证据的兼容注册表
完全匹配时，才允许执行该 fingerprint 对应的 `Config.Cipher` 固定结构或由相同 registry
签名者锚定的有界、missing-only 扫描；未登记或签名失败时不读取目标进程内存。registry 中的真机证据引用必须是脱敏
证据文件的 SHA-256。候选按进程实例和阶段隔离，只有对目标 Catalog 数据库首页 HMAC
验真的结果才能跨隔离边界；结构化逐库凭据保留对应的 opaque `process_instance_ids`，不会
退化成 PID-only provenance。当前生产兼容注册表有意保持为空，
因此 amd64/arm64 都不会在缺少真机证据时宣称 `Config.Cipher` 已受支持。

正式发行还受一层独立门禁约束：live evidence 中的 `provider_binary_sha256`（macOS 还包括 helper 摘要）必须与 GitHub attestation 验真的 `Release candidate` 完全一致。内容寻址 evidence 摘要保存在不参与候选编译的 `compatibility-evidence/promotions/<release-tag>.json`，从而消除原先的自引用哈希环；签名构建会校验 promotion、候选来源提交与受限源码 diff，并把 promotion 摘要注入发行二进制。当前生产 registry/evidence 仍为空，所以正式 release 继续按真实能力 fail closed。

macOS 的自动路径仍然受微信版本影响。4.1.x 的数据库密钥通常只在 CommonCrypto 调用的瞬间出现在寄存器中，开发构建可用机器验证后的通用符号路径做受控试验；签名发行构建只允许命中带内容寻址真机证据的精确 registry 条目。无论走动态断点还是静态扫描，候选都必须通过数据库首页验证，Provider 不会把零结果报成成功。

### 微信版本兼容矩阵

| 微信版本 | x86_64 | arm64 | 首选路径 | 失败时的回退路径 |
| --- | --- | --- | --- | --- |
| 4.1.10、4.1.11 及后续 4.1.x | 4.1.11 仅有历史记录；发行版仍需精确证据 | 实验性，未在本机验证 | 精确登记后使用 CommonCrypto 动态断点 | 未登记时发行版 fail closed |
| 4.0.x | 实验性，未在本机验证 | 实验性，未在本机验证 | 静态扫描 | CommonCrypto 动态断点（可用时） |
| 3.x 及更早版本 | 未验证 | 取决于微信构建，未验证 | 静态扫描 | 无保证 |
| 未识别版本 | 仅开发构建受控试验 | 仅开发构建受控试验 | 通用符号路径（development） | 发行版返回未登记诊断，不扫描进程 |

动态路径由 Provider 自动调用系统 `lldb`，不需要用户输入命令，也不需要用户手工运行 helper。如果当前版本没有触发数据库调用，Provider 会自动再进入一次 `--waitfor` 兼容路径，在微信新进程启动前预置断点。Provider 不会自动启动、退出或重启微信，这一步需要用户按下面的[触发一次数据库调用](#触发一次数据库调用)配合。

如果系统没有 `lldb`，Provider 会自动保留静态扫描并返回版本与 Hook 诊断，不会要求用户手工安装调试器或复制调试命令。

## 触发一次数据库调用

动态断点要命中，微信必须重新打开一次数据库。绝大多数动态路径的失败（`hook_trigger_required`、`hook_restart_required`）都按同一套动作处理：

1. 完全退出微信。只关闭窗口或切换聊天不算退出。
2. 启动调用方的一次性完整授权命令，例如 `v-local-cli setup --allow-key-access --storage keychain`。
3. **保持这个终端窗口不动，不要按 `Ctrl-C`。** 命令仍在运行、终端还没有回到提示符，就说明 Provider 正在等待。
4. 从“应用程序”手动打开微信，完成账号登录或手机端登录确认。只打开登录窗口，或只切换一个已经打开的聊天，都不能代替登录流程。

顺序很重要：先退出微信、再启动授权命令，最后才重新打开微信。不要先启动微信再运行 setup。Provider 全程不会自动启动、退出或重启微信，也不会要求用户运行 helper、`lldb` 或提供任何密钥。

按这个顺序连续两次仍然失败时，应该停止自动重试，并报告微信版本、进程架构和 Hook 诊断。

## Apple Silicon 与 Intel

Apple Silicon（`arm64`）和 Intel（`x86_64`）使用同一套工作流程，但动态断点读取的寄存器不同：

- **arm64**：`CCCrypt` 与 `CCCryptorCreate` 从 `x3`（密钥地址）和 `x4`（密钥长度）取参数，`CCCryptorCreateWithMode` 从 `x5` 和 `x6` 取。
- **x86_64**：同样两个函数改从 `rcx`（密钥地址）和 `r8`（密钥长度）取参数，`CCCryptorCreateWithMode` 从 `r9` 取密钥地址，长度则从栈上 `rsp + 8` 读出。

Provider 会读取**正在运行的微信进程的架构**并自动选择对应的 Hook 脚本，不只根据 CLI 自身的架构判断。因此在 Apple Silicon 上运行原生 arm64 微信会走 arm64 路径；如果微信通过 Rosetta 以 x86_64 进程运行，则会走 x86_64 路径。安装器会按当前 macOS 架构安装匹配的 Provider 和 helper，不要混用不同架构的发布件。

静态扫描路径不依赖这些寄存器，但仍然受微信版本、签名、SIP 和数据库布局影响。

正因为两种 ABI 读取的寄存器不同，一种架构的验收结论不能外推到另一种。仓库中的 Intel 历史记录没有与当前候选二进制摘要绑定，不能作为 Agent 可消费的发布证据；arm64 也仍属于实验性的 `build_only`。任何架构都必须在对应微信版本与签名候选件上重新形成可核验的 live evidence，才能升级能力声明。

## 安装

正式发布后的安装入口为：

```sh
npx @zanescope/v-local-key-provider@latest install
```

npm 包只负责下载和校验对应的 Go 二进制，不包含 Provider 的实现源码。它把正式资产安装到当前用户固定目录：Windows 为 `%LOCALAPPDATA%\v-local\key-provider\windows-<arch>\v-local-key-provider.exe`，macOS 为 `~/Library/Application Support/v-local/key-provider/darwin-<arch>/v-local-key-provider`；macOS helper 以固定同级文件名安装。每次启动都会复核发布 SHA-256，发行构建还会在运行时验证固定路径、文件身份和平台签名。用户不需要单独运行 helper、传递路径或处理中间候选。当前仓库尚未取得四架构真机 evidence，也未创建正式 Release，因此包不会提前发布。候选件、promotion 与正式签名发布的操作说明见 [RELEASING.md](RELEASING.md)。

仓库开发测试可以用 `V_LOCAL_KEY_PROVIDER_BINARY_PATH`（以及 macOS 的 `V_LOCAL_KEY_PROVIDER_HELPER_BINARY_PATH`）指向本地构建件，但必须同时设置 `V_LOCAL_KEY_PROVIDER_DEVELOPMENT=1` 和 `V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY=1`。路径、开发态和绕过开关缺一不可；正式 CLI 仍会拒绝未签名替代文件。它们不得写入普通用户配置或正式发布流程。

## macOS 使用前准备

### 默认流程

macOS 的默认 helper 模式是 `auto`：

1. Provider 先普通启动同目录的 helper。
2. 如果 `task_for_pid` 被拒绝，Provider 检查 SIP 状态。
3. SIP 开启时，Provider 不会弹出无意义的密码框，而是返回 `sip_enabled` 诊断。
4. 只有显式 development 构建在 SIP 已关闭时保留一次管理员授权兼容试验；签名发行构建禁止 AppleScript 提权，必须由已签名 companion helper 的固定权限模型完成或 fail closed。

程序不会自动关闭 SIP、修改微信签名或注入 dylib，也不会把候选密钥写入文件。标准动态路线本身仍会附加 LLDB、设置捕获断点并读取进程内存。

### SIP 跨重启协议（Shadow 优先、不可用时降级）

macOS 路由固定按 `standard -> shadow -> sip_disabled` 排序，但优先级不是硬依赖。当前实现尚未完成 Shadow 路线，因此 Provider 明确返回 `shadow_route_status=unavailable_in_build`；它表示该优先槽位已完成“本构建不可用”的终态判断，不表示 Shadow 曾经运行或失败。标准路线已有访问失败机器证据且 `csrutil status` 验证 SIP 开启后，可以进入较低优先级的 SIP fallback。

`next_action=disable_sip` 只接受三种终态 Shadow 依据：`unavailable_in_build`、`unsupported_for_target` 或 `attempted_failed`，并要求与相应 `blocking_reasons` 精确匹配。`not_evaluated`、`available` 或 `awaiting_approval` 都不能跳过 Shadow。CLI 随即结束旧 acquisition session，并在当前用户私有目录保存无权限 checkpoint：只含 opaque workflow/account/provider ID、scope、阶段、安全姿态和过期时间；绝不含路径、session、token、进程标识、候选、密钥、receipt 或授权。它用于让重启后的新 Agent 发现“上一阶段停在哪里”，不用于证明动作已经完成。

Provider 只能只读判断 SIP 状态，不能自行执行 `disable_sip` 或 `reenable_sip`。机器证据一旦确认 SIP 已关闭，即使 catalog、进程发现或二进制门禁在具体 fallback route 启动前失败，也会优先返回 `restoration_required + reenable_sip`；此时使用 `sip_disabled_route_not_attempted`，不会伪造 `routes_attempted`。若用户实际上没有关闭 SIP，后来一次普通 acquisition 在 `sip_enabled_verified` 下完整成功，CLI 会清除已经失效的关闭阶段 checkpoint。

用户明确选择 SIP fallback 后，人工步骤为：

1. 完全退出微信、Provider 和 CLI，保持微信账号信息不变。
2. 进入 macOS 恢复模式：Intel Mac 在重启时按住 `Command-R`；Apple 芯片 Mac 关机后长按电源键，出现启动选项后选择“选项”。
3. 在恢复模式的“终端”中运行 `csrutil disable`。
4. 重启回到桌面后，先用 `csrutil status` 取得系统证据，再新建 acquisition session，并按[触发一次数据库调用](#触发一次数据库调用)的四步完成一次授权。Provider 会自动启动 helper；如果系统弹出管理员授权提示，只确认这一次操作即可，不需要手工运行 helper。
5. **确认 setup 已经成功返回、密钥也已保存之后，必须恢复 SIP。**

恢复 SIP 的完整步骤：先退出 CLI、Provider 和微信，然后再次进入恢复模式——Apple 芯片 Mac 关机后按住电源键，直到出现“正在载入启动选项”，选择“选项”并点“继续”；Intel Mac 重新启动后立即按住 `Command-R`，直到出现 Apple 标志或地球图标，再按提示选择用户并输入登录密码。

进入恢复环境后，在顶部菜单选择“实用工具” > “终端”。这是恢复模式的终端，不是桌面上的终端。在其中运行 `csrutil enable`，看到命令成功完成后再运行 `csrutil status`，确认输出包含 `System Integrity Protection status: enabled`。然后运行 `reboot`，或者从左上角 Apple 菜单选择“重新启动”。回到桌面后可以在普通终端再次运行 `csrutil status`，确认仍然是 `enabled`，再进行日常使用。

把恢复模式终端关掉并不等于恢复 SIP，必须执行 `csrutil enable` 并重启。如果用户不接受关闭 SIP，应该改用调用方的 `--keys FILE` 导入已经取得的候选文件，而不是反复重试自动 helper。

### Agent/CLI 反馈契约

调用方收到下列任一状态时，必须把它反馈给用户，而不是显示“没有找到密钥”或者继续盲目重试：

| CLI 错误 | Provider 诊断 | 用户需要做什么 |
| --- | --- | --- |
| `key_provider_unsupported` | `result_code=unsupported`、`process_access_error=sip_enabled` | SIP 没有通过系统证据验证，或 Shadow 尚未得到可降级的终态；停止并报告，不得自行推断关闭 SIP。 |
| `key_provider_sip_required` | `next_action=disable_sip`、`shadow_route_status=unavailable_in_build\|unsupported_for_target\|attempted_failed` | 更高优先级 Shadow 已明确不可用或失败，可由用户选择 session 外的 SIP fallback；CLI 必须先持久化无权限 checkpoint。 |
| `key_provider_hook_trigger_required` | `process_access_error=hook_trigger_required` | 完成指定只读页面动作后，显式增加 `--confirm-key-action trigger_database` 续接当前 session。普通重跑不会自动确认。 |
| `key_provider_hook_restart_required` | `process_access_error=hook_restart_required` | 用户确认影响并只重启绑定进程后，显式增加 `--confirm-key-action restart_wechat`；Provider 必须观测到进程实例变化。 |

CLI 和 Provider 不会自动修改 SIP，也不会自动启动、退出或重启微信；helper 与 `lldb` 都由 Provider 自己处理。

在用户完成恢复模式操作并回到桌面之前，Agent 不应该自动重试，不应该要求用户手工运行 helper，也不应该要求用户提供任何私钥、密码或候选值。

收到 `hook_trigger_required` 时，Agent 还应该向用户说明：当前进程的数据库已经打开，普通地切换会话不一定会重新创建加密上下文，所以反复打开聊天没有用，必须按上面的顺序完整重来一次。

## 快速开始

Provider 由调用方在一次明确授权下启动。调用方应该保持微信已登录，并使用对应的账号目录和数据库目录：

```sh
v-local-cli setup --allow-key-access --storage keychain
```

该命令让 Provider 在一次请求中同时申请 `database` 和 `media` 两个 scope；调用方会再次使用本地数据库和真实 DAT 独立验证结果，并在验证成功后保存所需凭据。成功输出应确认 `status=ready`、`media.status=verified`、`database_credential_status=persisted|not_required_plaintext_only` 和 `image_keys_persisted=true`。`database_keys_persisted=false` 在已验真的 plaintext-only Catalog 中是正常结果，不能据此判失败。只有明确的 database-only 任务才使用 `v-local-cli setup --allow-key-access --storage keychain --database-only`，此时 Provider 只申请 `database` scope。后续媒体刷新使用 `refresh --require-media`，仍不需要再读取微信进程；只有凭据缺失、账号目录改变，或者出现未覆盖的新数据库分片时才需回到 setup。

## 安全边界

- 只处理本人拥有或已获明确授权访问的数据。
- 不注入 dylib、不修改或重签原版微信二进制。macOS 动态路线会附加 LLDB、安装只读捕获断点并读取受保护进程内存，因此可能被 SIP/Hardened Runtime 阻止；这项行为会明确展示，不表述成“完全不接触进程”。
- 默认通过认证的本地 IPC 传输请求与响应；兼容 one-shot 时才使用 stdin/stdout。密钥不出现在命令行参数、endpoint 或 resume 文件中。
- macOS 的 companion helper 使用同一套受限协议和同一次授权，只由主程序自动调用；管理员授权兼容路径使用一次性令牌认证的 loopback 连接，请求与响应不写临时文件。
- 发行构建拒绝 helper 环境变量覆盖。macOS 在启动、提权和 daemon 复用前核对 owner、权限、canonical sibling、Developer ID、固定 code identifier、Team ID 和实际 daemon PID image；Windows 核对固定安装路径、WinVerifyTrust 结果及编译期绑定的签名证书 SHA-256，运行时验证禁止联网取回证书状态。
- Unix 启动时把 core dump 硬上限设为零；Windows 要求 WER 禁止堆采集，并把持有协议/候选的可清理 byte buffer 注册为 excluded memory block。无法启用这些门禁时密钥处理入口 fail closed。
- 持久 Hook 由父进程存活管道约束；session 完成、取消、过期或 daemon 异常退出时，watchdog 会终止对应调试子进程。清理只作用于本次启动的确切进程组。
- stdout 只供调用方捕获，不应该直接写入日志或交给 Agent。
- 本程序只用数据库首页和图片头样本筛除错误候选，不保存候选；调用方必须再次独立验证。

## 候选来源

- 数据库：只读扫描微信进程中的候选对象，并用本地 SQLCipher 首页筛选。
- 图片：优先从 `kvcomm` 的 statistic 文件名提取 code，与规范化的 wxid 离线推导 AES/XOR，再用 V2 DAT 头块和 XOR 样本的共识筛选。
- 只有在 `kvcomm` 路径不可用时，才尝试从进程内存中寻找可由 V2 头块验证的 AES 候选。

macOS 进程发现先使用 `/bin/ps`；当宿主环境拒绝读取进程列表时，回退到
`launchctl print gui/<uid>`，再查询 `application.com.tencent.xinWeChat...` 应用服务详情。
诊断中的 `process_discovery_method` 只记录 `ps`、`launchctl` 或 `ps_then_launchctl` 等方法名，
不会包含进程路径、账号目录或密钥。若两种枚举方式都失败，返回 `process_list_unavailable`，调用方不应显示“微信未运行”。

XOR 多候选只在第一名的证据数至少是第二名四倍时才形成候选；结果接近时按歧义拒绝。所有诊断字段只包含计数和方法名，不包含候选值。

## 协议

首个公开协议标识为 `v-local-key-provider/v1`：

```json
{
  "protocol": "v-local-key-provider/v1",
  "request_id": "一次性请求标识",
  "action": "acquire",
  "account_dir": "绝对路径",
  "db_dir": "绝对路径",
  "scopes": ["database", "media"],
  "deadline_ms": 75000,
  "workflow": {"operation": "finalize"}
}
```

CLI 默认执行 `prepare -> observe -> finalize`。`prepare/observe` 不向客户端返回 secret；`finalize` 重新发现并核对同一 catalog 后才返回一次。`observe` 返回 `action_required` 时，daemon 保留同一 session（硬上限 15 分钟），但只有用户显式传入与 `next_action` 完全一致的 `--confirm-key-action` 才生成 action receipt；普通重跑和 `--allow-key-access` 都不代表动作确认。Shadow、关闭 SIP、恢复 SIP 不属于同 session receipt：旧 session 必须结束，CLI 只保存不含路径、秘密或授权的跨重启 checkpoint；重启后创建新 session 并重新验证机器状态，旧确认参数不得复用。`cancel`、客户端断开、完成、过期或 daemon 退出会清理 session。macOS daemon 由同包 companion helper 承载；helper 不可用时回退 one-shot，不静默改走主程序直接访问。内部入口为 `v-local-key-provider daemon serve <private-endpoint-file>`，endpoint 文件仅含随机认证令牌和回环地址，必须位于当前用户专属目录。

兼容 one-shot 的 `acquire` 仍通过 stdin/stdout 接受上面的 `workflow.operation=finalize` 请求。跨重启 checkpoint 已进入 SIP 恢复阶段时，CLI 使用一次性的 `workflow.operation=revalidate_security_posture`；该操作只读检查系统安全姿态，不启动 helper/hook、扫描进程或返回 credential，也不具备修改 SIP 的能力。只有 CLI 当次直接调用 Provider 得到的严格无秘密响应可以清除恢复 checkpoint，`--keys` 文件或历史响应不能替代机器复核。`database_keys` 只包含对当前 catalog 已完成首页 HMAC 的逐库 effective key；`catalog_entries` 同时返回逐库平台文件身份、大小、mtime、首页摘要、classification 和 profile。调用方必须在稳定复制前后以及 WAL 复制后复核这些证明，漂移时废弃本次结果。不要把 Provider 的原始 IPC/stdout 响应写入日志或交给 Agent。

### 关键诊断字段

| 字段 | 说明 |
| --- | --- |
| `result_code` | 本次 RPC 的整体结果，也是 Agent 判断整体成功或失败的唯一权威字段。 |
| `requested_scopes` | Provider 实际处理的 scope 回显，固定按 `database, media` 排序。 |
| `database_target_status` | `not_requested`、`none`、`present`；空 Catalog 必须为 `none`，不能被解释成 plaintext-only complete。 |
| `database_coverage_status` | 仅描述数据库覆盖：`not_requested`、`none`、`partial` 或 `complete`。 |
| `media_coverage_status` | 仅描述原子 AES/XOR 组合覆盖：`not_requested`、`pending`、`none` 或 `complete`。 |
| `security_posture_status` | `not_applicable`、`not_evaluated`、`sip_enabled_verified`、`sip_disabled_verified`、`restoration_required`；它只表达 SIP 这一项姿态，不代表整机总体安全，且只按 `csrutil status` 机器证据升级。 |
| `shadow_route_status` | `not_applicable`、`not_evaluated`、`unavailable_in_build`、`unsupported_for_target`、`available`、`awaiting_approval`、`attempted_failed`、`succeeded`；未实现与实际失败严格区分。 |
| `route_priority` | macOS 固定为 `[standard, shadow, sip_disabled]`。Shadow 优先于 SIP，但终态不可用不会阻塞较低优先级 fallback。 |
| `routes_attempted` | 只记录真正执行过的具体 route；`unavailable_in_build` 不能把 Shadow 写入该数组，`route_priority` 也不构成执行证据。 |
| `helper_status=not_installed` | 同目录的 helper 不存在或不可执行。 |
| `helper_status=used` | 普通 helper 已执行。 |
| `helper_status=elevated` | 已通过系统管理员授权执行 helper。 |
| `helper_status=sip_enabled` | SIP 开启，兼容路径未启动。 |
| `wechat_version`、`process_architecture` | Provider 实际识别到的微信版本和主进程架构，用于判断走兼容矩阵的哪个分支。 |
| `binary_fingerprint_status`、`binary_signing_status` | Windows/macOS 目标二进制摘要与平台签名证据状态；未验证时对应摘要/身份字段必须为空。 |
| `compatibility_registry_status` | 精确 registry 的 `registered_supported`、`registered_unsupported`、`unregistered`、`rejected_untrusted_binary` 或 `not_evaluated`。 |
| `config_cipher_route_status` | Windows `Config.Cipher` 的登记、尝试和结果状态；只有 `registered_supported` 才能进入尝试态。 |
| `windows_route_evidence` | 只含稳定、脱敏的 Windows 路由证据枚举，不含路径、地址或候选。 |
| `target_bound_process_count`、`other_account_process_count`、`unknown_account_process_count` | Windows 进程句柄路径产生的账号绑定分类；unknown 进程仍必须靠目标数据库 HMAC 绑定。 |
| `per_process_collector_count`、`fallback_stage_counts` | 逐进程候选隔离与 ordered fallback 的机器计数，用于证明没有把不同进程的未验证候选混合。 |
| `version_support=commoncrypto_dynamic` | 当前版本优先使用 CommonCrypto 动态断点。 |
| `hook_installed=true` | 动态断点已安装，正在等待微信触发数据库调用。 |
| `process_access_error=hook_trigger_required` | 断点已安装，但这一次没有捕获到可验证的候选。 |
| `process_access_error=hook_restart_required` | 数据库已经打开，需要微信重新打开一次。 |
| `dynamic_hook_used=true` | 已从调用参数捕获候选，并通过本地数据库首页验证。 |
| `static_scan_fallback=true` | 动态路径没有立即得到完整结果，Provider 已自动回退到静态扫描。 |
| `process_access_status=wechat_not_running` | 没有发现微信主进程。 |
| `process_access_status=denied` | 进程存在，但当前权限不能读取。 |
| `process_access_error=sip_enabled` | 需要按[临时关闭 SIP](#临时关闭-sip) 处理。 |
| `process_access_error=task_for_pid_denied` | 进程访问仍被系统拒绝，不要把它解释为数据库损坏。 |

未请求的 scope 必须返回 `not_requested`，不能用 `complete` 表示“无需执行”。只有所有 requested scope 都为 `complete`、工作流已 terminal 且没有待处理动作时，`result_code` 才能为 `complete`。Agent 不得仅凭任一 coverage 字段判断整体成功。

`hook_trigger_required` 和 `hook_restart_required` 的处理动作见[触发一次数据库调用](#触发一次数据库调用)。

### 时限

`deadline_ms` 是调用方给定的超时上限（毫秒，最大 3600000）。本程序在遍历内存区域、读取每个 1 MiB 分块，以及验证每个口令候选之前都会检查时限，到时间就停止并返回**已经验证出的候选**，同时在诊断中给出 `budget_exhausted` 与 `elapsed_ms`。

之所以需要这个上限，是因为内部允许的工作量远超调用方的等待时间：单次口令验证需要 25.6 万轮 PBKDF2-HMAC-SHA512（实测约 164 毫秒），候选上限 10000 且分四组尝试，最坏情况合计可达十几分钟。没有时限时，调用方只能超时杀掉进程，已完成的工作全部作废。

超出时限的幅度受检查粒度限制：内存扫描最多超出一个分块（约 18 毫秒），口令验证最多超出一次验证（约 164 毫秒）。

首发 v1 要求显式提供 `deadline_ms`，范围为 1 到 3600000；缺失或越界都会 fail closed。响应始终回显同一个 `v-local-key-provider/v1` 协议标识。

## helper 模式

默认值是 `auto`。开发或排错时可以通过环境变量覆盖：

```sh
export V_LOCAL_KEY_PROVIDER_MACOS_HELPER_MODE=auto
```

只有隔离开发环境需要覆盖 companion helper 路径时，才可同时设置 `V_LOCAL_KEY_PROVIDER_HELPER` 与 `V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_HELPER=1`；单独设置路径会被拒绝。发行构建即使同时设置两个变量也会 fail closed。

可选值：

- `auto`：普通启动被拒绝后，按 SIP 状态决定是否请求管理员授权。
- `direct`：只普通启动，不请求管理员授权。
- `elevated`：直接走管理员授权路径。

除非正在排错，不要改变默认值。

## 开发与构建

```powershell
go test ./...
go vet ./...
go build -trimpath -o build/v-local-key-provider.exe ./cmd/v-local-key-provider
```

目录边界为：`cmd/v-local-key-provider` 只负责接收 linker 注入的版本/发行标记并启动命令；仓库根目录是可测试的 `provider` 组合与信任策略注入层；协议、catalog、crypto、credential、diagnostics、release evidence、session、acquisition 以及 Windows/Darwin process-memory driver 分别由 `internal/*` 持有。Windows 根适配器只注入可执行文件哈希、Authenticode primary signer、发布 registry 与敏感内存回调；Darwin 根适配器只注入受限命令执行器、代码身份/摘要证据、动态 hook、SIP 状态与敏感内存回调，Mach task-port 生命周期和 acquisition pipeline 均由 `internal/platform/darwin` 持有。

macOS 构建应该保持 cgo 开启，并使用与目标机器匹配的架构：

```sh
scripts/build-macos.sh arm64
# Intel: scripts/build-macos.sh amd64
```

脚本会生成主程序和 companion helper，并分别使用固定 code identifier 签名。没有 Developer ID 时默认使用 ad-hoc 签名且保持开发模式；设置 `V_LOCAL_KEY_PROVIDER_CODESIGN_IDENTITY` 后才生成启用运行时信任门禁的发行构建。正式工作流会把两者放入签名 DMG，提交 notarization、检查零 warning/error 日志，并对 DMG 执行 staple/validate；裸可执行文件仍随 GitHub/npm 发布，但附票由 DMG 承载。

构建和签名 Windows 发布件可以运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
# ARM64:
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1 -Arch arm64
```

正式 Windows 构建必须增加 `-Release -CertificateThumbprint <thumbprint>`。脚本在签名前把叶证书 SHA-256 注入二进制，签名后再核对同一身份并生成 `manifest.json`；普通构建不能据此宣称 Authenticode 已验证。

完整的 Phase 0–5 自动化、真机和签名发布门禁见 [REGRESSION_TESTS.md](REGRESSION_TESTS.md)。Windows/macOS 真机回归必须由手动触发的专用 self-hosted runner 执行，普通 CI 和交叉构建不会升级真实设备支持状态。

## 许可与边界

- 本程序独立成仓、独立发布、独立许可，与任何调用它的工具划清代码、权限与发布的边界；本文件不构成法律意见。
- 采用个人非商业许可（`v-local-key-provider Personal Non-Commercial License 1.0`），不是 OSI 批准的开源许可，且仅限用户对本人拥有或已获明确授权访问的数据使用。商业使用、再分发、作为托管服务提供或出售，都需要事先取得书面许可，详见 [LICENSE](LICENSE)。
