# v-local-key-provider

`v-local-key-provider` 是独立安装的本地密钥候选 Provider。它通过 `v-local-key-provider/v2` stdin/stdout JSON 协议，在用户明确授权后读取本人微信进程中的候选密钥，再由调用方使用本地数据库和媒体样本独立验证。

本程序只适用于处理本人拥有或已获明确授权访问的数据。它不联网、不发送微信消息、不修改微信进程或文件，也不负责保存、解密或查询最终数据。

## 支持范围

| 平台 | 架构 | 状态 | 说明 |
| --- | --- | --- | --- |
| Windows | amd64 | 可构建 | 走 Windows 进程读取的代码路径。 |
| macOS | amd64（Intel） | 已在真机验证 | 微信 4.1.11 上动态断点取密钥已跑通；需要 companion helper，访问微信进程可能需要用户临时关闭 SIP。 |
| macOS | arm64（Apple Silicon） | 实验性 | 同一套流程，但尚未在真机验证；需要 companion helper，访问微信进程可能需要用户临时关闭 SIP。 |
| 其他平台 | 不适用 | 不支持自动获取候选密钥 | 可以继续使用调用方提供的候选文件。 |

macOS 的自动路径仍然受微信版本影响。4.1.x 的数据库密钥通常只在 CommonCrypto 调用的瞬间出现在寄存器中，Provider 会自动安装短时动态断点；旧版本仍然保留静态内存扫描。无论走动态断点还是静态扫描，候选都必须通过数据库首页验证，Provider 不会把零结果报成成功。

### 微信版本兼容矩阵

| 微信版本 | x86_64 | arm64 | 首选路径 | 失败时的回退路径 |
| --- | --- | --- | --- | --- |
| 4.1.10、4.1.11 及后续 4.1.x | 4.1.11 已在本机验证；其他版本尽力尝试 | 实验性，未在本机验证 | CommonCrypto 动态断点 | 静态扫描 |
| 4.0.x | 实验性，未在本机验证 | 实验性，未在本机验证 | 静态扫描 | CommonCrypto 动态断点（可用时） |
| 3.x 及更早版本 | 未验证 | 取决于微信构建，未验证 | 静态扫描 | 无保证 |
| 未识别版本 | 尽力尝试 | 尽力尝试 | 先静态扫描，再尝试动态断点 | 返回版本诊断，不返回未经验证的候选 |

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

正因为两种 ABI 读取的寄存器不同，一种架构的验收结论不能外推到另一种：x86_64 已在 Intel 真机上用微信 4.1.11 验证了自动获取密钥，arm64 仍属于实验性的 `build_only`，要等在 Apple Silicon 真机上完成对应微信版本的验收之后，才能说该架构支持自动获取密钥。

## 安装

正式发布后的安装入口为：

```sh
npx @zanescope/v-local-key-provider@latest install
```

npm 包只负责下载、校验并全局安装对应的 Go 二进制，不包含 Provider 的实现源码。macOS 上会同时把 `v-local-key-provider-helper` 安装到主程序同目录；用户不需要单独运行 helper、传递路径或处理中间候选。当前仓库尚未创建正式 Release，因此包也不会提前发布。

## macOS 使用前准备

### 默认流程

macOS 的默认 helper 模式是 `auto`：

1. Provider 先普通启动同目录的 helper。
2. 如果 `task_for_pid` 被拒绝，Provider 检查 SIP 状态。
3. SIP 已关闭时，Provider 自动弹出一次系统管理员授权，并以更高权限重试。
4. SIP 开启时，Provider 不会弹出无意义的密码框，而是返回 `sip_enabled` 诊断。

程序不会自动关闭 SIP、修改微信签名、注入微信，也不会把候选密钥写入文件。

### 临时关闭 SIP

只有当用户明确接受临时降低系统保护，并且确实需要使用没有 Developer ID 的本机兼容模式时，才执行下面的步骤。日常使用不应该长期关闭 SIP，取得密钥之后应该立即重新开启。

1. 完全退出微信、Provider 和 CLI，保持微信账号信息不变。
2. 进入 macOS 恢复模式：Intel Mac 在重启时按住 `Command-R`；Apple 芯片 Mac 关机后长按电源键，出现启动选项后选择“选项”。
3. 在恢复模式的“终端”中运行 `csrutil disable`。
4. 重启回到桌面后，按[触发一次数据库调用](#触发一次数据库调用)的四步完成一次授权。Provider 会自动启动 helper；如果系统弹出管理员授权提示，只确认这一次操作即可，不需要手工运行 helper。
5. **确认 setup 已经成功返回、密钥也已保存之后，必须恢复 SIP。**

恢复 SIP 的完整步骤：先退出 CLI、Provider 和微信，然后再次进入恢复模式——Apple 芯片 Mac 关机后按住电源键，直到出现“正在载入启动选项”，选择“选项”并点“继续”；Intel Mac 重新启动后立即按住 `Command-R`，直到出现 Apple 标志或地球图标，再按提示选择用户并输入登录密码。

进入恢复环境后，在顶部菜单选择“实用工具” > “终端”。这是恢复模式的终端，不是桌面上的终端。在其中运行 `csrutil enable`，看到命令成功完成后再运行 `csrutil status`，确认输出包含 `System Integrity Protection status: enabled`。然后运行 `reboot`，或者从左上角 Apple 菜单选择“重新启动”。回到桌面后可以在普通终端再次运行 `csrutil status`，确认仍然是 `enabled`，再进行日常使用。

把恢复模式终端关掉并不等于恢复 SIP，必须执行 `csrutil enable` 并重启。如果用户不接受关闭 SIP，应该改用调用方的 `--keys FILE` 导入已经取得的候选文件，而不是反复重试自动 helper。

### Agent/CLI 反馈契约

调用方收到下列任一状态时，必须把它反馈给用户，而不是显示“没有找到密钥”或者继续盲目重试：

| CLI 错误 | Provider 诊断 | 用户需要做什么 |
| --- | --- | --- |
| `key_provider_sip_required` | `process_access_error=sip_enabled` | 当前启用了 SIP。先按[临时关闭 SIP](#临时关闭-sip)处理，回到桌面后再走[触发一次数据库调用](#触发一次数据库调用)；取得密钥后务必执行 `csrutil enable` 恢复保护。 |
| `key_provider_hook_trigger_required` | `process_access_error=hook_trigger_required` | 动态断点已经装好，但这一次没有触发数据库调用。按[触发一次数据库调用](#触发一次数据库调用)重来一遍。 |
| `key_provider_hook_restart_required` | `process_access_error=hook_restart_required` | 微信需要在动态断点安装之后重新打开数据库。同样按[触发一次数据库调用](#触发一次数据库调用)重来一遍。 |

CLI 和 Provider 不会自动修改 SIP，也不会自动启动、退出或重启微信；helper 与 `lldb` 都由 Provider 自己处理。

在用户完成恢复模式操作并回到桌面之前，Agent 不应该自动重试，不应该要求用户手工运行 helper，也不应该要求用户提供任何私钥、密码或候选值。

收到 `hook_trigger_required` 时，Agent 还应该向用户说明：当前进程的数据库已经打开，普通地切换会话不一定会重新创建加密上下文，所以反复打开聊天没有用，必须按上面的顺序完整重来一次。

## 快速开始

Provider 由调用方在一次明确授权下启动。调用方应该保持微信已登录，并使用对应的账号目录和数据库目录：

```sh
v-local-cli setup --allow-key-access --storage keychain
```

该命令让 Provider 在一次请求中同时申请 `database` 和 `image` 两个 scope；调用方会用本地数据库和真实 DAT 独立验证候选，并在验证成功后把两类密钥一起保存。成功输出应确认 `status=ready`、`media.status=verified`、`database_keys_persisted=true` 和 `image_keys_persisted=true`。只有明确的 database-only 任务才使用 `v-local-cli setup --allow-key-access --storage keychain --database-only`，此时 Provider 只申请 `database` scope。后续媒体刷新使用 `refresh --require-media`，仍不需要再读取微信进程；只有凭据缺失、账号目录改变，或者出现未覆盖的新数据库分片时才需回到 setup。

## 安全边界

- 只处理本人拥有或已获明确授权访问的数据。
- 不注入、不修改微信进程和微信文件。
- 请求通过 stdin 传入，响应通过 stdout 返回；密钥不出现在命令行参数中。
- macOS 的 companion helper 使用同一套受限协议和同一次授权，只由主程序自动调用。
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

当前协议标识为 `v-local-key-provider/v2`：

```json
{
  "protocol": "v-local-key-provider/v2",
  "request_id": "一次性请求标识",
  "action": "acquire",
  "account_dir": "绝对路径",
  "db_dir": "绝对路径",
  "scopes": ["database", "image"],
  "deadline_ms": 75000
}
```

请求通过 stdin 传入，响应通过 stdout 返回。响应中的 `database_keys`、`image_keys.aes` 与 `image_keys.xor` 都只是候选值，必须由调用方使用本地样本独立验证；不要把 Provider 的原始 stdout 写入日志或交给 Agent。

### 关键诊断字段

| 字段 | 说明 |
| --- | --- |
| `helper_status=not_installed` | 同目录的 helper 不存在或不可执行。 |
| `helper_status=used` | 普通 helper 已执行。 |
| `helper_status=elevated` | 已通过系统管理员授权执行 helper。 |
| `helper_status=sip_enabled` | SIP 开启，兼容路径未启动。 |
| `wechat_version`、`process_architecture` | Provider 实际识别到的微信版本和主进程架构，用于判断走兼容矩阵的哪个分支。 |
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

`hook_trigger_required` 和 `hook_restart_required` 的处理动作见[触发一次数据库调用](#触发一次数据库调用)。

### 时限

`deadline_ms` 是调用方给定的超时上限（毫秒，最大 3600000）。本程序在遍历内存区域、读取每个 1 MiB 分块，以及验证每个口令候选之前都会检查时限，到时间就停止并返回**已经验证出的候选**，同时在诊断中给出 `budget_exhausted` 与 `elapsed_ms`。

之所以需要这个上限，是因为内部允许的工作量远超调用方的等待时间：单次口令验证需要 25.6 万轮 PBKDF2-HMAC-SHA512（实测约 164 毫秒），候选上限 10000 且分四组尝试，最坏情况合计可达十几分钟。没有时限时，调用方只能超时杀掉进程，已完成的工作全部作废。

超出时限的幅度受检查粒度限制：内存扫描最多超出一个分块（约 18 毫秒），口令验证最多超出一次验证（约 164 毫秒）。

旧的 `v-local-key-provider/v1` 请求不带 `deadline_ms`，仍然接受并按无限时限运行，行为与历史一致；v1 请求如果携带 `deadline_ms` 会被拒绝。响应会回显本次请求使用的协议版本。

## helper 模式

默认值是 `auto`。开发或排错时可以通过环境变量覆盖：

```sh
export V_LOCAL_KEY_PROVIDER_MACOS_HELPER_MODE=auto
```

可选值：

- `auto`：普通启动被拒绝后，按 SIP 状态决定是否请求管理员授权。
- `direct`：只普通启动，不请求管理员授权。
- `elevated`：直接走管理员授权路径。

除非正在排错，不要改变默认值。

## 开发与构建

```powershell
go test ./...
go vet ./...
go build -trimpath -o build/v-local-key-provider.exe .
```

macOS 构建应该保持 cgo 开启，并使用与目标机器匹配的架构：

```sh
scripts/build-macos.sh arm64
# Intel: scripts/build-macos.sh amd64
```

脚本会生成主程序和 companion helper，并分别签名。没有 Developer ID 时默认使用 ad-hoc 签名，依靠上面的管理员授权兼容路径在本人机器上做实验；如果以后取得 Developer ID，设置 `V_LOCAL_KEY_PROVIDER_CODESIGN_IDENTITY` 后即可切换为正式签名，并另行 notarization。

构建和签名 Windows 发布件可以运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build.ps1
```

## 许可与边界

- 本程序独立成仓、独立发布、独立许可，与任何调用它的工具划清代码、权限与发布的边界；本文件不构成法律意见。
- 采用个人非商业许可（`v-local-key-provider Personal Non-Commercial License 1.0`），不是 OSI 批准的开源许可，且仅限用户对本人拥有或已获明确授权访问的数据使用。商业使用、再分发、作为托管服务提供或出售，都需要事先取得书面许可，详见 [LICENSE](LICENSE)。
