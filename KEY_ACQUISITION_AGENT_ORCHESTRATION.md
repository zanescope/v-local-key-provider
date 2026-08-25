# 本地微信数据库凭据获取与 Agent 编排最终方案

## 1. 文档状态

本文是 `v-local-key-provider` 与 `v-local-cli` 的密钥获取、持久化、逐库派生、验证和 Agent 编排最终设计，并记录 Phase 1/2 的实现对照；后续阶段仍以本文门禁作为评审与验收依据。

### 1.1 目标态与当前能力门禁

本文同时描述最终目标态和分阶段实现，不能把目标态步骤当成当前二进制已经具备的能力。Agent 每次编排都必须先服从当前能力门禁和本次 Provider 的结构化机器证据；章节顺序、设计中的“必须”或历史成功案例都不是能力证明。

当前能力状态与升级条件只在下表维护；其余章节定义目标行为或引用本表，不得另行宣布能力已经升级。

| 能力或门禁 | 当前状态 | 唯一允许的升级条件 |
| --- | --- | --- |
| macOS standard 动态路线 | `build_only`；生产 `darwinCompatibilityRegistry` 为空 | Intel 与 Apple Silicon 分别完成 cgo 构建、授权真机验证，并加入绑定候选二进制摘要、签名身份、精确 fingerprint、route、完整 coverage 与 profiles 的 eligible registry/evidence。 |
| Windows `Config.Cipher` 与通用 fallback | `build_only`；生产 `windowsCompatibilityRegistry` 为空 | x64 与 ARM64 分别取得同等强度的精确、内容寻址真机证据；fallback 还必须由 eligible registry signer 锚定。 |
| macOS Shadow | `unavailable_in_build` | 创建、签名和运行路线实现完成，通过对应架构真机测试，并产生与候选二进制摘要绑定的签名发布证据后，才可进入 `available/awaiting_approval`。 |
| 生产 cipher profile | 仅包含已有证据项 | 新 profile 必须由真实历史/迁移数据库逐文件 HMAC 证据支持；fixture、参数化测试或“无候选命中”不能升级生产声明。 |
| Phase 5 正式发行 | 外部 promotion 实现已完成；被空 registry/evidence 和未执行真机验收阻止 | 每个发布目标架构均有 eligible registry 候选条目；live workflow 按 run id 下载并验证 GitHub-attested 候选；内容寻址 evidence 经外部 promotion 与候选源码提交、Provider/helper 摘要、条目和架构完全绑定；随后仍须满足最终签名件复验、notarization/Trusted Publishing 与干净机器验收。promotion 不参与候选编译，已消除自引用哈希环。 |
| A1 包边界 | 领域分包、session store、release evidence validator 与 `cmd/v-local-key-provider` wiring 已完成；已有 `internal/{workbudget,crypto,catalog,credential,protocol,diagnostics,releaseevidence,session,platform}`。root 已是可导入的 `provider` 包，唯一 `package main` 是薄命令入口；Windows 内存遍历和 Darwin 进程解析已通过回调下沉。最终 Darwin Mach/cgo attach 与少量 Windows handle 编排仍是 build-tagged Provider adapter | 仅在对应 OS/cgo runner 可回归时继续移动持有原生 handle 的 adapter；必须保持候选 collector、deadline、敏感内存清理和 TOCTOU 复核的窄接口。目录变化本身不是运行时能力证据。 |

普通 CI、mock、交叉编译、历史记录、签名或 notarization 不能单独解除任何真机门禁。macOS 固定按 `standard -> shadow -> sip_disabled` 排序：当前 Shadow 槽位必须如实返回 `unavailable_in_build`，不得伪造运行失败；标准路线已有机器失败证据且 SIP 状态已验证时，允许向用户提供较低优先级的 `disable_sip` 选择。未来 Shadow 可用后必须先进入 Shadow 判断，不能从 `available/awaiting_approval` 直接跳到 SIP。

Phase 5 的候选摘要必须来自 `Release candidate` 产生且经 GitHub artifact attestation 验真的候选件。live workflow 必须按 run id 下载并直接执行该资产，不能本地重建。签名构建只接受位于 `compatibility-evidence/promotions/` 的 reviewed promotion，并验证候选提交到 release tag 之间没有 `compatibility-evidence/**` 之外的变化；构建脚本不得从自己即将生成的 release 二进制推导或伪造候选摘要。

本方案基于以下实现与社区路线复核后形成：

- 当前 `v-local-key-provider` 和 `v-local-cli`；
- `TANGandXUE/wcdb-key-tool`；
- `dylan121322/wxkey-hook`；
- `r266-tech/wxkey`；
- `Thearas/wechat-db-decrypt-macos`；
- WeFlow pre-DMCA 源码提交 `a7656bf26776f6e0026b754de90fd07d2f037966`。

社区项目的版本结论、变量命名和成功案例只作为路线参考。候选类型、数据库归属和覆盖率最终以目标数据库的密码学验证、文件身份和账号绑定证据为准。

## 2. 最终决策摘要

1. 允许同时修改 Provider 和 CLI；不再坚持“只改 Provider、调用方完全不变”。
2. 首个公开协议统一为结构化、可编排的 `v-local-key-provider/v1`；Provider 与 CLI 在发版前原子迁移，不保留任何未发布旧协议兼容路径。
3. 长期凭据采用“账号级全局 passphrase 优先、逐库 raw `enc_key` override、允许 mixed 模式”。
4. `database_keys` 只表示当前数据库 catalog 已派生且已验证的最终逐库 `enc_key`，不再用它重复承载全局 passphrase。
5. 全局 passphrase 只有在完整调用证据和目标数据库 HMAC 验证支持时才接受；不能仅凭 32 字节长度、微信版本或社区描述判定。
6. 每个物理数据库文件独立验证。相同 salt 只允许复用派生计算，不允许复用验证结论。
7. macOS 获取优先级固定为：标准模式、Shadow 模式、SIP-disabled 模式；未实现的 Shadow 以终态 `unavailable_in_build` 占位，不成为硬依赖。
8. 标准路线已有机器失败证据，且 Shadow 为 `unavailable_in_build`、`unsupported_for_target` 或 `attempted_failed` 时，才允许明确提供 SIP-disabled fallback；用户仍可拒绝。
9. Provider 和 Agent 不自动关闭 SIP；用户必须在恢复环境中手工执行。成功后必须引导重新开启 SIP 并验证恢复状态。
10. Windows 优先使用已登记二进制指纹的 `Config.Cipher` 定向路径，通用内存扫描只作为有界 fallback。
11. 多账号、多进程候选必须在验证前隔离，并绑定进程实例而非仅绑定 PID。
12. “全部首页 HMAC 通过”命名为 `key_coverage_complete`，不等价于数据库/WAL/SQLite 全量完整性验证。

## 3. 范围与非目标

### 3.1 本方案负责

- 发现目标账号目录下需要密钥的数据库；
- 获取全局 passphrase 或逐库 raw `enc_key` 候选；
- 识别候选类型和 SQLCipher/WCDB profile；
- 派生当前 catalog 的逐库最终 `enc_key`；
- 对每个物理数据库文件做首页 HMAC 验证；
- 保存结构化凭据到系统凭据库；
- 为 Agent 提供可恢复、有界、可解释的操作状态机；
- 在对应 route 已通过 1.1 能力门禁时，逐级引导标准、Shadow、SIP-disabled 三种 macOS 路线；
- 向 snapshot generation 构建阶段提供与 catalog 绑定的逐库有效 key。

### 3.2 本方案不负责

- 绕过用户授权读取其他用户或其他账号的数据；
- 修改微信数据库内容；
- 自动发送消息或执行有副作用的微信操作；
- 把首页 HMAC 验证表述为整个数据库内容完整；
- 自动关闭或开启 SIP；
- 将关闭 SIP 作为所有 macOS 用户的默认要求；
- 依赖微信私有网络接口；
- 新增必须依赖对话记忆或外部 Skill 才能正确运行的秘密获取逻辑；Agent 只编排 Provider v1 暴露的机器状态和动作；
- 在正常日志中输出 passphrase、raw key、派生 key、内存地址或绝对账号路径。

## 4. 核心术语

### 4.1 Credential 与 effective key

`credential` 是长期或短期保存的根凭据：

- `global_passphrase`：与每库 salt 结合后派生最终 `enc_key`；
- `raw_enc_key`：已经是某个数据库可直接使用的最终加密 key。

`effective_enc_key` 是对一个具体数据库、具体 profile、具体文件 catalog 条目最终使用的 32 字节 key。

任何候选在输出到 `database_keys` 前都必须归一化为逐库 `effective_enc_key`。

### 4.2 Catalog

Catalog 是一次获取与一次 snapshot generation 共同使用的不可变数据库清单。它用于防止发现、验证和复制之间发生文件替换或轮转。

### 4.3 Acquisition session

Acquisition session 是跨 `prepare/observe/finalize` 调用存活的短期会话。它保持 hook、候选、进程实例绑定、动作回执和阶段预算，不依赖 Agent 对话记忆保存秘密。

### 4.4 Key coverage

`key_coverage_complete` 表示 catalog 中所有需要密钥的物理数据库文件都有唯一的、通过首页 HMAC 的 `effective_enc_key`。

它不证明所有数据页、WAL 或 SQLite 结构完整；后者由 CLI 的 generation 构建和查询前验证负责。

## 5. 凭据模型

### 5.1 三种模式

```text
global_passphrase
    同一账号级 passphrase 覆盖当前全部合格数据库

per_database
    每个数据库只能由逐库 raw enc_key 覆盖

mixed
    全局 passphrase 覆盖一部分数据库，其他数据库使用逐库 override
```

`mixed` 是正式支持的正常状态，不能把它当成异常或强行用一把凭据覆盖所有数据库。

### 5.2 结构化凭据

概念结构如下：

```yaml
database_credential:
  mode: global_passphrase | per_database | mixed
  credential_epoch: random-id
  account_binding_id: opaque-account-id
  roots:
    - credential_id: random-id
      kind: global_passphrase
      profile_id: wcdb-v4-sha512-256000
      secret: <仅出现在受控秘密通道>
      scope: account
      verified_catalog_id: <catalog-id>
      verified_database_ids: [<opaque-db-id>]
      source_evidence: [macos_pbkdf_hook]
  overrides:
    <opaque-db-id>:
      kind: raw_enc_key
      profile_id: <profile-id>
      secret: <仅出现在受控秘密通道>
      source_evidence: [macos_cccrypt_hook]
```

系统凭据库保存 secret；普通状态文件只保存 `credential_id`、`profile_id`、账号绑定、验证 catalog 和凭据库引用。

### 5.3 `database_keys` 的最终语义

```yaml
database_keys:
  contact/contact.db: <current effective enc_key>
  message/message_0.db: <current effective enc_key>
```

规则：

- value 永远是当前文件已经通过 HMAC 的最终 `enc_key`；
- 不允许把全局 passphrase 按路径重复填入 map；
- 只服务当前 catalog 和当前 generation 构建；
- 长期恢复能力来自 `database_credential`，不是来自这张临时派生 map；
- v1 响应同时返回当前 map 和独立的结构化根凭据；二者语义不可混用。

### 5.4 为什么优先保存 passphrase

当 passphrase 被证明是账号级全局凭据时，保存它有以下收益：

- 不依赖数据库是否曾被微信打开；
- 下一次 refresh 可为新出现的数据库自动派生 key；
- 避免为了补一个未触发数据库再次 attach 或重登；
- 减少长期保存的独立秘密数量；
- 可按唯一 salt 复用 KDF 结果，降低重复计算。

代价是 passphrase 能派生未来数据库 key，泄露影响范围更大。因此只能进入系统凭据库，不能进入普通 JSON、诊断、临时文件或日志。

### 5.5 接受全局 passphrase 的条件

候选必须同时满足：

1. 来源调用参数符合已知或探测成功的 passphrase KDF profile；
2. password、salt、PRF、rounds、输出长度等调用证据完整；
3. 至少在一个目标数据库上派生并通过 HMAC；
4. 对当前 catalog 的每个唯一 salt 派生；
5. 每个物理数据库文件独立通过 HMAC；
6. 不能被更合理地解释为只属于一个数据库的 raw key。

如果当前只有一个数据库或只有一个唯一 salt，只能在本次 session 内把它保留为 `global_candidate` 证据；长期凭据降级保存该数据库已验真的 effective key override，不能声称或持久化为账号级全局根。出现第二个 salt 后必须用同一根候选重新逐文件验证，成功后才升级为 `global_passphrase`。

## 6. SQLCipher/WCDB Profile

### 6.1 Profile 字段

```text
profile_id
page_size
reserve_size
kdf_algorithm
kdf_prf
kdf_iterations
hmac_algorithm
hmac_kdf_algorithm
hmac_kdf_iterations
page_number_endian
plaintext_header_size
hmac_input_layout
```

不能只写“SQLCipher 4”后硬编码全部参数。WCDB cipher compatibility、历史库、迁移库或特殊数据库可能使用不同 profile。

### 6.2 Profile 选择

选择顺序：

1. 已登记的微信版本、架构和二进制指纹 profile；
2. 动态 hook 提供的完整 KDF/crypto 参数；
3. 对安全、有界的 profile 集合逐个做 HMAC 探测；
4. 密文本身没有 authenticated profile marker；无法预判时保持 `encrypted_eligible` 且 `profile_id` 为空，只对已登记的有界 profile 集合逐个做完整 HMAC 验证。全部不命中只能报告 missing，不能伪造“已证明 unsupported”。

### 6.3 验证规则

- raw key 必须执行首页解密和 HMAC，不能只检查 SQLite header；
- passphrase 先在代表数据库派生，命中后按唯一 salt 扩展；
- 同 salt 文件可以共用派生出的 `enc_key`，但每个文件必须单独验 HMAC；
- 多种 credential 产生同一个 `effective_enc_key` 时合并来源，不算歧义；
- 不同 `effective_enc_key` 对同一文件、同一 profile 都通过 HMAC 时，优先判定为验证器错误、文件漂移或 profile 错误，不能作为普通 `ambiguous` 自动继续。

## 7. 数据库 Catalog 与覆盖率

### 7.1 Catalog 条目

数据库发现递归扫描目标 `db_dir` 下的全部 `.db` 文件，不因为微信当前没有打开某个数据库而排除它。独立的 `-wal` 和 `-shm` 文件不作为数据库条目；它们在 generation 稳定复制阶段与主库关联处理。

加密数据库必须能读取完整首页并取得 16 字节 salt。无法读取、首页不完整或已经是明文 SQLite 的文件都生成条目并记录 classification，不能静默忽略；profile 只在候选通过完整首页 HMAC 后成为权威值。

每个发现的 `.db` 文件生成：

```yaml
database:
  database_id: <本机密钥化的 opaque id>
  relative_path: <默认诊断可隐藏>
  canonical_file_id: <platform file identity>
  size: 0
  mtime_ns: 0
  first_page_sha256: <digest>
  salt: <16-byte digest or protected value>
  classification: encrypted_eligible | plaintext | unreadable | unstable | truncated
  required_for_key_coverage: true | false
```

`database_id` 使用本机随机秘密做 HMAC，避免直接把账号路径和稳定文件名暴露到诊断中。

### 7.2 目录安全

- 对 `account_dir` 和 `db_dir` 做真实路径解析；
- 验证 `db_dir` 位于目标账号目录允许范围内；
- 拒绝越界 symlink、junction 和 reparse point；
- Windows/macOS 按平台文件系统规则处理大小写和 Unicode 归一化碰撞；
- 发现期间出现遍历、打开、读取或相对路径计算错误时必须记录，不能静默跳过后返回完整覆盖。

### 7.3 Catalog ID

`catalog_id` 由排序后的条目身份、大小、mtime、首页摘要、classification 和 profile 共同计算。

Provider finalize 返回的 key map 必须绑定 `catalog_id`。CLI stable copy 前重新核对文件身份和首页摘要；不一致时废弃对应 key 结果并重新 catalog，而不是继续构建 generation。

### 7.4 覆盖状态

```text
required_database_count
matched_database_count
missing_database_count
unreadable_database_count
unstable_database_count
```

`database_coverage_status`：

- `not_requested`：本次请求未包含 `database` scope；
- `none`：没有必需数据库通过；
- `partial`：部分必需数据库通过，或仍有必需文件无法分类/读取；
- `complete`：全部必需数据库逐文件 HMAC 通过，且 catalog 无未处理发现错误。

明文 SQLite 文件标记为 `plaintext`，不需要数据库 key，但仍由 generation 构建阶段处理。

## 8. 候选与进程隔离

### 8.1 候选结构

```yaml
candidate:
  candidate_id: random-id
  kind: unknown_32_bytes | global_passphrase | raw_enc_key
  secret: <secure buffer>
  source: macos_pbkdf_hook | macos_cccrypt_hook | windows_config_cipher | structured_memory | fallback_scan
  process_instance_id: <pid+start-time+exe-identity>
  binary_fingerprint: <version+arch+signature+hash>
  captured_at: <monotonic time>
  call_evidence:
    algorithm: ...
    prf: ...
    rounds: ...
    password_length: ...
    salt_length: ...
    output_length: ...
  associated_database_ids: []
  associated_salts: []
```

### 8.2 进程实例

不能只使用 PID。`process_instance_id` 至少包含：

- PID；
- 进程启动时间；
- canonical executable path；
- 实际运行架构；
- 代码签名 Team ID/designated requirement 或 Windows Authenticode 身份；
- executable hash；
- bundle/product identity。

PID 复用或进程重启后必须创建新实例。

### 8.3 多进程规则

- 每个微信进程使用独立 candidate collector；
- 验证前禁止跨进程合并候选；
- 候选先对目标账号 catalog 验证；
- 验证成功后只能合并相同 `effective_enc_key` 的来源证据；
- 当前登录 B、目标数据 A 时，B 进程候选不得因为名称相同而进入 A 的保存流程。

### 8.4 候选尝试优先级

在相同安全证据和预算条件下，候选按以下顺序尝试：

1. macOS 完整 PBKDF 调用证据支持的全局 passphrase；
2. macOS `CCCrypt*` 捕获的逐库 raw key；
3. Windows 已登记 `Config.Cipher` 候选；
4. 结构化 key object；
5. salt 邻域候选；
6. 有界普通十六进制候选。

优先级只决定尝试顺序，不能替代目标数据库 HMAC。普通 64 位十六进制字符串不得无条件全部进入高成本 PBKDF2。

## 9. 账号绑定

区分：

```text
target_data_binding
    候选是否属于目标账号目录的数据

session_account_binding
    当前微信进程的活动账号是否为目标账号
```

证据优先级：

1. 候选通过目标 catalog 数据库 HMAC；
2. 进程打开了目标账号目录的数据库文件；
3. 进程内可验证账号标识与目标本地标识一致；
4. 命令行、应用路径和进程名只能证明它是微信，不能证明账号；
5. 用户口头确认只作为动作授权，不能替代机器证据。

状态：

```text
target_binding_status:
  hmac_verified | path_verified | mismatch | unknown

session_account_status:
  known_target | known_other | unknown
```

明确错账号时不得保存新凭据；已经对目标数据独立 HMAC 通过的旧结果可以保留，但必须隔离本次错账号候选。

明确 mismatch 包括：进程打开了其他账号目录、进程内强账号标识对应其他账号，或候选只对其他账号数据库有效而对目标账号全部失败。此时返回 `result_code=action_required`、`next_action=switch_to_target_account` 和 `blocking_reasons=[account_mismatch]`，不能伪装成权限错误。

没有找到打开句柄、启动早期尚未打开数据库、只有一个进程但无法取得账号标识或命令行没有账号信息时，只能标记 `unknown`。unknown 状态允许继续候选获取，但候选必须通过目标数据库 HMAC，且结果不得表述为“当前登录账号已机器确认”。

## 10. Provider v1 协议与 Acquisition Daemon

### 10.1 首发版本策略

- 首个公开、受支持的协议固定为 `v-local-key-provider/v1`。
- v1 从首发起就包含 catalog、结构化 credential、session、动作回执和三种 macOS 路由，不先发布残缺协议再升级。
- 当前源码中的未发布协议常量和测试数据由 Provider、CLI 一次性同步迁移到 v1；不提供旧协议 fallback。
- 发版前的本地状态、测试 fixture 和开发构建不构成兼容承诺；迁移脚本只负责清理或重建这些未发布数据。
- 首次发版后，v1 的新增可选字段必须保持向后兼容；只有无法兼容的契约变更才提升主版本。
- 不允许把结构化 passphrase 伪装成 `database_keys`，版本号不能替代字段语义。

### 10.2 请求概念结构

```yaml
protocol: v-local-key-provider/v1
request_id: random-id
action: acquire
catalog_key: <当前用户私有目录保存的 32-byte machine catalog HMAC key>
account_dir: ...
db_dir: ...
scopes: [database, media]
deadline_ms: 30000
workflow:
  operation: prepare | observe | finalize | cancel | revalidate_security_posture
  session_id: optional
  expected_catalog_id: observe/finalize 必填，cancel 可省略
  action_receipt:
    action: trigger_database | restart_wechat | relogin_wechat | switch_to_target_account
    user_confirmed: true
    observed_process_transition: optional
```

`action_receipt` 只承载同一桌面 session 内可以由 Provider 立即取得机器证据的 Phase 2 动作。`approve_shadow_mode`、`disable_sip`、`reenable_sip` 不属于可恢复 daemon receipt：它们涉及新进程、恢复环境或系统重启，必须结束旧 session，完成用户手工操作后创建新 session，并重新检查二进制、进程实例、账号绑定和 SIP 状态。CLI 的通用 `--allow-key-access` 只授权进程访问，不等于确认任何具体动作；只有同 session 的 `trigger_database`、`restart_wechat`、`relogin_wechat`、`switch_to_target_account` 或 `stop_and_report` 才能通过匹配的 `--confirm-key-action <next_action>` 生成 receipt。跨重启流程不得携带或复用该参数。

跨重启连续性由 CLI 当前用户私有目录中的 authority-free checkpoint 提供，而不是保持 daemon 或 Agent：

- checkpoint 只保存随机 workflow ID、opaque account/provider ID、scopes、`revalidation_stage`、`prior_requested_action`、上一 catalog ID、安全姿态和有效期；`prior_requested_action` 是重启前的历史请求，不是当前仍应执行的动作；
- 不保存路径、daemon token、session ID、进程实例、候选、密钥、`action_receipt`、`user_confirmed` 或长期授权；未知字段、过期记录和 ACL/文件类型异常一律 fail-closed；
- `status` 与 `setup --dry-run` 可以发现 checkpoint，并必须明确显示 `session_resumable=false`、`authorization_carried_forward=false`、`machine_revalidation_required=true`；
- 重启后重新运行普通 `setup --allow-key-access`，不得携带旧 `--confirm-key-action`。关闭 SIP 后进入获取阶段时，CLI 创建全新 acquisition session，Provider 重新读取 SIP、版本、架构、签名、进程实例、账号绑定和 Catalog；恢复阶段则使用下述独立只读复核请求。checkpoint 不能让任何状态跳过对应的机器验证；
- `disable_sip -> reenable_sip` 可以保留同一个 workflow ID，但每一段都是独立请求或 session。新的只读姿态复核请求验证 SIP 已恢复并正常 terminal 后才删除恢复阶段 checkpoint；显式 cancel 同时清理同 session resume 与 checkpoint。若用户没有执行 `disable_sip`，后续普通 acquisition 在 SIP 仍开启的机器证据下完整成功，也必须清理已经失效的关闭阶段 checkpoint。
- 当 checkpoint 已进入 `security_restoration_revalidation_required` 时，CLI 必须改用一次性的 `revalidate_security_posture` 请求，只读验证 SIP，不启动 daemon/helper/hook、不扫描进程、不重新获取或返回任何 credential。只有 CLI 当次直接调用 Provider 所得的新响应返回 `sip_enabled_verified + complete + terminal` 后才删除 checkpoint；导入的候选文件、旧响应或仅匹配 diagnostics 形状的数据都不能声明机器复核完成。SIP 仍关闭或状态不可验证时保留 checkpoint。该操作不是 SIP 修改能力，Provider 仍然不能自动开启或关闭 SIP。
- 关闭阶段 checkpoint 的 scopes 必须与重启后的普通 acquisition 精确一致，不能用不同 scope 覆盖原 checkpoint。若普通 acquisition 在产生结构化姿态诊断前因 catalog、路径或 Provider 错误终止，CLI 只允许补做一次同样无 credential 的 `revalidate_security_posture`：仅当它确认 SIP 已关闭时，才把 checkpoint 转入 `reenable_sip`；SIP 仍开启、状态未知或复核本身失败时，保留原错误和 checkpoint。
- `revalidate_security_posture` 不得依赖账号/数据库路径仍然存在；请求中的路径只作为 CLI 已完成 account/provider checkpoint 绑定后的兼容字段，Provider 不得为该操作 stat、解析、扫描或创建这些路径。

`catalog_key` 只用于生成本机 opaque database/account/catalog ID，不是数据库凭据。CLI 在当前用户专属 acquisition 私有目录中生成一次并跨 setup/refresh 复用；它通过受控 stdin/IPC 传给 Provider，不进入 endpoint、resume、diagnostics 或 generation manifest。Provider session 销毁时清零内存副本。缺少私有目录的兼容 one-shot 调用使用一次性随机 key。

### 10.3 响应概念结构

本节是 `diagnostics` 稳定字段名与值域的唯一规范性 schema。后续章节只定义字段间不变量、隐私边界或验收场景，不得复制一份可独立漂移的字段清单；实现增加稳定机器字段时必须先更新本节。

```yaml
protocol: v-local-key-provider/v1
request_id: random-id
catalog_id: optional opaque-id
catalog_entries: optional []
database_keys: optional {opaque-database-id: hex-effective-key}
database_profiles: optional {opaque-database-id: profile-id}
database_credential: optional structured-credential
image_keys: optional {aes: hex-key, xor: byte}
diagnostics:
  # 整体裁决与 scope 覆盖
  result_code: complete | partial | action_required | permission_required | ambiguous | unsupported | deadline_exhausted | cancelled | failed
  workflow_status: running | waiting_action | blocked | terminal
  requested_scopes: [database, media]
  database_target_status: not_requested | none | present
  database_coverage_status: not_requested | none | partial | complete
  media_coverage_status: not_requested | pending | none | complete
  security_posture_status: not_applicable | not_evaluated | sip_enabled_verified | sip_disabled_verified | restoration_required
  shadow_route_status: not_applicable | not_evaluated | unavailable_in_build | unsupported_for_target | available | awaiting_approval | attempted_failed | succeeded
  route_priority: [standard, shadow, sip_disabled]
  next_action: none | trigger_database | restart_wechat | relogin_wechat | switch_to_target_account | approve_shadow_mode | disable_sip | reenable_sip | fix_permission | stop_and_report
  blocking_reasons: [stable-blocking-reason]
  candidate_mode: none | global_passphrase | per_database_enc_key | mixed
  candidate_sources: []
  missing_database_count: integer
  missing_database_ids: [opaque-database-id]
  target_binding_status: unknown | hmac_verified | path_verified | mismatch
  session_account_status: unknown | known_target | known_other
  route_selected: optional route-id
  routes_attempted: [route-id]

  # session / action 绑定
  session_id: optional
  session_expires_at: optional RFC3339Nano
  process_instance_id: optional opaque-id
  action_stage: optional stable-enum

  # 平台、目标二进制与 route 证据
  phase_timings_ms: {phase-name: integer-ms}
  platform: darwin | windows | unsupported
  wechat_version: optional string
  wechat_build: optional string
  executable_sha256: optional hex-sha256
  binary_fingerprint_status: optional stable-enum
  binary_signing_status: optional stable-enum
  binary_signer_sha256: optional hex-sha256
  binary_product_identity: optional stable-enum
  signing_team_id: optional string
  designated_requirement_sha256: optional hex-sha256
  process_architecture: optional unknown | amd64 | arm64
  process_architecture_status: optional stable-enum
  process_translation_status: optional stable-enum
  macos_version: optional string
  compatibility_registry_status: optional stable-enum
  standard_route_status: optional stable-enum
  standard_route_evidence: [stable-evidence-enum]
  config_cipher_route_status: stable-enum
  windows_route_evidence: [stable-evidence-enum]
  process_access_status: optional stable-enum
  process_access_error: optional redacted-stable-enum
  helper_status: optional stable-enum

  # hook / fallback 观测
  hook_target_found: integer
  hook_installed: boolean
  hook_timeout: boolean
  hook_trigger_required: boolean
  hook_restart_required: boolean
  hook_relogin_required: boolean
  hook_capture_count: integer
  dynamic_hook_used: boolean
  static_scan_fallback: boolean
  version_support: optional stable-enum

  # 进程、catalog 与验证计数
  process_count: integer
  opened_process_count: integer
  access_denied_count: integer
  selected_process_count: integer
  target_bound_process_count: integer
  other_account_process_count: integer
  unknown_account_process_count: integer
  per_process_collector_count: integer
  database_count: integer
  required_database_count: integer
  plaintext_database_count: integer
  unreadable_database_count: integer
  unstable_database_count: integer
  truncated_database_count: integer
  matched_database_count: integer
  ambiguous_database_keys: integer
  validator_conflict_count: integer

  # 候选与扫描计数
  candidate_count: integer
  passphrase_candidate_count: integer
  kdf_budget_exhausted: boolean
  hex_pattern_count: integer
  raw_key_candidate_count: integer
  validated_database_candidate_count: integer
  key_object_pattern_count: integer
  dereferenced_key_candidate_count: integer
  passphrase_validation_count: integer
  key_object_structural_count: integer
  key_object_capacity_32_count: integer
  key_object_capacity_47_count: integer
  key_object_capacity_63_count: integer
  key_object_other_capacity_count: integer
  internal_xor_key_candidate_count: integer
  config_cipher_structure_count: integer
  config_cipher_invalid_structure_count: integer
  config_cipher_candidate_count: integer
  config_cipher_verified_candidate_count: integer
  fallback_candidate_count: integer
  fallback_stage_counts: {stage-name: integer}

  # media 候选与总预算
  v2_sample_count: integer
  xor_sample_count: integer
  xor_distinct_candidate_count: integer
  xor_leading_sample_count: integer
  xor_second_sample_count: integer
  media_aes_candidate_count: integer
  kvcomm_code_candidate_count: integer
  kvcomm_verified_candidate_count: integer
  media_candidate_method: optional stable-enum
  process_discovery_method: optional stable-enum
  scanned_bytes: integer
  scan_limited: boolean
  budget_exhausted: boolean
  elapsed_ms: integer-ms
```

`stable-blocking-reason` 的完整值域为：

```text
account_mismatch
database_targets_not_found
hook_not_triggered
database_open_required
login_time_derivation_required
wechat_not_running
process_access_denied
process_identity_untrusted
validator_conflict
candidate_ambiguous
deadline_exhausted
action_receipt_required
user_cancelled
catalog_drift
acquisition_request_in_progress
action_receipt_rejected
duplicate_action_without_state_change
action_retry_budget_exhausted
user_declined_action
standard_route_unavailable
shadow_route_failed
shadow_route_unavailable_in_build
shadow_route_unsupported_for_target
shadow_route_not_evaluated
security_posture_not_verified
helper_untrusted
user_declined_security_change
sip_route_failed
sip_disabled_route_not_attempted
```

其中 `user_declined_security_change` 保留给 session 外安全变更流程；其余值均有当前 Provider 生产者或明确的 Shadow 目标态生产者。`stable-enum` 与 `stable-evidence-enum` 表示 JSON 类型和值域必须由协议测试锁定，不能退化成自由文本；相应平台章节可以解释状态转换，但不能添加另一套同名字段定义。无 `optional` 标记的集合必须编码为空集合而不是 `null`。计数字段不得包含 secret、地址或路径。

Secret 字段只通过受控 stdin/stdout pipe 或本地 IPC 传输，CLI 捕获后立即写入系统凭据库。诊断、错误和 Agent 可见日志不包含 secret。

`prepare` 和 `observe` 响应不返回 `database_keys`、`database_credential` 或 `image_keys`；这些 secret 只在 finalize 重新发现并确认同一 `catalog_id` 后返回一次。daemon 可以在 session 内存中保存已经验真的中间结果，但不得把它们写入 endpoint、resume 或诊断。

### 10.4 Daemon 生命周期

Provider 用户入口是短命令，实际动态 hook 由同版本、同签名的本地 acquisition daemon 保持。

Daemon 要求：

- 本地 IPC 仅允许当前桌面用户和经过验证的 CLI/Provider 客户端；
- session token 使用加密随机数；
- 每个账号最多一个写入型 acquisition session；
- 默认 session wall-time 15 分钟，可配置但有硬上限；
- action window 结束、用户取消、客户端消失或 deadline 到期时 detach 并恢复目标进程；
- 不把候选或 passphrase写入磁盘恢复文件；
- daemon 崩溃后不得遗留暂停进程、breakpoint 或可复用 session；
- session 完成后清理安全缓冲、临时 Shadow 资源和 IPC endpoint。

### 10.5 三阶段操作

```text
prepare
    catalog + preflight + process binding + route selection + install hook

observe
    在 hook 保持期间接收用户动作回执并采集候选

finalize
    归一化候选 + 派生 + 逐文件 HMAC + 返回 credential 和 database_keys
```

Provider 返回 `trigger_database` 时 hook 必须仍由 daemon 保持；不能像一次性进程那样返回后丢失 hook。

每次 RPC 可以在返回动作状态后结束，但 acquisition daemon 和对应 hook 必须继续存活到 action window 到期、用户取消或 session 完成。

### 10.6 内部处理流水线

```text
REQUEST_VALIDATE
    -> HOST_PREFLIGHT
    -> TARGET_DATABASE_DISCOVERY
    -> SAVED_CREDENTIAL_COVERAGE
    -> PROCESS_DISCOVERY
    -> PROCESS_VERSION_ARCHITECTURE
    -> TARGET_BINDING
    -> ROUTE_SELECTION
    -> PRIMARY_ACQUIRE
    -> CANDIDATE_NORMALIZE
    -> CANDIDATE_VALIDATE
    -> PASSPHRASE_EXPAND
    -> LIMITED_FALLBACK
    -> FINALIZE
```

前置检查必须覆盖 Provider 平台、目标进程实际架构、微信版本/指纹、helper、SIP、进程权限、目标账号与数据库目录、数据库/唯一 salt 数量以及已存 credential 的现有覆盖率。

微信尚未运行时只能记录预估环境并进入 wait-for 状态；目标进程启动后必须重新确认版本、实际架构、签名、账号绑定和 route，不能沿用启动前估计。

## 11. 状态与重试模型

### 11.1 正交状态

字段定义与值域以 10.3 为准。本节只规定覆盖、工作流和安全姿态之间的正交关系与裁决不变量：

```text
requested_scopes[]
database_coverage_status
media_coverage_status
workflow_status
security_posture_status
result_code
blocking_reasons[]
next_action
```

这样可以同时表达：

```text
database_coverage_status=partial
media_coverage_status=not_requested
workflow_status=waiting_action
security_posture_status=sip_disabled_verified
blocking_reasons=[hook_not_triggered]
```

`result_code` 保留旧方案的可操作语义：

```text
complete
partial
action_required
permission_required
ambiguous
unsupported
deadline_exhausted
cancelled
failed
```

其中 `result_code` 是本次 RPC 整体结果的唯一权威字段，不能由任何单个 scope coverage 字段替代或反向推断。比如预算到期且已有部分数据库结果时，可以同时表达 `result_code=deadline_exhausted`、`database_coverage_status=partial`、`media_coverage_status=not_requested`。若预算到期前所有 requested scope 已经完整覆盖且没有待处理动作，则必须返回 `complete`。

scope coverage 必须满足以下不变量：

- `requested_scopes` 使用固定顺序 `database, media`，不得包含未知值或重复值；
- 未请求的 scope 必须返回 `not_requested`，不得用 `complete` 表示“无需执行”；
- 请求的 scope 不得返回 `not_requested`；
- `result_code=complete` 时，`workflow_status` 必须为 `terminal`，且所有 requested scope 的 coverage 必须为 `complete`；
- 任一 requested scope 为 `none`、`partial` 或 `pending` 时，`result_code` 不得为 `complete`；
- Agent 必须先依据 `result_code` 判断整体结果，再使用两个 scope coverage 字段解释缺口。

唯一例外是 `workflow.operation=revalidate_security_posture`：其 `requested_scopes` 只用于与 checkpoint 做关联，两个 acquisition coverage 必须保持 `not_requested`；此时 `result_code=complete` 只表示本次只读安全姿态复核完成，不表示重新获取了任何 credential。

`route_priority` 只表达评估顺序，不是执行历史；`routes_attempted` 只包含真正运行过的具体 route。`shadow_route_status=unavailable_in_build` 时不得把 Shadow 写入 `routes_attempted`，也不得用 `route_priority` 冒充 Shadow 失败证据。

### 11.2 稳定 route 标识

```text
darwin_arm64_standard_dynamic
darwin_amd64_standard_dynamic
darwin_arm64_shadow_dynamic
darwin_amd64_shadow_dynamic
darwin_arm64_sip_disabled
darwin_amd64_sip_disabled
darwin_standard_dynamic_waitfor
darwin_sip_disabled_waitfor
darwin_static_fallback
windows_config_cipher
windows_memory_fallback
```

route 标识只用于诊断、兼容 registry 和验收，不代表候选已验证。

### 11.3 重试规则

- 同一 `process_instance_id + catalog_id + route + action_stage` 未发生状态变化时不重复；
- 用户动作必须携带显式 action receipt；CLI 不得把普通重跑或 `--allow-key-access` 自动转换为 `user_confirmed=true`；
- receipt 中的 route、stage 和原 process instance 只用于绑定 Provider 已保存的状态，不能由调用方覆盖；restart 必须由 Provider 观测到新进程实例，账号动作必须有账号绑定证据；
- process start time、catalog ID、SIP 状态或账号绑定变化后才允许重置相应阶段；
- fallback 只处理 missing database IDs；
- `complete` 达成后即使临近 deadline，也以完整覆盖结束；
- 预算耗尽保留已验证结果，但不把 partial 提升为 complete；
- Agent 不得无限循环 trigger/restart/relogin；Shadow/SIP 操作不在同一 session 内循环或恢复。
- 用户拒绝当前 Phase 2 动作但希望保留已验真的 partial 时，CLI 以 `stop_and_report` 请求无 receipt 的 finalize；Provider 重新核对 catalog 后返回现有 partial 并销毁 session。该路径不能覆盖 mismatch、catalog drift 或其他阻塞状态。

## 12. macOS 路由

### 12.1 路由依据

兼容性登记项至少包含：

```text
WeChat version/build
executable SHA-256
signing Team ID/designated requirement
actual process architecture
macOS major/minor
route support state
validated cipher profiles
real-device evidence
```

版本号用于初筛，二进制指纹和真实探测决定最终路线。未知构建不能因为版本字符串相似就套用固定寄存器、偏移或内存结构。

### 12.2 实际架构

Universal Binary 不能通过 Provider 自身 `GOARCH` 判断目标架构。必须读取目标进程实际运行 slice 和 Rosetta/translatable 状态，再选择相同架构 helper 和寄存器 ABI。

### 12.3 标准模式

目标：SIP 开启、原版签名微信、不复制或重签微信。

路径：

1. 运行环境、权限和目标进程身份预检查；
2. 尝试允许的只读、受控 attach/hook 或结构化扫描路径；
3. 同时观察 `CCCrypt`、`CCCryptorCreate`、`CCCryptorCreateWithMode` 和 `CCKeyDerivationPBKDF`；
4. 完整记录 PBKDF 参数，不只按 rounds 分类；
5. raw 候选先廉价验证，passphrase 候选验证后按 catalog 扩展；
6. 标准模式成功即结束，不进入 Shadow/SIP 路线。

标准模式失败必须记录机器证据，例如：

```text
target_debugging_denied
hardened_runtime_denied
hook_symbol_unavailable
unsupported_binary_fingerprint
helper_not_trusted
```

### 12.4 PBKDF 事件分类

`rounds=256000` 通常可作为 passphrase 路线信号，但必须同时检查算法、PRF、password length、salt length、output length 和 salt 与目标数据库的关系。

`rounds=2` 不能忽略。部分构建中它的 password 参数就是每库 `enc_key`，salt 等于 `file_salt XOR 0x3a`。符合这一关系时，直接将 password 作为与目标数据库关联的 raw key 候选，再执行 HMAC。

任何 32 字节候选都可以在有界范围内同时测试 raw 和 passphrase 解释，由真实数据库验证决定类型。

### 12.5 当前进程、重启和重登顺序

这三个动作在每种可用动态 route 内按以下顺序升级：

1. **当前进程触发**：短时 attach 并保持 hook，先让用户打开与 missing database 类别对应的只读页面；不要求退出登录。
2. **完整重启触发**：用户确认并完全退出绑定的目标微信进程；daemon 必须先安装 wait-for hook，再由用户启动目标微信，随后重新确认进程实例、版本、架构、签名和账号绑定。
3. **重新登录触发**：只有机器证据明确表明目标派生仅在登录阶段发生且前两阶段没有触发时，才返回 `relogin_wechat`；不得把重新登录作为第一次尝试。

hook 已安装但尚未触发时必须先返回 `trigger_database`，不能立即启动大规模静态扫描。RPC 返回后 daemon 保持 hook；用户动作完成后通过 `observe` 继续同一 session。

### 12.6 有界静态 fallback

只有以下条件允许进入：

- 动态 hook 不可用；
- 当前 fingerprint 明确不支持动态路径；
- 用户动作完成后仍未覆盖全部数据库；
- 剩余阶段预算足够。

fallback 只处理 missing database IDs，顺序为：

```text
限定可写堆
    -> 结构化 key object
    -> salt 邻域
    -> 限定只读区域
    -> 有界普通十六进制候选
```

### 12.7 Shadow 模式（高优先级占位，执行能力尚未启用）

本节是 Shadow 的实现和验收约束；当前状态及升级条件以 1.1 为唯一依据。`unavailable_in_build` 会结束 Shadow 槽位的本次评估，但不表示它曾被运行，也不阻止满足 12.8 条件后的 SIP fallback。未来通过 1.1 门禁后，状态应先变为 `available/awaiting_approval`，因此优先于 SIP。

进入条件：

- 兼容性 registry 判定标准模式不支持；或
- 标准模式已运行并得到明确的 hardened-runtime/attach 阻断证据。

要求：

- 必须先向用户说明将创建微信副本、需要重新启动/登录以及可能的账号状态影响；
- 用户显式确认 `approve_shadow_mode` 后执行；
- 只复制原版微信到应用私有、权限受控目录；
- 记录原版路径、版本、签名和 hash，禁止替换原版应用；
- Shadow 副本只添加调试所需的最小 entitlement，不携带额外网络、文件或自动化权限；
- 不从不可信路径加载 dylib/helper；
- 只对 Shadow 进程安装 hook；
- 获取完成后退出并删除 Shadow 副本及调试工件，除非用户明确选择保留；
- Shadow 模式仍然必须执行账号绑定、catalog 和逐文件 HMAC。

### 12.8 SIP-disabled 模式（低优先级 fallback）

本节在标准路线已有机器失败证据、SIP 状态已验证，且 Shadow 已到达可降级终态时适用。当前构建使用 `unavailable_in_build`；未来可使用 `unsupported_for_target` 或实际运行后的 `attempted_failed`。`not_evaluated`、`available`、`awaiting_approval` 不能进入本节。

进入条件：

1. 微信版本/二进制指纹不支持标准模式，或标准模式已由机器证据证明失败；并且
2. `shadow_route_status` 为 `unavailable_in_build`、`unsupported_for_target` 或 `attempted_failed`，且对应机器/构建证据完整；并且
3. 仍有必需数据库缺少 credential；并且
4. 用户未拒绝安全姿态变更。

满足全部条件后必须返回（以下展示当前构建未实现 Shadow 的情况）：

```text
workflow_status=waiting_action
next_action=disable_sip
shadow_route_status=unavailable_in_build
route_priority=[standard, shadow, sip_disabled]
blocking_reasons=[standard_route_unavailable, shadow_route_unavailable_in_build]
security_posture_status=sip_enabled_verified
```

Agent 必须向用户解释：

- 关闭 SIP 会降低 macOS 的系统级保护；
- 需要进入恢复环境并重启；
- Provider 无法也不会自动执行该变更；
- 获取完成后应立即重新开启 SIP；
- 用户拒绝时现有 partial 结果会保留，但流程以 `user_declined_security_change` 停止。

用户确认后，Agent 引导其在恢复环境手工执行系统提供的 SIP 关闭操作并重启。Provider 再次运行时必须通过 `csrutil status` 等系统证据确认 SIP 已关闭，不能只相信 action receipt。

标准引导步骤：

1. 提醒用户保存工作并完全退出微信；
2. Apple Silicon 关机后长按电源键进入“选项”，Intel 启动时按住 Command-R 进入恢复环境；
3. 在恢复环境终端执行 `csrutil disable`；
4. 正常重启 macOS；
5. Provider 只读检查 `csrutil status`，确认状态后才进入 SIP-disabled 获取；
6. 不要求用户安装来源不明的微信版本、helper 或动态库。

SIP-disabled 模式仍然需要：

- 验证目标微信版本、签名、路径和账号；
- 使用签名可信 helper；
- 限制 attach、扫描范围和会话时长；
- 逐文件 HMAC；
- 禁止原始 key 日志；
- 禁止按应用名称宽泛结束所有微信进程。

关闭 SIP 不是成功保证。如果 SIP-disabled 路线已经真正运行，但仍因目标签名、Hardened Runtime、ABI、hook symbol、helper trust 或未知二进制布局失败，Provider 必须返回 `sip_route_failed` 和机器证据并停止；不得继续自动降级微信、反复重启或扩大扫描/注入范围。如果机器证据已经确认 SIP 关闭，但 catalog、进程发现、二进制门禁或其他前置检查在具体 SIP-disabled route 启动前失败，则必须返回 `sip_disabled_route_not_attempted`，并保持 `routes_attempted` 不含伪造的 SIP route。

### 12.9 恢复 SIP

只要本次 acquisition 的机器证据确认 SIP 已关闭，恢复安全姿态就优先于继续获取或其他用户动作。若 requested scopes 已完整验真，Provider 必须返回候选和下列非 terminal 状态；CLI 先发布已验真的 credential/generation 并保存 authority-free checkpoint，但不得把整体安全工作流称为完成：

```text
database_coverage_status=not_requested | complete
media_coverage_status=not_requested | complete
result_code=action_required
workflow_status=waiting_action
security_posture_status=restoration_required
next_action=reenable_sip
```

若 requested scopes 尚未完整，Provider 仍必须返回 `restoration_required + reenable_sip`：具体 SIP-disabled route 已运行时附带 `sip_route_failed`；尚未运行时附带 `sip_disabled_route_not_attempted`。两者不能同时出现，且后一种情况不得伪造 `routes_attempted`。

Agent 引导用户重新进入恢复环境开启 SIP 并重启。下一次只读检查确认 SIP 已开启后，工作流才进入正常 `terminal`。

标准恢复步骤：

1. 保存已经验证的 credential 和 generation 状态；
2. 退出 acquisition daemon、helper、Shadow 和微信调试进程；
3. 重新进入恢复环境；
4. 在恢复环境终端执行 `csrutil enable`；
5. 正常重启 macOS；
6. Provider 只读确认 SIP 已开启并清除 `restoration_required`。

如果用户明确选择保持 SIP 关闭：

- 不删除已经验证的 credential 或 generation；
- 记录本机安全姿态警告，不保存用户解释文本；
- 每次涉及进程访问的 setup/acquire 显示提醒；
- 不影响纯离线、只读 immutable generation 查询。

### 12.10 macOS 明确禁止的行为

- 自动执行或伪装执行 `csrutil`；
- 未经确认重签或替换原版微信；
- 用 `killall`/`pkill -f` 按名称或可配置路径宽泛终止进程；
- 把“降级微信、冷重启、再升级”作为没有机器证据的默认恢复流程；
- 仅选择最大 PID 或第一个 PID；
- 在日志输出 helper 原始返回值；
- 将 SIP 开启简单等同为平台不支持，而跳过标准和 Shadow 路线判断。

## 13. Windows 路由

### 13.1 `Config.Cipher` 主路径

`Config.Cipher` 布局只在明确登记的二进制指纹上启用。登记项包括：

```text
version/build
architecture
executable hash/signature
needle/string identity
object layout
decode mask/algorithm
validated fixture/real-device evidence
```

社区实现中针对 4.1.11 的固定 XOR mask 和固定对象偏移不能直接表述为全部 4.1+ 通用。

主路径：

1. 分进程定位登记的结构；
2. 只读提取 key/salt/passphrase 候选；
3. 保留进程实例 provenance；
4. 对目标 catalog 逐文件 HMAC；
5. 完整覆盖后立即停止。

### 13.2 通用 fallback

只在以下情况进入：

- 当前 fingerprint 没有登记；
- 定向结构不存在或结构检查失败；
- 定向候选验真失败；
- 定向路径只覆盖部分数据库；
- 剩余预算允许。

fallback 顺序：

```text
结构化 key object
    -> salt 邻域
    -> 限定可写堆
    -> 限定只读区域
    -> 有界普通十六进制候选
```

多个 `Weixin.exe`/`WeChat.exe` 使用独立 collector，不能像当前实现一样把所有进程候选预先放进同一个集合。

### 13.3 Windows 用户流程

- Windows 默认在一次 acquisition session 内先执行 `Config.Cipher`，再对 missing database IDs 执行有限 fallback；
- 默认不要求退出登录、重启微信或重新登录；
- 整个 session 受统一 wall-time 和独立阶段预算约束；
- 超时返回已经验证的 partial 结果和 `deadline_exhausted` 诊断；
- Agent 不得对未变化的进程/catalog 无限重复扫描；
- 当前已经验证的通用内存扫描路径保留到 `Config.Cipher` 新路径完成真实设备验收，不因新增主路径而提前删除。

### 13.4 Windows 禁止行为

- 为获取 key 执行注入、调试器或断点实验路线作为默认 Agent 操作；
- `taskkill /F /T /IM Weixin.exe` 或 `WeChat.exe`；
- 使用用户可控 DLL 路径而不做 Authenticode/hash/owner 校验；
- 因某个进程候选通过就把它分配给其他账号或所有相同 salt 文件。

## 14. Helper、提权与秘密处理

Provider、daemon 和 helper 只处理当前用户本人或明确获授权的本地数据，不联网、不修改微信数据库，也不调用微信私有网络接口。需要联网的发布校验、签名和 notarization 不得与运行时密钥获取进程共享 secret。

### 14.1 Helper 信任

发布版 helper 必须：

- 随主程序固定位置发布；
- 正式签名并纳入 notarization/发布校验；
- 运行前验证 owner、权限、canonical path、签名、Team ID/designated requirement 或 Authenticode；
- 验证父目录不可被非授权用户替换；
- 发布模式禁止通过 `V_LOCAL_KEY_PROVIDER_HELPER`、`WX_KEY_HELPER_PATH` 等环境变量指向任意可执行文件；当前实现只在同时显式设置 `V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_HELPER=1` 的隔离开发环境接受前者，否则 fail closed；
- 开发模式 override 必须显式编译或显式命令行开启，且不得进入正式发行包。

### 14.2 最小权限

- 普通路径先尝试无提权能力；
- 只有明确的进程访问错误才请求管理员授权；
- 提权 helper 只接受当前 session 的签名请求和限定目标 PID/进程实例；
- helper 不接受任意命令、任意文件路径或任意输出路径；
- 不保存 sudo 密码或可长期复用的管理员凭据。

### 14.3 秘密传输与内存

- 使用 inherited pipe、受 ACL 保护的本地 socket 或等价 IPC；
- 不使用普通临时 request/response/capture 文件保存 key；
- stdout 只有机器协议消费者可见，永不进入 Agent 日志；
- stderr 只允许红acted 状态；
- 候选使用可清理 buffer，避免不必要地转为不可擦除字符串；
- 禁止 core dump 和崩溃报告采集秘密内存；
- cleanup 必须覆盖超时、取消、异常、daemon 崩溃和系统关机。

## 15. Agent SOP

### 15.1 通用流程

第 7—10 步同时适用于当前占位和未来实现。优先级只规定评估顺序：Shadow 已到达 `unavailable_in_build/unsupported_for_target/attempted_failed` 之一时可以继续 SIP；`not_evaluated/available/awaiting_approval` 时不能跳过。

1. 调用 `prepare`，读取 catalog、平台、实际架构、版本、指纹、账号绑定和 route。
2. 如果 `complete`，停止获取，进入 generation 构建。
3. 如果 `trigger_database`，只执行不会发送消息或修改数据的页面访问动作，再提交回执。
4. 如果 `restart_wechat`，先提示可能中断通话、未发送内容或前台工作，用户确认后只重启绑定的目标进程。
5. 如果 `relogin_wechat`，说明扫码/MFA/会话影响，用户确认后执行；不得作为第一次默认动作。
6. 如果账号 mismatch，要求切换目标账号，不把它伪装成权限错误。
7. 标准模式失败后，按 registry 和构建能力判断 Shadow 状态；当前未实现构建明确落到 `unavailable_in_build`。
8. Shadow 若为 `available`，必须先进入 `awaiting_approval` 并获得用户确认，不能直接跳到 SIP。
9. Shadow 到达可降级终态后，才允许向用户提供 SIP-disabled 模式；不可用与实际失败必须分开说明。
10. SIP-disabled 路线获取完成后，必须引导恢复 SIP。
11. `partial` 只补 missing database IDs，不重复已经验证的 KDF/HMAC。
12. `ambiguous`、helper trust failure、明确账号冲突、catalog drift 不盲目重试。

### 15.2 `trigger_database` 白名单

允许：

- 打开已经存在的聊天会话；
- 打开联系人、收藏、朋友圈、群成员等只读页面；
- 切换微信内部已有只读页面；
- 打开明确对应 missing database 类别的功能。

禁止：

- 发送消息、点赞、评论、加好友；
- 删除、编辑或迁移微信数据；
- 自动下载不必要内容；
- 未经确认退出登录、切换账号或终止进程。

### 15.3 用户拒绝

用户拒绝 restart、relogin、Shadow 或 SIP 变更时：

- 立即停止对应升级路线；
- 返回已经验证的 partial 结果；
- 记录机器状态 `user_declined_action`，不记录用户解释；
- 不用换一种措辞反复要求同一动作。

## 16. CLI 集成与持久化

### 16.1 CLI 必须消费状态

CLI 不能只在 `database_keys` 为空时读取 diagnostics。以下状态即使已有 partial key 也必须阻止自动保存新根凭据或错误发布：

```text
target_binding_status=mismatch
workflow_status=waiting_action
blocking_reasons 包含 helper_untrusted/catalog_drift
credential verification 未完成
```

已经逐库 HMAC 通过的 partial effective keys 可以用于临时 generation，但必须明确标记 partial，并遵守覆盖率回退保护。

### 16.2 凭据库存储

系统凭据库保存：

- global passphrase；
- per-DB overrides；
- credential epoch；
- account binding；
- profile ID；
- 可选加密 derived-key cache。

普通状态保存：

- credential reference；
- catalog ID；
- verified database IDs；
- generation ID；
- 非秘密 diagnostics 摘要。

### 16.3 Refresh

日常 refresh 默认不读微信进程：

1. 重新发现 catalog；
2. 从系统凭据库读取结构化 credential；
3. 对新 salt 用 global passphrase 派生；
4. 应用 per-DB overrides；
5. 每文件 HMAC；
6. 构建新的 immutable generation；
7. 原子提交 generation 指针；
8. 覆盖率回退时保留旧 generation。

只有新数据库无法被已存 credential 覆盖、credential epoch 变化或账号切换时，才重新进入进程获取流程。

### 16.4 Generation 绑定

Provider 返回：

```text
catalog_id
database_id -> effective key
file identity + first-page digest proof
```

CLI stable copy 后重新检查 proof。generation manifest 保存 catalog ID、源文件身份摘要和验证 profile，但不保存 secret。

### 16.5 Media scope 兼容

旧方案和当前 Provider 的 `media` scope、`image_keys` 响应继续保留，不与数据库 credential 混为一体：

- media 候选沿用独立的 AES/XOR 样本验真；
- media 验证有独立阶段预算和诊断；
- `database_coverage_status` 只描述数据库 key coverage；`media_coverage_status` 只描述媒体凭据 coverage；
- `media_coverage_status=not_requested` 表示未请求 media，`pending` 表示会话仍在验真，`none` 表示请求已处理但没有完整可发布的 AES/XOR 组合，`complete` 表示完整组合已通过样本验真；v1 的 `image_keys` 是原子组合，不使用 `partial`；
- 调用方要求 media 时，数据库 complete 但 media 未验证应返回整体 `partial` 或 `action_required`；
- 明确 `database-only` 时，media 缺失不阻止数据库 generation；
- 明确 `media-only` 时必须返回 `database_coverage_status=not_requested`，不能以 `complete` 表示数据库无需执行；
- media secret 同样只能进入系统凭据库，不写日志或普通状态文件。

## 17. 性能与资源预算

### 17.1 上限

默认建议：

```text
database files hard cap: 4096
unique salts hard cap: 4096
candidates per source hard cap: 512
PBKDF workers: 1-2
dynamic observe window: 30 seconds/stage
active scan window: 45 seconds/process
acquisition session wall time: 15 minutes
Agent action repeats: at most 1 per unchanged process/catalog/route stage
```

实际扫描字节上限沿用并收紧现有平台安全常量。超过任何上限返回 partial/blocked diagnostics，不扩大到无界扫描。

### 17.2 优化顺序

```text
catalog/preflight
    -> saved credential validation
    -> dynamic structured hooks
    -> raw key cheap HMAC
    -> one passphrase trial
    -> derive per unique salt
    -> per-file HMAC
    -> bounded platform fallback for missing IDs only
```

共享 passphrase 只需先在一个代表数据库上执行高成本试验；命中后按唯一 salt 派生，不按文件重复 KDF。每个候选和每个 salt 的高成本计算只执行一次，但每个物理文件仍独立验证。全部 required database IDs 覆盖后立即停止。

hook 等待、内存扫描、PBKDF2、数据库派生和 media 使用独立阶段预算，避免某一阶段耗尽总预算。

### 17.3 阶段诊断

```yaml
phase_timings_ms:
  discovery: 0
  helper: 0
  dynamic_hook: 0
  memory_scan: 0
  raw_key_validation: 0
  passphrase_validation: 0
  database_derivation: 0
  media: 0
  total: 0

candidate_count: 0
passphrase_candidate_count: 0
kdf_budget_exhausted: false
scan_regions: 0
scanned_bytes: 0
```

## 18. 诊断与隐私

诊断可以包含：

```text
platform
wechat_version/build
actual_process_architecture
binary_support_state
route_selected/routes_attempted
workflow/coverage/security posture
database counts
candidate counts by kind/source
phase timings
scan bytes/regions
budget flags
opaque missing database IDs
redacted blocking reasons
```

默认不得包含：

- passphrase、raw key、derived key；
- 候选片段、salt 原值或可反推秘密的摘要；
- 内存地址；
- 绝对账号路径；
- helper 原始 stdout；
- 用户管理员密码或扫码/MFA 信息。

只有用户显式开启 `--show-paths` 时，CLI 才可以在本地终端将 opaque database ID 映射为账号根目录下的相对路径。

为保证 Agent 不需要解析自由文本，发行版必须稳定提供 10.3 定义的机器字段并遵守 11.1 的关系不变量。本节只增加隐私红线，不维护第二份字段 schema。

`blocking_reasons` 使用稳定枚举；面向用户的解释文本可以本地化，但不得成为 Agent 的唯一判断依据。

## 19. 验收矩阵

本节每一项的自动化、平台真机与签名发布入口统一记录在 [`REGRESSION_TESTS.md`](REGRESSION_TESTS.md)。任何依赖真实微信进程、SIP 状态、硬件架构或正式签名的项目都必须保留独立证据；普通 CI 或 mock 通过不得替代真机状态升级。

### 19.1 凭据与数据库

- 全局 passphrase 覆盖多个不同 salt；
- 逐库 raw key；
- mixed 模式；
- 同 salt、不同 raw key；
- 相同 effective key 来自多个来源；
- 不同 profile 的历史/迁移数据库；
- 新数据库在 refresh 时自动派生；
- unreadable/truncated/unstable/plaintext 数据库；
- catalog 发现后文件被替换；
- WAL 存在、轮转和稳定复制；
- partial 不覆盖更完整旧 generation。

### 19.2 macOS

以下是 Phase 3 的目标验收矩阵，不是当前能力清单；当前状态与升级条件只认 1.1。Shadow 处于表中不可用终态时，可在标准失败和 SIP 已验证后按 P3-10 进入较低优先级 fallback。

- Apple Silicon ARM64 真机；
- Intel x86_64 真机；
- Apple Silicon Rosetta 下 x86_64 微信；
- SIP 开启的标准模式；
- SIP 开启的 Shadow 模式；
- 标准不支持、Shadow 失败后正确引导关闭 SIP；
- SIP-disabled 模式成功；
- 成功后正确引导并验证 SIP 恢复；
- 用户拒绝 Shadow/SIP 时安全停止；
- stock、Shadow 和 SIP-disabled 的账号/进程隔离；
- hardened runtime、helper trust、attach denied 的可解释诊断；
- PBKDF rounds=256000 passphrase；
- PBKDF rounds=2 raw key + salt XOR `0x3a`；
- `CCCrypt*` 与 PBKDF 同时命中后的有效 key 去重；
- 当前进程触发、完整重启触发和仅有机器证据时的重新登录触发；
- 完整重启时 daemon 先进入 wait-for、目标启动后重新校验进程实例；
- 目标 A 数据库但当前登录 B，以及 session account 无法确认；
- hook 未触发、阶段超时和多个有效候选歧义；
- 用户动作后只补 missing IDs，不重复相同静态扫描阶段。

### 19.3 Windows

- 已登记 4.1.x 指纹的 `Config.Cipher`；
- 未登记 fingerprint 安全回退；
- 固定结构失效但通用 fallback 成功；
- 多个 `Weixin.exe`、多账号；
- x64 与 ARM64 实际进程架构；
- access denied 和部分进程可读；
- 定向路径 partial 后只补 missing IDs；
- 不执行宽泛 taskkill；
- 目标 A 数据库但当前登录 B，以及多个唯一数据库 salt；
- 候选冲突、阶段预算耗尽和单次 session 有界结束；
- 默认流程不要求退出登录、重启或重新登录。

### 19.4 共同状态与编排

- 全部 required database IDs 唯一通过首页 HMAC 后才返回 `complete`；
- 数据库部分结果返回 `database_coverage_status=partial`、准确计数和 opaque missing ID 列表；
- 明确错账号返回 `action_required/account_mismatch`，且不保存根凭据；
- 未知账号状态可以继续，但候选必须通过目标数据库 HMAC，且不得声称当前账号已确认；
- 已完成数据库不会在 fallback 中重复 KDF、扫描或验证；
- 单次 RPC 在 deadline 内返回，跨动作 session 受统一 wall-time 和重试预算约束；
- `trigger/restart/relogin` 每种动作都需要回执和状态变化，不允许 Agent 盲目循环；
- 稳定诊断字段足以解释下一动作，状态判断不依赖自然语言；
- database-only 与 database+media 两种 scope 的总体状态均符合定义。

### 19.5 安全

- helper 被替换、重签、改 owner/权限；
- 环境变量 helper/DLL override 在发行版被拒绝；
- symlink/junction/reparse 越界；
- IPC session 猜测、重放和跨用户访问；
- daemon/CLI/微信异常退出；
- 目标进程不会遗留暂停状态；
- 临时目录和普通日志中不存在 secret；
- crash report/core dump 不包含 secret；
- 错账号候选不保存；
- SIP 状态机器验证，不只依赖用户回执。

### 19.6 发布

- Provider、CLI、daemon、helper 正式签名；
- macOS notarization 和 staple 验证；
- Trusted Publishing；
- Windows 签名和 Authenticode 验证；
- ARM64 真机端到端；
- 发布包内 helper hash/signature 清单；
- 从干净机器验证 v1、Provider/CLI 版本不匹配时的明确失败、Keychain/Credential Manager 和卸载清理。

### 19.7 当前能力声明门禁

验收矩阵不得自行宣布能力升级。所有当前状态、升级条件与不得替代的证据类型统一见 1.1；本节测试只证明实现满足相应门禁，不改变门禁本身。

## 20. 实施顺序

### Phase 0：协议、Catalog 和验证器

1. 定义首发 v1 schema、状态优先级和 Provider/CLI 原子迁移行为；
2. 实现 fail-closed catalog 和 catalog ID；
3. 实现 profile registry；
4. raw/passphrase 统一 HMAC 验证；
5. 修复同 salt 只复用派生、不复用文件验证。

### Phase 1：结构化 Credential 与 CLI

1. 增加 global/per-DB/mixed credential；
2. CLI 系统凭据库存储；
3. `database_keys` 改为当前 effective key map；
4. refresh 对新 catalog 自动派生；
5. CLI 正确消费 partial/mismatch/action-required。

实现门槛补充：只有动态 KDF 调用提供完整算法/PRF/rounds/salt/output 证据，且同一捕获 passphrase 对至少两个不同 salt 的目标数据库逐文件 HMAC 成功，才保存为账号级 `global_passphrase`。普通静态内存探测、单库或单 salt 证据只保存当前数据库已经验真的 effective key override，不把根候选提升为账号级凭据。

### Phase 2：Acquisition Daemon 与 Agent 状态机

1. 本地受控 IPC；
2. prepare/observe/finalize；
3. session/action receipt/retry budget；
4. hook 生命周期、取消和崩溃恢复；
5. missing-only fallback。

Phase 1/2 实现复核清单（2026-08-23）：

| 方案条款 | 代码落点与门禁 |
| --- | --- |
| global/per-DB/mixed 与 effective key map | Provider 结构化 credential；KDF 调用证据不完整、不同 passphrase、单 salt 均不合并或提升根凭据；CLI 只在完整 generation 验真后保存根凭据。 |
| refresh 覆盖新 catalog | CLI 从系统凭据库读取根/override，逐文件派生和 HMAC，不访问微信进程；覆盖率回退继续 fail closed。 |
| partial/mismatch/action-required | partial 进入 generation 覆盖率比较；mismatch/waiting/blocked 作为结构化错误返回，不保存冲突候选。 |
| 受控 IPC | loopback + 256-bit token + 私有 endpoint/resume + 短鉴权超时；连接并发处理，慢速未认证连接不能阻塞 daemon。运行时签名验证仍属于 Phase 5。 |
| prepare/observe/finalize | observe 对外无 secret；finalize 强制绑定并重新发现 catalog，成功后只返回一次 secret 并删除 session。 |
| action receipt | 仅显式 `--confirm-key-action` 生成；Provider 固定 route/stage，验证原/新进程实例，拒绝 Shadow/SIP 同 session 回执。 |
| 用户拒绝 Phase 2 动作 | `--confirm-key-action stop_and_report` 不生成 receipt，只触发 catalog 重检后的 partial finalize；错账号和 catalog drift 继续 fail closed。 |
| session hard limit/cancel/disconnect | 每个请求预算被 session expiry 截断；取消、客户端断开、daemon shutdown 会取消扫描并关闭 platform session。 |
| daemon/hook 生命周期 | 同账号写 session 互斥；同 session 请求串行；macOS daemon 必须由 companion helper 承载，helper 不可用时回退 one-shot；watchdog 约束调试子进程。 |
| missing-only fallback | 已验证 key 在后续 observe/finalize 中不重复进入平台扫描目标。 |
| 崩溃恢复 | endpoint 原子发布；resume 使用 `.old` 回滚/恢复；daemon 启动使用 OS 文件锁并在启动失败时回收子进程。 |

以上表示 Phase 1/2 的代码和本地自动化门禁，不替代 Phase 3 的 macOS 三模式真机证据，也不替代 Phase 5 的签名、notarization、Trusted Publishing 和发行安全验收。

### Phase 3：macOS 三模式

1. 实际架构和 binary fingerprint；
2. `CCCrypt*` + 完整 `CCKeyDerivationPBKDF` 双路径；
3. 标准模式兼容 registry；
4. Shadow 模式；
5. 标准/Shadow 失败后的 SIP 引导；
6. SIP 恢复工作流；
7. ARM64/Intel/Rosetta 真机验收。

### Phase 4：Windows

1. per-process collector；
2. fingerprint 绑定的 `Config.Cipher` registry；
3. missing-only 通用 fallback；
4. x64/ARM64、多账号真机验收。

### Phase 5：发布安全

1. helper/daemon 运行时签名验证；
2. 移除发行版任意路径 override；
3. pipe/IPC 取代秘密临时文件；
4. 内存、日志、crash 安全；
5. 正式签名、notarization、Trusted Publishing；
6. 干净机器发布验收；
7. 依据真机阶段计时和候选计数，最后校准默认 budget、候选上限与硬上限，不凭社区样例拍定数值。

实现边界：Provider 不提供自动关闭 SIP、替换/重签原版微信或宽泛终止进程的代码路径。标准模式无法完成时，只能根据版本、签名、架构和系统状态返回结构化门禁；Shadow 与 SIP-disabled 路线在正式签名和对应架构真机验收前不得宣称自动可用，也不得由 Agent 静默执行。

## 21. 完成判据

本方案只有同时满足以下条件才算完成：

这是整体方案的最终完成判据，不是当前发行版能力声明；未满足的 Phase 必须保持 `build_only`、`experimental` 或 `unverified`。

- 当前 catalog 的每个必需数据库有唯一有效 `effective_enc_key`；
- 每个物理文件独立通过正确 profile 的首页 HMAC；
- 结构化 credential 能在不读取微信进程的 refresh 中覆盖同 epoch 新增数据库；
- global/per-database/mixed 类型由证据和 HMAC 决定，不由版本猜测；
- 多进程候选验证前隔离；
- CLI 不忽略 partial/mismatch/action-required；
- standard、Shadow、SIP-disabled 路由均有明确进入条件和停止条件；
- 标准路线失败且 Shadow 到达匹配的可降级终态时能够引导 SIP-disabled 模式，同时严格区分未实现、不支持和实际失败；
- SIP-disabled 成功后能够引导并验证恢复 SIP；
- helper/daemon 信任链和秘密传输满足发行安全要求；
- macOS ARM64、Intel/Rosetta 和 Windows 目标架构均有真机证据；
- generation 绑定 catalog 并防止覆盖率回退；
- Agent 不执行未经确认的重登、重启、Shadow、SIP 变更或宽泛进程终止。

## 22. 历史材料与审计

主规范只描述目标态、契约、不变量与当前能力门禁。非规范性历史材料已拆分：

- 旧方案迁移 provenance：[`MIGRATION_FROM_LEGACY.md`](MIGRATION_FROM_LEGACY.md)；
- 时点审计、整改声明与后续核销：[`AUDIT_LOG.md`](AUDIT_LOG.md)。

历史记录不能覆盖 1.1 的当前状态，也不能作为 19 节验收或真机证据的替代品。

## 23. 参考来源

- https://github.com/TANGandXUE/wcdb-key-tool
- https://github.com/dylan121322/wxkey-hook
- https://github.com/r266-tech/wxkey
- https://github.com/Thearas/wechat-db-decrypt-macos
- https://github.com/soucod/WeFlow/tree/master
- WeFlow reviewed commit: `a7656bf26776f6e0026b754de90fd07d2f037966`
