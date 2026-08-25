# Phase 0–5 深入审查计划（设计质量优先）

> 对象：`v-local-key-provider`（含其与 `v-local-cli` 的契约面）
> 主文档：[`KEY_ACQUISITION_AGENT_ORCHESTRATION.md`](KEY_ACQUISITION_AGENT_ORCHESTRATION.md)（1463 行）
> 计划制定时点：2026-08-25　基线：branch `codex/release-readiness` @ `6e65e53`
> 原则：设计质量优先；找可优化点；减少冗余与过时内容；给目录结构建议。

---

## 0. 核心判断：这不是一次普通代码审查

主文档已经**把自己的审计历史写进了设计规范**（§24 审计 Phase 0-3、§25 审计 Phase 4-5，均 2026-08-24），并且这些审计结论**已开始互相推翻**：§24.2 的「零 P0、零 P1」被 §24.6 明确宣布「只能保留为当时的静态审读快照，不能继续作为当前审计结论」。也就是说，规范文档内部同时存在**被推翻的结论**与**推翻它的结论**。

因此本次审查必须分成三条独立轨道，且顺序不可颠倒：

- **Track 0 — 锁定审查基线**（前置，不做完无法开展其余）。
- **Track A — 审计设计文档本身**（设计质量优先，收益最高、风险最低）。
- **Track B — 对照文档做 Phase 0-5 代码深审**（含横切专项与目录建议）。

其中 Track A / B 都要额外做一件普通审查不会做的事：**核销文档里的自评声明**（"零 P0/P1""A3/A4/A5 完成"等），把它们当作待验证假设，而不是既成事实。这正是用户要求的"设计文档自身也需要审计"。

---

## Track 0 — 锁定审查基线（前置，必须先做）

### 0.1 已确认的基线问题

| 事实 | 证据 | 影响 |
| --- | --- | --- |
| 核心实现大面积未提交 | 磁盘 93 个 `.go`，`git ls-files` 仅 25 个被追踪；`catalog.go`/`session.go`/`credential.go`/`profile.go`/全部 `daemon_*.go`/`phase3_*`/`phase4_*`/`runtime_trust_*`/`windows_*` 均 **UNTRACKED**；`git status --short` 106 项变更 | 文档 §24-25 的 `file:line` 引用（`catalog.go:26`、`session.go:696`、`platform_darwin.go:497`…）**指向未提交文件**，随时可能漂移或丢失，无法作为可复核证据 |
| 本机测试受限 | 文档 §24.1 自述：Windows App Control 拦截 temp 测试二进制；darwin 为 cgo，本机无法交叉编译 | `go test` 正确性只能依赖 CI；本机只能做静态审读 + `go build`/`go vet`（文档称二者干净，需复跑确认） |

### 0.2 Track 0 动作

1. **把工作树锁成可复核快照**：在 `codex/release-readiness` 上 commit（或至少 `git stash create` 记录 tree hash），记录确切 commit/tree hash，之后所有发现的 `file:line` 以此为准。
2. **确定审查目标物**：明确"审的是工作树快照 X"，而非误以为在审 HEAD `6e65e53`（后者只有 25 个文件、是旧状态）。
3. **复跑并留证** `go build ./...`、`go vet ./...`；在 CI 上触发一次全量 `go test`（含 darwin cgo runner），把结果附到审查记录，作为"正确性由 CI 承担"的落地证据。
4. **确认门禁清单仍成立**：逐条核对 §25.3 五项未解除门禁（空 registry、macOS cgo 真机、Shadow `unavailable_in_build`、profile 仅证据项、A1 拆包未完成），审查全程不得用普通 CI/mock/交叉编译/签名冒充其中任何一项。

---

## Track A — 设计文档自身审计（设计质量优先）

目标：让**设计规范**回归"干净、单一真源、只描述目标态与当前能力门禁"，把审计史与迁移史移出规范。以下每项都是可直接落地的重构。

### A-1【高】把审计日志从规范中剥离（最重要）

- **问题**：§24（Phase 0-3 审计）、§25（Phase 4-5 审计）是**时点日志**，且 §24.2 已被 §24.6 自我否定；§24.3-24.5 描述的 F1/F2/F3/P2-1/A1-A6 现状，又被 §24.6/24.7 的整改表覆盖。读者要交叉比对 4 个子节才能得知"当前真相"。规范里长期驻留**被推翻/已过时的结论**，是典型的过时内容。
- **建议**：新建 `AUDIT_LOG.md`（或 `CHANGELOG-AUDIT.md`），把 §24、§25 整体迁出；规范文档只保留一句指针。审计条目按时间倒序、每条标注"当时状态/现状/是否已被后续条目取代"。
- **收益**：规范瘦身约 100+ 行；消除自相矛盾；后续审计只追加到日志，不再污染规范。

### A-2【高】收敛"目标态 vs 当前能力"的重复门禁

- **问题**：同一条"这是目标态、当前构建以 `unavailable_in_build`/`build_only` 占位"的门禁，散落在 §1.1、§2.7、§2.8、§12.7、§12.8、§19.2、§19.7、§20（各 Phase 注）、§21、§25.3 至少十处；Shadow 的 `unavailable_in_build` 语义重复 6 次以上。
- **建议**：设一个权威"能力门禁"章（合并 §1.1 + §19.7 + §25.3），用一张"路由/能力 → 当前状态 → 升级条件"表集中表达；其余章节改为引用该表，不再各自复述。
- **收益**：改一次能力状态只动一处，杜绝"某处漏改导致规范内部不一致"。

### A-3【中】§22 迁移追踪表定位

- **问题**：§22 是 30 行"旧方案 → 新落点"的 provenance 表，价值真实但属**历史**，混在规范里增加噪音。
- **建议**：移到 `AUDIT_LOG.md` 或独立 `MIGRATION_FROM_LEGACY.md`；规范正文只留结论性一句。

### A-4【中】diagnostics 字段建立单一真源

- **问题**：100+ 诊断字段在 §10.3（响应结构）、§11.1（正交状态）、§18（诊断与隐私）多处分别列举，字段集易漂移。
- **建议**：以 §10.3 为唯一权威 schema，§11.1/§18 改为引用 + 只讲各自关注点（不变量 / 隐私红线），不再重列字段。

### A-5【中】核销文档内的自评声明

- **问题**：§24.7 声称 A3（状态机）、A4（collector）、A5（Darwin pipeline）"完成"，但 `main.go` 1123 行、`session.go` 1136 行、`pattern.go` 1035 行、`platform_darwin_hook.go` 1140 行、`platform_darwin.go` 726 行——God-file 规模并未消除。"完成"可能仅指某个具体结构改动（如加了 ordered rule 列表），却读作"重构已了结"。
- **建议**：文档层面把这些自评从"陈述句"改为"待代码核实项"，并交由 Track B 的 X-1 逐条落实；不核实通过前不得在规范中断言"完成"。

### Track A 产出

一份"三分文档"结构提案 + 具体 diff 级重构清单：
`KEY_ACQUISITION_AGENT_ORCHESTRATION.md`（纯规范/目标态/能力门禁）＋ `AUDIT_LOG.md`（§24/§25 及后续审计）＋ `MIGRATION_FROM_LEGACY.md`（§22）。

---

## Track B — Phase 0-5 代码深审

对每个 Phase：先列文档规定的**关键不变量**，再定**重点排查项**，同时做**冗余/死代码猎取**与**集成缝测试充分性**评估。文档 §24-25 已声称修复的项，一律列为"核实点"，不采信自评。

### Phase 0：协议 / Catalog / 验证器

- 不变量：fail-closed catalog（发现错误不得静默跳过后报完整覆盖）；raw/passphrase 统一"解密+首页 HMAC"而非仅查 header；同 salt 只复用派生、每文件单独验 HMAC；validator-conflict（同文件不同 key 都过 HMAC）判为验证器/漂移错误而非 `ambiguous`。
- 核实点：
  - F1 死枚举 `classificationUnsupportedProfile` 与恒零 `unsupported_profile_count` 是否已按 §24.6 删除、catalog 是否保持 profile-neutral、不预填默认 profile（勿采用被否决的"无匹配即 unsupported"）。
  - F2 `profileRegistry` 是否只含已证据项、机制已参数化且多 profile 路径有回归、生产 registry 未获真机证据前保持 `build_only`。
- 冗余猎取：catalog 分类枚举是否还有其它"定义但无赋值/无消费"的成员。

### Phase 1：结构化 Credential（Provider 侧）

- 不变量：账号级 `global_passphrase` 提升门槛＝完整 KDF 调用证据 + **同一 passphrase 对 ≥2 个不同 salt 逐文件 HMAC 成功**；单库/单 salt/静态探测只保存该库已验真 effective key override；`database_keys` 仅当前 catalog 已验真 effective key，不重复承载 passphrase；refresh 默认不读微信进程。
- 核实点：证据不完整 / 不同 passphrase / 单 salt 三种情形确实不合并、不提升；CLI 仅在完整 generation 验真后才写系统凭据库。

### Phase 2：Acquisition Daemon 与状态机

- 不变量：IPC = loopback + 256-bit 常量时间 token + 私有 endpoint + 短鉴权超时 + 并发接受；secret 三段纪律（prepare/observe 无 secret、finalize 一次性返回并销毁 session、重发现 catalog + 双 `catalog_id` 校验）；`result_code` 为整体唯一权威，不被单个 scope 反推。
- 核实点：
  - F3 预算耗尽覆写是否已并入**有序 rule 裁决**、`failed`/`ambiguous`/`unsupported`/`permission_required` 等终态是否不再被改标 `deadline_exhausted`。
  - P2-1 无回执 finalize（`stop_and_report`）是否**不再**把待处理 `switch_to_target_account` 降级为 `partial`+`user_declined_action`；mismatch 是否优先于 partial；是否已补跨 session/finalize 集成测试。
- 关联横切：A3 声称"状态裁决单一化完成"——但 `session.go` 1136 行仍是全库最脆之一（文档点名 `mergeSessionDiagnosticEvidence`），须核实是否真的只有一处裁决、会话层不再自改 `result_code`。

### Phase 3：macOS 三模式

- 不变量：不靠 Provider 自身 `GOARCH`，须读目标进程实际 slice + Rosetta 状态选 helper/ABI；同时观察 `CCCrypt*` 与 `CCKeyDerivationPBKDF`；rounds=2 且 salt=`file_salt XOR 0x3a` 时 password 作 raw key 候选；Shadow 当前恒 `unavailable_in_build`（终态、非"失败"、不写 `routes_attempted`）；SIP 只读 `csrutil status` 机器验证，Provider 绝不自动改 SIP；§12.10 禁止行为（`killall`/`pkill -f`、自动 `csrutil`、擅自重签微信、只选最大/首个 PID）。
- 核实点：F-P3-1 `relogin_wechat` 是否已从"半接线"变为真正产出（`trigger→restart→relogin` 升级链 + receipt + 有限重试）。
- 方法约束：cgo 路径本机无法编译，只能**静态契约审读**；正确性依赖对应架构（Intel/Apple Silicon）真机 CI，不得用交叉编译或历史 Intel 记录冒充。

### Phase 4：Windows

- 不变量（§25.1）：进程身份绑定 signed version metadata + 目标 exe SHA-256 + 签名叶证书 SHA-256 + 实际架构，任一缺失即 fail closed；open 后同 handle 复核以防 discovery→open TOCTOU；per-process collector 隔离、只合并已逐库 HMAC 验真结果；账号绑定只认进程实际打开、位于精确 `db_dir`、形态为数据库的路径；**Authenticode 有效 ≠ 目标产品授权**，空 registry 不读目标内存、不宣称支持；所有 native buffer/扫描量/阶段 deadline 有硬上限并清零。
- 核实点：x64 与 ARM64 registry/真机证据是否独立、当前是否确为 `build_only`；`Config.Cipher` 与通用 fallback 均由完整 registry 条目锚定。
- 禁止行为：宽泛 `taskkill /F /T /IM`、用户可控 DLL 路径无校验、单进程候选外溢到其它账号/同 salt 文件。

### Phase 5：发布安全

- 不变量（§25.2）：helper/daemon 运行时签名验证；release 拒绝一切路径 override（未验证本地二进制须同时 显式路径 + `DEVELOPMENT=1` + allow 开关）；pipe/IPC 取代秘密临时文件；固定安装目录逐层创建校验、拒绝 symlink/junction/reparse 祖先、canonical path 用文本规范比较（不用会跟随 junction 的 SameFile）；named pipe/Unix socket 绑定同用户 peer + 进程镜像（macOS 另验 Developer ID/Team ID）；Provider/helper 握手要求版本完全一致；npm 下载仅固定 HTTPS host、保留最初 `O_EXCL` descriptor、发行集合整体验证与回滚。
- 核实点：签名前 `TestReleaseCompatibilityEvidenceGate` 是否确实要求每架构有 eligible registry 条目且 `compatibility-evidence/<sha256>.json` 与条目一致，空 registry/缺证据能阻止 release。

---

## Track B 横切专项（"减冗余/去过时"的重头）

### X-1【高】God-file 拆分核实（对齐 A-5）

逐一核对文档 A3/A4/A5"完成"声称 vs 实际规模，不符者列为"未竟重构"：

| 文件 | 行数 | 文档相关声称 | 核实动作 |
| --- | --- | --- | --- |
| `platform_darwin_hook.go` | 1140 | — | 是否可按 hook 类型/stage 拆分 |
| `session.go` | 1136 | A3 状态裁决单一化"完成" | 是否仍有并行裁决；`mergeSessionDiagnosticEvidence` 是否已改穷尽/类型校验策略表 |
| `main.go` | 1123 | A2/A3；巨型 switch | 状态机是否仍排序敏感；diagnostics 构造是否已统一 `newDiagnostics` |
| `pattern.go` | 1035 | A4 collector"完成" | 三并行 map 是否已并为 `candidateInfo`；~20 计数器是否已收敛为单一 `merge` |
| `platform_darwin.go` | 726 | A5 pipeline"完成" | 是否已按 §10.6 stage（discover/route/hook/refresh/static/finalize/assemble）切分 |

### X-2【高】internal/ 半迁移与双实现（A1 直接产物，减冗余）

- **已定位疑点**：`pattern.go:488 func pbkdf2SHA512(...)` 与 `internal/cryptokdf/pbkdf2.go func PBKDF2SHA512Key32(...)` 并存；`pattern.go` 已 import `internal/cryptokdf`。同理 `budget.go` 与 `internal/workbudget`。
- **核实**：root 版是"委托到 internal"还是"与 internal 重复实现"。若重复→合并为单一实现（保留 cancellation hook 等 root 需要的差异点作为 internal 的参数）。
- **勿误伤**：root `pbkdf2_test.go` 是**有意**存在的——它把手写 `pbkdf2SHA512`（带标准库没有的取消钩子）逐字节钉到 `crypto/pbkdf2` 上，非冗余测试；先判"意图"再判"冗余"。

### X-3【中高】diagnostics God-DTO（A2）

核实 100+ 扁平字段是否已全部经 `newDiagnostics` 单一初始化、是否有"反射穷尽测试"要求每字段有唯一且类型匹配的 session merge policy——这是防止 F1/F-P3-1 这类"定义未接线"复发的结构约束。

### X-4【中】平行类型建模同一事物

核实 `darwinHookResult` / `platformHookSnapshot` 是否已按 §24.7 合一（原为 37 行近乎逐行重复的 `recordHook`/`recordPersistentHook` 的根因）。

### X-5【高】死代码 / 未接线枚举清理（去过时）

全仓扫描"定义但无生产者或无消费者"的枚举与 next_action / result_code / status 值：文档已自陈的 `classificationUnsupportedProfile`（死枚举）、`relogin_wechat`（曾半接线）即样本。建立一次性"枚举生产者↔消费者穷尽性配对"检查，一并堵住此类残留（这也是文档 §24.5 建议 3 的落地）。

---

## Track B 目录结构优化建议

| # | 级别 | 现状 | 建议 |
| --- | --- | --- | --- |
| D-1 | 高 | 单一 `main` 包、93 个 `.go` 平铺，仅 `internal/workbudget`、`internal/cryptokdf` 两个子包（A1"部分完成"） | 按领域续拆 `internal/`：`protocol`、`catalog`、`crypto`(profile/HMAC/KDF)、`credential`、`session`、`platform/{darwin,windows}`、`diagnostics`。用 build-tag 分阶段迁移，避免一次性大改。**大手术，置于文档剥离与去冗余之后**。 |
| D-2 | 中 | 命名混用：`phase3_darwin_route.go`/`phase4_windows_route.go`（按 Phase 编号）与 `platform_darwin.go`/`windows_config_cipher.go`（按领域） | 统一按**领域**命名（platform/route/feature），Phase 是过程不是结构；把 `phase3_`/`phase4_` 前缀并入领域文件或 `internal/platform/*`。 |
| D-3 | 中 | 工作树含 `.codex-temp/audit-gocache/`（数千个 Go build cache 文件）与 `v-local-key-provider.exe`、`.phase3-provider.test.exe` | 三者均已在 `.gitignore`（不会入库，无风险），但污染工作树、拖慢搜索/工具。建议从工作树物理清除 `.codex-temp/` 与本地二进制。 |
| D-4 | 高 | 规范/审计/迁移三类内容挤在一个 1463 行文档 | 拆成规范 + `AUDIT_LOG.md` + `MIGRATION_FROM_LEGACY.md`（呼应 A-1/A-3）。 |
| D-5 | 低 | 契约测试（`release_contract_test.go`、`phase_regression_test.go`、`live_regression_test.go`）与单元测试混在根目录 | 可显式标注/分组（build-tag 或子目录），让"契约/回归/单元"分层可见；配合 §19 验收矩阵与 [`REGRESSION_TESTS.md`](REGRESSION_TESTS.md)。 |

---

## 审查方法、发现记录格式与产出

- **方法**：静态审读为主；`go build`/`go vet` 本机（文档称干净，复跑留证）；`go test` 正确性由 CI（本机 App Control 拦截）；darwin cgo 由对应架构真机 runner。审读**充分性**本机做，**正确性**归 CI/真机。
- **每条发现格式**：`级别(P0-P3 / 质量分级) | 位置(file:line @ 锁定基线) | 关联文档条款 | 失败场景 | 修复方向 | 是否与文档自评冲突`。
- **产出物**：
  1. 三分后的文档（规范 / 审计 / 迁移）+ Track A 重构 diff 清单；
  2. Phase 0-5 发现清单（区分"核实通过""核实推翻自评""新发现"）；
  3. 重构着力点（按性价比排序）；
  4. 目录迁移提案（D-1/D-2 的分包与命名映射表）。

## 建议执行顺序（性价比）

1. **Track 0** 锁定基线（不做无法开展）。
2. **Track A** 文档剥离与去重（低风险、高收益、立即减少过时内容）。
3. **X-2 / X-5** 双实现与死代码（直接减冗余，改动收敛）。
4. **X-1**（+A-5）God-file 与自评核实（最难审、最易引 bug 之处）。
5. **Track B** 各 Phase 逐条核实文档"已修复"声称。
6. **D-1 / D-2** 目录分包与改名（大手术，最后做，且以 build-tag 分阶段）。

## 全程红线

- 不得用普通 CI / mock / 交叉编译 / 历史记录 / 签名，冒充 §25.3 任一未解除门禁的真机证据。
- 基线未锁定前不采信任何 `file:line`。
- 先判"设计意图"再判"冗余/死代码"，避免误伤（如 root `pbkdf2_test.go`）。
- 文档自评（"零 P0/P1""X 完成"）一律视为待验证假设。
