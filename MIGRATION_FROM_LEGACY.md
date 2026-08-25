# 旧方案迁移追踪

> 本文只记录旧方案到当前规范的迁移 provenance，不定义运行时契约或能力状态。规范性要求以 [`KEY_ACQUISITION_AGENT_ORCHESTRATION.md`](KEY_ACQUISITION_AGENT_ORCHESTRATION.md) 为准。

`保留`表示语义不变，`加强`表示仍满足旧约束且增加更严格条件，`纠正`表示经当前实现、社区源码或设计复核后不应原样保留。

| 旧方案主题 | 结论 | 新方案落点或变化 |
| --- | --- | --- |
| 目标账号目录下全部有效 `.db`，不依赖当前是否打开 | 加强 | 7.1 递归 catalog；`-wal/-shm` 不作独立 DB，异常文件显式分类，generation 阶段再关联 WAL。 |
| 每个数据库首页 HMAC、完整/部分覆盖语义 | 加强 | 6.3、7.4、11.1、21；同一 salt 也逐物理文件验证。 |
| 已保存候选覆盖率前置检查 | 保留 | 10.6 增加 `SAVED_CREDENTIAL_COVERAGE`，16.3 refresh 优先复用结构化凭据。 |
| 平台、版本、目标进程实际架构、权限和 wait-for 后重检 | 加强 | 10.6、12.1-12.2；另外重检签名、账号绑定和 route。 |
| 稳定内部流水线和 route ID | 加强 | 10.6、11.2；route 拆分 standard/Shadow/SIP-disabled，仍不代表候选已验证。 |
| 全局 passphrase、逐库 key、mixed 与逐库验真 | 加强 | 5、6、8；根凭据和当前 effective key map 分离。 |
| “相同 salt 的文件共享同一个最终 key” | 纠正 | 2.6、6.3、17.2：只复用该 passphrase/profile 下的派生计算；不假设不同根凭据得到同一 key，不复用文件验证结论。 |
| 账号 A 数据绑定、当前会话账号状态及多进程隔离 | 加强 | 8.2-8.3、9、19.4；明确 mismatch/unknown 的机器响应和保存门禁。 |
| macOS `CCCrypt*` 与 `CCKeyDerivationPBKDF` 双观察 | 加强 | 12.3-12.4；完整识别 KDF 参数，并把已证实的 rounds=2 形态关联为 raw key 候选。 |
| 当前进程触发 -> 完整重启 -> 有证据时重新登录 | 保留 | 12.5、15；RPC 可返回动作，但 daemon 持续保持 hook。 |
| 动态路径失败后的有界静态 fallback | 加强 | 12.6；严格进入条件、missing-only 和固定扫描顺序。 |
| Windows `Config.Cipher` 优先、现有扫描兜底 | 保留 | 13；新路径通过 fingerprint registry 约束，旧路径保留到真机验收完成。 |
| Windows 默认一次 session，不要求重启/重登 | 保留 | 13.3、19.3；主路径与 missing-only fallback 共用 wall-time。 |
| 候选归一化、优先级、冲突和歧义 | 加强 | 8、11.1、19；候选增加进程实例和证据绑定。 |
| 独立阶段预算、计数与耗时诊断 | 加强 | 17.1-17.3、18；补全旧字段并要求稳定枚举。 |
| Agent 按 next action 编排，不盲目重试 | 加强 | 10.4-10.5、11.3、15；动作回执、状态变化和 session hard limit 都是门槛。 |
| 本地授权数据、Provider 不联网、不修改微信、秘密不进日志 | 加强 | 3、14、18、19.5；增加 IPC、helper 信任、crash/core dump 和路径越界防护。 |
| media 阶段 | 加强 | 16.5、17.3、19.4；与 database coverage 分离，但在请求 media scope 时纳入总体结果。 |
| 不引入 Skill | 保留 | 3.2；Agent 只消费 v1 机器协议，不依赖对话记忆或外部 Skill 保存秘密。 |
| “只修改 Provider，调用方完全不变” | 纠正 | 2.1、16；结构化根凭据、系统凭据库存储和 generation 绑定要求 Provider 与 CLI 原子修改。 |
| 沿用未发布的 `v-local-key-provider/v2` | 纠正 | 2.2、10.1；项目尚未首发，公开契约从完整的 v1 开始，不为未发布常量制造兼容债。 |
| Provider 返回动作后一次性 hook 结束 | 纠正 | 10.4-10.5；RPC 结束不等于 acquisition session 结束，daemon 必须跨用户动作保持 hook。 |
| 普通诊断可以返回相对路径 | 加强 | 7.1、18；默认只返回 opaque ID，只有显式 `--show-paths` 才在本机映射相对路径。 |
| 最后依据真实耗时调预算和候选上限 | 保留 | Phase 5；在真机证据完成后校准。 |

旧方案中需要继续成立的约束均有明确落点；未原样继承的内容仅限上表标为 `纠正` 的设计决定，不属于无意遗漏。
