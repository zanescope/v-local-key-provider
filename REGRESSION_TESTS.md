# 回归测试矩阵

测试分为三层：

- `CI`：不依赖真实微信账号，所有提交必须通过；
- `platform CI`：依赖 Windows 或 macOS ABI/权限语义，但不把 GitHub runner 当作真实微信验收；
- `live/release`：只在明确授权的专用真机或签名发布环境运行，保存脱敏证据，不上传路径、账号、候选或密钥。

任何 `live/release` 行没有证据时，能力状态必须保持 `build_only`、`experimental` 或 `unverified`。单元测试和 mock 不能把该状态升级为 `real_device_verified`。

## 协议、Catalog 与验证器

| ID | 回归点 | 自动化证据 |
| --- | --- | --- |
| P0-01 | v1 schema、未知字段、deadline 边界、未发布 v2 拒绝 | `TestDecodeRequest*`、`TestDecodeRequestV1*` |
| P0-02 | Catalog 分类 encrypted/plaintext/truncated，WAL 不作为数据库 | `TestCatalogClassifiesEveryDatabaseWithoutTreatingWALAsDatabase` |
| P0-03 | machine-keyed database ID 稳定，Catalog 绑定物理文件证明 | `TestCatalogIdentifiersAreStableForOneMachineKey`、`TestCatalogProofChangesWhenPhysicalFileChanges` |
| P0-04 | Unicode/case 路径规范化、symlink/reparse 与越界路径拒绝 | `TestCatalogPathKeyNormalizesUnicode`、平台 path-safety 测试、CLI snapshot 测试 |
| P0-05 | raw key/passphrase 统一走 profile 首页 HMAC | `TestRawKeyRequiresFirstPageHMAC`、`TestPassphraseReturnsDatabaseSpecificEffectiveKey` |
| P0-06 | 同 salt 仅复用派生，不复用物理文件验证 | `TestSameSaltFilesAreVerifiedIndependently` |
| P0-07 | 同一 effective key 的多来源去重；不同 key 冲突 | `TestSameEffectiveKeyFromMultipleSourcesIsDeduplicated`、`TestDifferentKeysForSameProfileAreValidatorConflict` |
| P0-08 | CLI 拒绝未知/重复 profile、伪造覆盖计数和 missing ID | CLI `TestValidateBundle*` |
| P0-09 | scope-qualified coverage、media-only `not_requested`、scope 回显及整体结果不变量 | Provider `TestOptionsFromRequestRejectsDuplicateScopes`、`internal/diagnostics.TestFinalizeKeepsCoverageOrthogonalAndScopeExplicit`、`TestCoverageDiagnosticsJSONUsesOnlyScopeQualifiedFields`；CLI `TestValidateBundleRejectsAmbiguousOrContradictoryScopeCoverage`、`TestValidateBundleRejectsRequestedScopeEchoMismatch` |
| P0-10 | ciphertext 无 authenticated profile marker 时不得伪造 `unsupported_profile`；所有已登记 profile 均可达 | `TestCatalogDoesNotPinEncryptedPagesToDefaultProfile`、`TestNonDefaultRegisteredProfileCanValidate`；Provider/CLI schema 不再包含死枚举或恒零计数器 |

## 结构化凭据

| ID | 回归点 | 自动化证据 |
| --- | --- | --- |
| P1-01 | global/per-database/mixed 的根与 override 不混淆 | `TestDatabaseCredentialSeparatesGlobalRootAndOverrides` 及 CLI credential tests |
| P1-02 | 单库、单 salt、不同 passphrase、跨 profile 或缺 KDF 调用证据不提升根 | `TestDatabaseCredentialDoesNot*`、`TestMultiSaltProbeWithoutKDFCallEvidenceStaysPerDatabase`、`TestGlobalRootRequiresTwoSaltsWithinTheSameProfile` |
| P1-03 | 同一 passphrase 跨两个不同 salt 逐库通过后才提升 | `TestPassphraseEvidenceStaysBoundAcrossTwoSalts` |
| P1-04 | partial 保存 verified effective overrides，不保存未经完全证明的根 | CLI `TestBindPartialCredentialStripsRootAndPreservesVerifiedEffectiveKey` |
| P1-05 | 系统凭据库结构化往返及跨账号拒绝 | CLI state `TestStructuredCredential*` |
| P1-06 | refresh 不访问微信进程并覆盖同 epoch 新数据库 | CLI `TestExpandGlobalCredentialCoversNewDatabaseWithoutProcessAccess`、`TestRefreshUsesStoredSecretsWithoutProcessAccess` |
| P1-07 | partial generation 不覆盖更完整旧 generation | CLI snapshot `TestBuildPreventsCoverageRegressionAndKeepsPreviousSnapshot` |
| P1-08 | plaintext 与 database/media coverage 独立 | Provider/CLI plaintext、media 和 deadline partial tests |

## Daemon 与状态机

| ID | 回归点 | 自动化证据 |
| --- | --- | --- |
| P2-01 | 私有 endpoint、loopback、256-bit token、猜测令牌拒绝 | `TestAcquisitionDaemon*`、`TestDaemonRejectsGuessedTokenWithoutAffectingAuthenticatedSession`、平台 DACL/permission tests |
| P2-02 | 慢速未认证连接不阻塞已认证调用 | `TestAcquisitionDaemonDoesNotLetSlowUnauthenticatedClientBlockPing` |
| P2-03 | prepare/observe/finalize，observe 不返回 secret，finalize 只返回一次 | `TestObserveKeepsSecretsInSessionUntilFinalize`、`TestFinalizeReturnsTerminalSessionResultWithoutRepeatingAcquisition` |
| P2-04 | Catalog/session/process/route/stage 绑定与漂移拒绝 | `TestSessionRejectsCatalogDriftBeforeAcquisition`、receipt binding tests |
| P2-05 | trigger/restart/relogin receipt 不能猜测、重放或盲循环 | `TestSessionRejectsDuplicateActionReceiptWithoutStateChange`、`TestActionsHaveFiniteRetryBudgets` |
| P2-06 | `stop_and_report` 只保留已验真的 partial | `TestFinalizeWithoutActionReceiptReturnsVerifiedPartialAndEndsSession` 及 CLI daemon tests |
| P2-07 | session hard limit、取消、断连和第二 prepare 冲突 | session/platform-session/daemon lifecycle tests |
| P2-08 | missing-only 不重复扫描已完成数据库 | `TestMissingOnlyTargetsExcludesAlreadyVerifiedDatabase` |
| P2-09 | mismatch、complete、action、permission、conflict、ambiguous、deadline、partial 的单一有序优先级 | `internal/diagnostics.TestFinalizeOutcomePriorityRegression`、`TestOutcomeRulePriorityAndDefaultAreStable`、session `stop_and_report` mismatch integration test |
| P2-10 | Shadow/SIP 跨重启 checkpoint 不含授权、路径或 session；新 session 复验后才清除 | CLI `TestExternalCheckpoint*`、`TestSensitiveActionsAreNotDaemonResumable`、Provider `internal/diagnostics.TestFinalizeRequiresSIPRestoration` |

## macOS 平台

默认 macOS CI 必须运行 `go test ./...` 和 `go vet ./...`，覆盖：`internal/platform/darwin` 的 process/Mach driver、进程过滤和隔离扫描，以及 build-tagged hook 的实际架构寄存器、`CCCrypt*`/`CCKeyDerivationPBKDF` 双观察、rounds=256000 passphrase、rounds=2 raw key、wait-for 先装 hook、helper deadline/loopback、临时 secret 文件禁止和生命周期清理。

本节 P3-04 是尚未启用的 Shadow 目标态验收项，不是当前能力声明。当前构建必须把 Shadow 报告为 `unavailable_in_build`，保留 `standard -> shadow -> sip_disabled` 的优先级，并按 P3-05/P3-10 在该槽位终态不可用时允许用户选择 SIP fallback；绝不能伪造 `attempted_failed`。

以下项目必须通过 `.github/workflows/live-regression.yml` 在专用真机分别执行，不能合并证据：

| ID | 真机组合 | 必须验证 |
| --- | --- | --- |
| P3-01 | Apple Silicon / native arm64 / SIP on / standard | 实际进程架构、binary fingerprint、standard route、完整或准确 partial |
| P3-02 | Intel x86_64 / SIP on / standard | x86_64 ABI、standard route、当前进程触发与 wait-for 重启 |
| P3-03 | Apple Silicon / Rosetta x86_64 微信 | runner 为 arm64、目标进程为 amd64，候选不得跨进程混合 |
| P3-04 | Apple Silicon 与 Intel / SIP on / Shadow | Shadow 只在用户明确批准后进入；stock 数据与进程不被修改 |
| P3-05 | standard unavailable，Shadow 为 `unavailable_in_build`、`unsupported_for_target` 或 `attempted_failed` | 状态与 blocking reason 精确匹配后只返回 `disable_sip` 引导，不自动修改 SIP |
| P3-06 | SIP disabled | helper trust、管理员最小权限、目标账号绑定和密钥覆盖 |
| P3-07 | SIP 恢复后的新 session | `csrutil status` 机器验证并返回恢复完成状态，不接受纯用户回执 |
| P3-08 | 多进程/错账号/未知账号 | A/B 进程候选隔离；mismatch 不保存根；unknown 只接受目标 DB HMAC |
| P3-09 | 拒绝 Shadow/SIP、hook 超时、候选冲突 | 有界停止、无进程暂停、无 secret 临时文件或日志 |
| P3-10 | Shadow 未实现但优先级高于 SIP | Provider 返回 `shadow_route_status=unavailable_in_build`，不伪造失败；标准访问失败且 SIP 已验证时允许 `disable_sip`，见 Provider `internal/diagnostics.TestFinalizeDarwinShadowFallbackPolicy` 与 CLI `TestDisableSIPActionRequiresTerminalShadowRouteEvidence` |

真机命令由工作流设置不含私有路径的 `V_LOCAL_KEY_PROVIDER_LIVE_*` 预期值后执行。账号和数据库目录只从 runner 本机固定位置的 schema v1 私有配置读取；配置文件及其父目录必须由当前用户持有、禁止继承或普通用户访问，并且不得是 symlink、junction 或 reparse point：

```text
go test -tags=live_regression -run '^TestMacOSLiveAcquisition$' -count=1 .
```

每种 route 和动作阶段单独运行；测试只验证已准备好的机器状态，不会自动重启微信、替换应用或更改 SIP。

## Windows 平台

| ID | 回归点 | 证据 |
| --- | --- | --- |
| P4-01 | Weixin 根进程/子进程筛选与实际 x64/ARM64 架构 | `internal/platform/windows` tests，包括 `TestWindowsReportsActualCurrentProcessArchitecture` |
| P4-02 | 已登记 4.1.x `Config.Cipher` fingerprint 主路径 | `TestWindowsRegistryRequiresExactMachineEvidence`、extractor 边界测试；专用 x64/ARM64 真机断言精确 registry route |
| P4-03 | 未登记 fingerprint 或固定结构失效时安全 fallback | CLI `TestWindowsEvidenceCannotMisleadTheAgent`；专用真机分别断言 fallback route 与准确诊断 |
| P4-04 | 多 Weixin/WeChat、多账号和部分进程 access denied | `TestMergeValidatedCollectorDoesNotMergeUnverifiedProcessCandidates`、Windows handle-path 分类与 opaque process provenance 测试；专用多进程测试账号 |
| P4-05 | 定向 partial 后 missing-only fallback | `TestMissingOnlyTargetsExcludesAlreadyVerifiedDatabase`、`TestConfigCipherPassphraseCannotBecomeAccountRoot`；真机计数证明已完成 ID 不被重复扫描/KDF/验证 |
| P4-06 | 候选冲突、预算耗尽、单 session 有界结束 | CI 状态/预算测试 + 真机阶段计时 |
| P4-07 | 默认不重启、不重登、不宽泛终止进程 | `TestWindowsSourceHasNoProcessTerminationPath` + 真机进程实例前后对比 |

真机入口：

```text
go test -tags=live_regression -run '^TestWindowsLiveAcquisition$' -count=1 .
```

Windows x64 与 Windows ARM64 必须分别保存证据；交叉编译不能替代 ARM64 真机。
当 `live-regression.yml` 尚未进入默认分支、因而没有可直接 dispatch 的 workflow ID 时，只能通过
默认分支已经注册的 `Audit gates` 的 `live_regression_request` 调用同一 reusable workflow。该 JSON
只允许携带候选来源、预期枚举和专用 runner label，不得携带账号或数据库路径。
工作流必须显式设置预期 registry、`Config.Cipher`、route、架构和账号绑定状态。正式入口使用
180 秒总 deadline；逐阶段窗口、每进程字节上限和总扫描上限仍由 Provider 保持不变。工作流上传
`build/live/evidence.json`。工作流固定请求 `database,media`，两类 coverage 都必须为 complete。
该文件只含版本、摘要、稳定枚举、计数和耗时，并显式声明 secret、路径、账号身份和聊天内容
均未包含；不得含账号路径、数据库路径、进程内存、候选或密钥。

若采集或正式证据门禁失败，工作流可以额外上传 `build/live/diagnostic.json`，但该文件必须是
schema v1、`qualification_only=true`、`formal_release_evidence=false` 且 `promotion_verified=false`。
诊断只允许固定枚举、阶段计时、字节数和计数，不得包含目标摘要、版本、路径、账号身份、
原始 Provider 响应、密钥候选或密钥；正式 evidence 解码器必须拒绝该诊断，promotion 也不得引用它。

## 发布安全

| ID | 回归点 | 自动化/发行证据 |
| --- | --- | --- |
| P5-01 | Windows Authenticode、编译期叶证书 SHA-256 绑定、离线 WinVerifyTrust、RFC3161 时间戳 | `scripts/build.ps1 -Release` 与 `TestReleaseWorkflowKeepsSigningNotarizationAndProvenanceGates` |
| P5-02 | macOS Provider/helper 固定 identifier、Hardened Runtime、Developer ID/Team ID、notarization、DMG staple、无 warning/error 日志、Gatekeeper | signed release workflow contract test |
| P5-03 | GitHub artifact attestation 与 npm Trusted Publishing | signed release workflow contract test |
| P5-04 | 发布资产集合与 checksum 一一绑定 | `npm run verify-release`；只有正式构建资产生成后运行 |
| P5-05 | checksum 路径/重复项、下载协议/主机/端口、重定向保留独占 descriptor、随机临时文件、Provider/helper 集合提交与回滚 | npm `install.test.js` |
| P5-06 | 固定当前用户安装路径及无 symlink/junction 祖先；发行版拒绝路径 override，开发绕过需路径 + development + allow 三重显式授权 | CLI status tests、npm tests 与 macOS helper override test |
| P5-07 | endpoint/resume/diagnostics/普通日志不含 secret；Unix core=0、Windows WER NOHEAP 与 excluded buffers | daemon/session/release contract tests；发布真机另做 crash/core-dump 检查 |
| P5-08 | 干净机器安装、版本不匹配、Keychain/Credential Manager、卸载清理 | signed npm 包在隔离 VM 执行 CLI `references/macos-acceptance.md` 和对应 Windows 清单 |
| P5-09 | 依据真机 timing/count 校准预算 | 汇总 `phase_timings_ms` 与候选计数；校准变更必须重新运行全部回归 |
| P5-10 | 每个发行架构必须有精确 registry 候选条目及外部 promotion 绑定的内容寻址真机证据；真机 workflow 必须下载并 attestation 验证指定候选，空 registry/promotion、重建候选、重复 evidence、错摘要、错来源/身份/架构/profile 均阻止签名构建 | `TestReleaseCompatibilityEvidenceGate`、`TestReleaseEvidenceArtifactIsContentAddressedAndExternallyPromoted`、`TestDarwinPromotionBindsProviderHelperAndRoute`、`candidate-manifest.test.js`；候选/live/signed-release workflow contract tests |

## 常规命令

Provider：

```text
go test -count=1 ./...
go test -race ./...
go vet ./...
npm --prefix npm test
```

CLI：

```text
go test -count=1 ./...
go test -race ./...
go vet ./...
npm --prefix npm test
```

正式候选还必须在生成全部资产及 `checksums.txt` 后运行两个仓库的 `npm run verify-release`，并执行签名发布工作流。开发树中的空 checksum 清单不能算失败，也不能用虚假摘要填充。
