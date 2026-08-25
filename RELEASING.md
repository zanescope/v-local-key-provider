# 发布流程

正式发布只从版本标签触发 `.github/workflows/release.yml`，标签必须与
`npm/package.json` 以及运行时 `--version` 完全一致。例如当前预发布版本使用
`v0.1.0-dev.0`，并发布到 npm 的 `next` dist-tag；无预发布后缀的版本才进入
`latest`。

## 一次性配置

在 GitHub `release` environment 中配置并保护以下 secrets：

- `WINDOWS_SIGNING_CERTIFICATE_BASE64`、`WINDOWS_SIGNING_CERTIFICATE_PASSWORD`
- `MACOS_SIGNING_CERTIFICATE_BASE64`、`MACOS_SIGNING_CERTIFICATE_PASSWORD`
- `MACOS_CODESIGN_IDENTITY`
- `APPLE_NOTARY_APPLE_ID`、`APPLE_NOTARY_TEAM_ID`、`APPLE_NOTARY_APP_PASSWORD`

该包按 npm 规则声明为 `dual-use`，`contentPolicy` 和包根目录的 `DISCLOSURE`
不得在后续版本删除。OIDC 只用于 `npm stage publish`；每个 staged package 仍须维护者
用 2FA 审核批准。

npm 要求包先存在才能配置 Trusted Publisher，而当前包尚未创建。第一个签名 Release
生成后，维护者必须下载并检查其中的 tgz，再在已登录且启用 2FA 的终端完成一次 bootstrap：

```sh
npm publish ./zanescope-v-local-key-provider-0.1.0-dev.0.tgz --access public --tag next
npm trust github @zanescope/v-local-key-provider --file release.yml --repo zanescope/v-local-key-provider --env release --allow-stage-publish
```

bootstrap 后，正式流水线只提交 staged publish，不接受长期 npm token，也不直接绕过 2FA 发布。

## 发布步骤

1. 在 `main` 上运行 `Audit gates` 和 `Release candidate`。候选工作流以 `buildMode=candidate` 构建四个平台资产，生成 `candidate-manifest.json`（绑定源码提交、workflow run id、Provider/helper 摘要），并为清单和全部资产生成 GitHub artifact attestation。
2. 手动触发 `Phase 3-4 live regression`，明确提供候选 run id 和源码提交。真机工作流会跨 workflow 下载那一份不可变候选，复核清单中的全部摘要，并以 `gh attestation verify --signer-workflow .../release-candidate.yml` 验证来源；禁止在真机 runner 重新构建替代品。真机输出必须是脱敏 schema v2 JSON，并记录候选来源、目标微信身份、实际进程架构、registry route、完整覆盖和验证过的 cipher profile。
3. 以证据文件自身 SHA-256 命名并提交到 `compatibility-evidence/`。registry 条目只保存候选前即可确定的精确目标身份、架构、profiles 和 route recipe，不再保存 evidence 摘要。用 `node npm/scripts/candidate-manifest.js promote <candidate-manifest> compatibility-evidence/promotions/<release-tag>.json <evidence...>` 生成外部 promotion；x64、ARM64、不同目标 fingerprint 不得共用证据。
4. `TestReleaseCompatibilityEvidenceGate` 会确认 promotion 的每个候选摘要、来源提交、workflow run、Provider/helper 集合、内容寻址 evidence、目标身份、route、coverage 和 profiles 与 registry 完全一致，并要求覆盖该架构的全部 eligible 条目。签名 workflow 还会按 promotion 的 run id 重新下载候选，复核统一清单和全部资产摘要，并用 `gh attestation verify --source-digest <candidate-commit> --signer-workflow .../release-candidate.yml` 再次验证来源，而不是只相信 evidence 中的布尔字段。promotion 不参与候选编译，因此不会再形成 `binary -> evidence -> binary` 自引用；缺失或不完整时正式签名构建仍会有意失败。
5. 确认 Windows Authenticode、macOS Developer ID/notarization 与干净 npm 安装验收方案就绪，再在只比候选提交多出 `compatibility-evidence/**` 的提交上创建与包版本一致的标签，例如 `v0.1.0-dev.0`。发布工作流会验证这个受限 diff 和 promotion 来源提交的祖先关系。
6. `Signed release` 校验 promotion 后重新构建并启用 `buildMode=release`，把 promotion SHA-256 注入二进制。Windows 同时注入签名叶证书 SHA-256，再做 Authenticode/RFC3161 签名和一致性复核；macOS 使用固定 code identifier、Hardened Runtime、Developer ID 与 notarization。工作流生成每架构签名 manifest、notary log、`release-checksums.txt` 和正式 artifact attestation，然后只创建 GitHub prerelease。
7. 下载这个确切 prerelease，在对应架构干净机器从最终 tgz 安装。确认安装树没有 symlink/junction 重定向，`provider status` 显示发行签名信任，任意路径 override 被拒绝，daemon PID image 与已签名 Provider/helper 一致，并复验 WER/core-dump、临时目录和普通日志不含 secret。再执行最终签名件的真实目标路径和安全姿态验收；通过后才人工提升 GitHub Release，并在核对同一 tgz 摘要后用 2FA 批准 staged npm publish。

任一兼容证据绑定、证书身份、公证/staple、摘要、版本、运行时信任、干净机器或 Trusted Publishing 步骤失败时，正式发布作业必须失败。签名、公证和 CI 通过不会升级 `build_only/unverified`；只有对应目标 fingerprint/架构的内容寻址真机证据，以及对最终签名发布件的复验，才能改变能力声明。
