# 发布流程

发布分为两个互不冒充的通道：

- `-dev.N` 是未签名 early-access，只能进入 GitHub prerelease 与 npm `next`。它使用
  `buildMode=candidate`，不要求 Authenticode、Developer ID、notarization 或 promotion，
  也不得宣称正式发行信任。
- 未来的 `-rc.N` 或稳定版本才进入 `.github/workflows/release.yml`。该通道继续要求
  promotion、平台签名、公证、最终签名件复验和 Trusted Publishing；无预发布后缀时
  才能进入 npm `latest`。

## 未签名 early-access

1. 在 `main` 上确认 `Audit gates` 全绿，手动运行 `Release candidate`。
2. 需要创建可下载版本时，设置 `publish_unsigned_preview=true`，并把确认值精确填写为
   `PUBLISH_UNSIGNED_PREVIEW`。工作流只允许从 `main` 发布与 `npm/package.json` 完全一致的
   `-dev.N` 版本。
3. 发布作业会先通过 GitHub API 确认同一 `main` 提交存在成功的 `Audit gates`。工作流再以 `buildMode=candidate` 构建四个平台资产，生成绑定源码提交、workflow run id
   和 Provider/helper 摘要的 `candidate-manifest.json`，并为清单、二进制和 tgz 生成 GitHub
   artifact attestation。发布作业会重新验证摘要、tgz 内校验和与 attestation，随后创建
   明确标记为 unsigned early access 的 GitHub prerelease；已有标签或 Release 一律拒绝覆盖。
4. 该通道不读取签名或 Apple 凭据，不生成 promotion，不执行 `npm publish`，也不会触发
   `Signed release`。首次 npm 发布或后续人工 early-access 发布必须从这个确切 prerelease
   下载 tgz、核对摘要，并在启用 2FA 的维护者终端发布到 `next`：

```sh
npm publish ./zanescope-v-local-key-provider-0.1.0-dev.0.tgz --access public --tag next
```

候选件虽然有内容摘要和 GitHub 来源证明，但没有平台签名信任；它只适合明确选择
early-access 的用户，不能提升为 `latest` 或替代正式签名件验收。

## 正式签名通道的一次性配置

仅在准备 signed release 时，才需要在 GitHub `release` environment 中配置并保护：

- `WINDOWS_SIGNING_CERTIFICATE_BASE64`、`WINDOWS_SIGNING_CERTIFICATE_PASSWORD`
- `MACOS_SIGNING_CERTIFICATE_BASE64`、`MACOS_SIGNING_CERTIFICATE_PASSWORD`
- `MACOS_CODESIGN_IDENTITY`
- `APPLE_NOTARY_APPLE_ID`、`APPLE_NOTARY_TEAM_ID`、`APPLE_NOTARY_APP_PASSWORD`

该包按 npm 规则声明为 `dual-use`，`contentPolicy` 和包根目录的 `DISCLOSURE`
不得在后续版本删除。包完成首次 2FA bootstrap 后，可为正式工作流配置 Trusted Publisher：

```sh
npm trust github @zanescope/v-local-key-provider --file release.yml --repo zanescope/v-local-key-provider --env release --allow-stage-publish
```

正式流水线只提交 staged publish，不接受长期 npm token，也不直接绕过 2FA 发布。

## 正式签名发布步骤

1. 在 `main` 上运行 `Audit gates` 和 `Release candidate`，并选定不可变候选集合。
2. 手动触发真机回归工作流（`live-regression.yml`），明确提供候选 run id 和源码提交。真机工作流会跨 workflow 下载那一份不可变候选，复核清单中的全部摘要，并以 `gh attestation verify --signer-workflow .../release-candidate.yml` 验证来源；禁止在真机 runner 重新构建替代品。账号目录和数据库目录不得进入 GitHub input、Secret 或环境变量：Windows runner 只从 `%LOCALAPPDATA%\v-local\live-regression-private\config.json` 读取，macOS runner 只从 `~/Library/Application Support/v-local/live-regression-private/config.json` 读取。该文件必须是 schema v1、仅含 `schema_version`、`account_dir`、`db_dir`，并满足平台专用的 owner、ACL/mode 和非 reparse/symlink 校验。真机固定同时请求 database 与 media；成功输出必须是脱敏 schema v1 正式证据。失败时只允许上传 qualification-only 诊断，且 promotion 不得引用它。
3. 以证据文件自身 SHA-256 命名并提交到 `compatibility-evidence/`。用 `node npm/scripts/candidate-manifest.js promote <candidate-manifest> compatibility-evidence/promotions/<release-tag>.json <evidence...>` 生成外部 promotion；x64、ARM64、不同目标 fingerprint 不得共用证据。
4. `TestReleaseCompatibilityEvidenceGate` 会确认 promotion 的候选摘要、来源提交、workflow run、Provider/helper 集合、内容寻址 evidence、目标身份、route、coverage 和 profiles 与 registry 完全一致。缺失或不完整时正式签名构建仍会有意失败。
5. 证书、公证和干净安装验收条件就绪后，将包版本提升到未来的 `-rc.N` 或稳定版本，再创建完全一致的标签。`-dev.N` 标签被明确排除在 Signed release 触发器之外。
6. `Signed release` 校验 promotion 后重新构建并启用 `buildMode=release`。Windows 注入签名叶证书 SHA-256 并完成 Authenticode/RFC3161；macOS 使用固定 code identifier、Hardened Runtime、Developer ID 与 notarization。工作流生成签名 manifest、notary log、`release-checksums.txt` 和正式 artifact attestation，然后只创建 GitHub prerelease。
7. 下载这个确切 signed prerelease，在对应架构干净机器复验固定安装、发行签名信任、override 拒绝、daemon PID image、crash artifact 和真实数据能力；通过后才人工提升 GitHub Release，并在核对同一 tgz 摘要后用 2FA 批准 staged npm publish。

证书资料尚未完成不会阻塞 unsigned early-access；但任一兼容证据绑定、证书身份、公证、摘要、运行时信任、干净机器或 Trusted Publishing 条件失败，仍必须阻塞 signed release 与 `latest`。签名、公证和 CI 通过本身也不会升级 `build_only/unverified` 能力声明。
