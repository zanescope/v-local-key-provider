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

1. 在 `main` 上运行 `Audit gates` 和 `Release candidate`，下载候选件做真机验证。
2. 确认 Windows Authenticode、macOS Developer ID/notarization 与干净 npm 安装验收均有记录。
3. 从已验收提交创建并推送与包版本一致的标签，例如 `v0.1.0-dev.0`。
4. `Signed release` 会重新构建、签名、公证、校验摘要和来源证明，然后创建 GitHub Release。
5. 首次发布按上面的 bootstrap 操作；后续版本由工作流提交 staged publish，维护者检查后用 2FA 批准。

任一证书、公证、摘要、版本或 Trusted Publishing 步骤失败时，正式发布作业必须失败。
