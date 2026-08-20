#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const path = require('path');

const packageRoot = path.resolve(__dirname, '..');
const allowedHosts = new Set([
  'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
]);

function target(platform = process.platform, arch = process.arch) {
  if (platform === 'win32' && arch === 'x64') {
    return {
      platform: 'windows', arch: 'amd64',
      asset: 'v-local-key-provider-windows-amd64.exe',
      binary: 'v-local-key-provider.exe',
      helperAsset: null, helperBinary: null,
    };
  }
  if (platform === 'darwin' && (arch === 'x64' || arch === 'arm64')) {
    const targetArch = arch === 'x64' ? 'amd64' : 'arm64';
    return {
      platform: 'darwin', arch: targetArch,
      asset: `v-local-key-provider-darwin-${targetArch}`,
      binary: 'v-local-key-provider',
      helperAsset: `v-local-key-provider-helper-darwin-${targetArch}`,
      helperBinary: 'v-local-key-provider-helper',
    };
  }
  throw new Error(`当前版本不支持 ${platform}/${arch}`);
}

function parseChecksums(text) {
  const result = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?([^\s]+)$/);
    if (!match) throw new Error(`无效的校验和记录：${line}`);
    result.set(match[2], match[1].toLowerCase());
  }
  return result;
}

function verifyHash(file, expected) {
  const actual = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  if (actual !== expected.toLowerCase()) {
    throw new Error(`二进制 SHA-256 不匹配：期望 ${expected}，实际 ${actual}`);
  }
}

function assertDownloadUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !allowedHosts.has(url.hostname)) {
    throw new Error(`拒绝从未授权地址下载：${url.origin}`);
  }
  return url;
}

function download(value, destination, redirects = 0) {
  if (redirects > 5) return Promise.reject(new Error('下载重定向次数过多'));
  const url = assertDownloadUrl(value);
  return new Promise((resolve, reject) => {
    const request = https.get(url, {headers: {'user-agent': '@zanescope/v-local-key-provider'}}, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        download(new URL(response.headers.location, url).toString(), destination, redirects + 1)
          .then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`下载失败：HTTP ${response.statusCode}`));
        return;
      }
      const stream = fs.createWriteStream(destination, {flags: 'wx', mode: 0o700});
      response.pipe(stream);
      stream.on('finish', () => stream.close(resolve));
      stream.on('error', reject);
    });
    request.setTimeout(30_000, () => request.destroy(new Error('下载超时')));
    request.on('error', reject);
  });
}

async function install() {
  if (process.env.V_LOCAL_KEY_PROVIDER_SKIP_BINARY_INSTALL === '1') return;
  const selected = target();
  const destinationDir = path.join(packageRoot, 'bin', `${selected.platform}-${selected.arch}`);
  const destination = path.join(destinationDir, selected.binary);
  fs.mkdirSync(destinationDir, {recursive: true});
  if (process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH) {
    fs.copyFileSync(path.resolve(process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH), destination);
    fs.chmodSync(destination, 0o700);
    if (selected.helperBinary) {
      const helperSource = process.env.V_LOCAL_KEY_PROVIDER_HELPER_BINARY_PATH ||
        process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH;
      const helperDestination = path.join(destinationDir, selected.helperBinary);
      fs.copyFileSync(path.resolve(helperSource), helperDestination);
      fs.chmodSync(helperDestination, 0o700);
    }
    return destination;
  }
  const packageInfo = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  const checksums = parseChecksums(fs.readFileSync(path.join(packageRoot, 'checksums.txt'), 'utf8'));
  const releaseVersion = packageInfo.version.replace(/-.+$/, '');
  const artifacts = [{asset: selected.asset, binary: selected.binary}];
  if (selected.helperAsset && selected.helperBinary) {
    artifacts.push({asset: selected.helperAsset, binary: selected.helperBinary});
  }
  for (const artifact of artifacts) {
    const expected = checksums.get(artifact.asset);
    if (!expected) throw new Error(`发布包缺少 ${artifact.asset} 的 SHA-256`);
    const artifactDestination = path.join(destinationDir, artifact.binary);
    const temporary = `${artifactDestination}.${process.pid}.tmp`;
    const url = `https://github.com/zanescope/v-local-key-provider/releases/download/v${releaseVersion}/${artifact.asset}`;
    try {
      await download(url, temporary);
      verifyHash(temporary, expected);
      fs.chmodSync(temporary, 0o700);
      fs.renameSync(temporary, artifactDestination);
    } finally {
      if (fs.existsSync(temporary)) fs.rmSync(temporary, {force: true});
    }
  }
  return destination;
}

if (require.main === module) {
  install().catch(error => {
    process.stderr.write(`Provider 安装失败：${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {assertDownloadUrl, install, parseChecksums, target, verifyHash};
