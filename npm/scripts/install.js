#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const https = require('https');
const os = require('os');
const path = require('path');

const packageRoot = path.resolve(__dirname, '..');
const allowedHosts = new Set([
  'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
]);
const maxBinaryBytes = 128 * 1024 * 1024;

function target(platform = process.platform, arch = process.arch) {
  if (platform === 'win32' && (arch === 'x64' || arch === 'arm64')) {
    const targetArch = arch === 'x64' ? 'amd64' : 'arm64';
    return {
      platform: 'windows', arch: targetArch,
      asset: `v-local-key-provider-windows-${targetArch}.exe`,
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

function installationBase(platform = process.platform, environment = process.env, home = os.homedir()) {
  if (platform === 'win32') {
    const value = String(environment.LOCALAPPDATA || '').trim();
    if (!value || !path.isAbsolute(value)) {
      throw new Error('LOCALAPPDATA 不可用，无法确定当前用户固定安装目录');
    }
    return path.resolve(value);
  }
  if (platform === 'darwin') {
    if (!home || !path.isAbsolute(home)) {
      throw new Error('用户主目录不可用，无法确定当前用户固定安装目录');
    }
    return path.join(path.resolve(home), 'Library', 'Application Support');
  }
  throw new Error(`当前版本没有 ${platform} 的固定安装目录`);
}

function installationDirectory(selected = target(), base = installationBase()) {
  return path.join(path.resolve(base), 'v-local', 'key-provider', `${selected.platform}-${selected.arch}`);
}

function installedBinaryPath(selected = target(), base = installationBase()) {
  return path.join(installationDirectory(selected, base), selected.binary);
}

function sameResolvedPath(left, right, platform = process.platform) {
  const first = path.resolve(left);
  const second = path.resolve(right);
  return platform === 'win32' ? first.toLowerCase() === second.toLowerCase() : first === second;
}

function assertDirectDirectory(directory, platform = process.platform, filesystem = fs) {
  const absolute = path.resolve(directory);
  const info = filesystem.lstatSync(absolute);
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error(`安装目录不能是符号链接或目录联接：${absolute}`);
  }
  const realpath = filesystem.realpathSync.native || filesystem.realpathSync;
  const resolved = realpath(absolute);
  if (!sameResolvedPath(absolute, resolved, platform)) {
    throw new Error(`安装目录祖先包含符号链接或目录联接：${absolute}`);
  }
  if (platform !== 'win32' && typeof process.geteuid === 'function') {
    const uid = process.geteuid();
    if ((info.uid !== uid && info.uid !== 0) || (info.mode & 0o022) !== 0) {
      throw new Error(`安装目录所有者或写权限不可信：${absolute}`);
    }
  }
  return absolute;
}

function prepareInstallationDirectory(destination, base, platform = process.platform, filesystem = fs) {
  const absoluteBase = path.resolve(base);
  const absoluteDestination = path.resolve(destination);
  const relative = path.relative(absoluteBase, absoluteDestination);
  if (relative === '' || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
    throw new Error('安装目录必须是固定安装基目录的非空后代');
  }
  assertDirectDirectory(absoluteBase, platform, filesystem);
  let current = absoluteBase;
  for (const segment of relative.split(path.sep)) {
    if (!segment || segment === '.' || segment === '..') throw new Error('安装目录层级无效');
    current = path.join(current, segment);
    try {
      filesystem.mkdirSync(current, {mode: 0o700});
    } catch (error) {
      if (!error || error.code !== 'EEXIST') throw error;
    }
    assertDirectDirectory(current, platform, filesystem);
    if (platform !== 'win32') {
      filesystem.chmodSync(current, 0o700);
      assertDirectDirectory(current, platform, filesystem);
    }
  }
  return absoluteDestination;
}

function parseChecksums(text) {
  const result = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?([^\s]+)$/);
    if (!match) throw new Error(`无效的校验和记录：${line}`);
    const name = match[2];
    if (path.basename(name) !== name || name.includes('/') || name.includes('\\') || name === '.' || name === '..') {
      throw new Error(`校验和文件名不能包含路径：${name}`);
    }
    if (result.has(name)) throw new Error(`校验和包含重复资产：${name}`);
    result.set(name, match[1].toLowerCase());
  }
  return result;
}

function releaseTag(version) {
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new Error(`npm 包版本无法映射到 GitHub Release：${version}`);
  }
  return `v${version}`;
}

function releaseUrl(version, asset) {
  return `https://github.com/zanescope/v-local-key-provider/releases/download/${releaseTag(version)}/${asset}`;
}

function sha256(file) {
  const hash = crypto.createHash('sha256');
  const descriptor = fs.openSync(file, 'r');
  const buffer = Buffer.allocUnsafe(1024 * 1024);
  try {
    for (;;) {
      const bytes = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (bytes === 0) break;
      hash.update(buffer.subarray(0, bytes));
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return hash.digest('hex');
}

function verifyHash(file, expected) {
  const actual = sha256(file);
  if (actual !== expected.toLowerCase()) {
    throw new Error(`二进制 SHA-256 不匹配：期望 ${expected}，实际 ${actual}`);
  }
}

function assertDownloadUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || !allowedHosts.has(url.hostname) ||
      url.username !== '' || url.password !== '' || url.port !== '') {
    throw new Error(`拒绝从未授权地址下载：${url.origin}`);
  }
  return url;
}

function reserveSiblingFile(destination, suffix, mode, filesystem = fs) {
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const nonce = crypto.randomBytes(16).toString('hex');
    const candidate = path.join(path.dirname(destination), `.v-local-key-provider-${nonce}.${suffix}`);
    try {
      const descriptor = filesystem.openSync(candidate, 'wx', mode);
      return {path: candidate, descriptor};
    } catch (error) {
      if (error && error.code === 'EEXIST') continue;
      throw error;
    }
  }
  throw new Error('无法创建随机独占的安装临时文件');
}

function reserveSibling(destination, suffix, mode, filesystem = fs) {
  const reservation = reserveSiblingFile(destination, suffix, mode, filesystem);
  filesystem.closeSync(reservation.descriptor);
  return reservation.path;
}

function replaceFiles(replacements, filesystem = fs) {
  if (!Array.isArray(replacements) || replacements.length === 0) {
    throw new Error('原子安装集合不能为空');
  }
  const destinations = new Set();
  const states = replacements.map(replacement => {
    const temporary = path.resolve(replacement.temporary);
    const destination = path.resolve(replacement.destination);
    if (path.dirname(temporary) !== path.dirname(destination)) {
      throw new Error('安装临时文件必须与目标文件位于同一目录');
    }
    if (destinations.has(destination)) throw new Error(`安装集合包含重复目标：${destination}`);
    if (!filesystem.existsSync(temporary)) throw new Error(`安装临时文件不存在：${temporary}`);
    destinations.add(destination);
    return {temporary, destination, backup: '', movedOld: false, installed: false};
  });

  try {
    for (const state of states) {
      if (!filesystem.existsSync(state.destination)) continue;
      state.backup = reserveSibling(state.destination, 'old', 0o600, filesystem);
      filesystem.rmSync(state.backup);
    }
    for (const state of states) {
      if (!state.backup) continue;
      filesystem.renameSync(state.destination, state.backup);
      state.movedOld = true;
    }
    for (const state of states) {
      filesystem.renameSync(state.temporary, state.destination);
      state.installed = true;
    }
  } catch (error) {
    const rollbackErrors = [];
    for (const state of [...states].reverse()) {
      if (!state.installed || !filesystem.existsSync(state.destination)) continue;
      try {
        filesystem.renameSync(state.destination, state.temporary);
        state.installed = false;
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
    }
    for (const state of [...states].reverse()) {
      if (!state.movedOld || !filesystem.existsSync(state.backup)) continue;
      try {
        if (filesystem.existsSync(state.destination)) filesystem.rmSync(state.destination, {force: true});
        filesystem.renameSync(state.backup, state.destination);
        state.movedOld = false;
      } catch (rollbackError) {
        rollbackErrors.push(rollbackError);
      }
    }
    if (rollbackErrors.length > 0) {
      const combined = new Error(
        `安装失败且回滚不完整：${error.message}; ${rollbackErrors.map(value => value.message).join('; ')}`,
      );
      combined.cause = error;
      throw combined;
    }
    throw error;
  }
  for (const state of states) {
    if (!state.movedOld || !filesystem.existsSync(state.backup)) continue;
    try {
      filesystem.rmSync(state.backup, {force: true});
    } catch (_) {
      // 新安装集合已完整提交；保留随机命名的旧副本比反向破坏已提交集合更安全。
    }
  }
}

function replaceFile(temporary, destination) {
  replaceFiles([{temporary, destination}]);
}

function allowUnverifiedLocalBinary(environment = process.env) {
  return Boolean(String(environment.V_LOCAL_KEY_PROVIDER_BINARY_PATH || '').trim()) &&
    environment.V_LOCAL_KEY_PROVIDER_DEVELOPMENT === '1' &&
    environment.V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY === '1';
}

function download(value, destination, redirects = 0, descriptor = undefined, requester = https.get) {
  if (redirects > 5) return Promise.reject(new Error('下载重定向次数过多'));
  const url = assertDownloadUrl(value);
  return new Promise((resolve, reject) => {
    const request = requester(url, {headers: {'user-agent': '@zanescope/v-local-key-provider'}}, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        response.resume();
        download(
          new URL(response.headers.location, url).toString(), destination,
          redirects + 1, descriptor, requester,
        )
          .then(resolve, reject);
        return;
      }
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error(`下载失败：HTTP ${response.statusCode}`));
        return;
      }
      const declaredLength = Number(response.headers['content-length']);
      if (Number.isFinite(declaredLength) && declaredLength > maxBinaryBytes) {
        response.resume();
        reject(new Error('下载响应超过二进制大小上限'));
        return;
      }
      const stream = descriptor === undefined ?
        fs.createWriteStream(destination, {flags: 'wx', mode: 0o700}) :
        fs.createWriteStream(destination, {fd: descriptor, autoClose: false});
      let received = 0;
      response.on('data', chunk => {
        received += chunk.length;
        if (received > maxBinaryBytes) response.destroy(new Error('下载响应超过二进制大小上限'));
      });
      response.pipe(stream);
      stream.on('finish', () => {
        if (received <= 0 || received > maxBinaryBytes) {
          reject(new Error('下载响应大小无效'));
        } else {
          resolve();
        }
      });
      stream.on('error', reject);
      response.on('error', reject);
    });
    request.setTimeout(30_000, () => request.destroy(new Error('下载超时')));
    request.on('error', reject);
  });
}

async function install() {
  if (process.env.V_LOCAL_KEY_PROVIDER_SKIP_BINARY_INSTALL === '1') return;
  const selected = target();
  const base = installationBase();
  const destinationDir = prepareInstallationDirectory(installationDirectory(selected, base), base);
  if (process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH) {
    if (!allowUnverifiedLocalBinary()) {
      throw new Error('V_LOCAL_KEY_PROVIDER_BINARY_PATH 仅允许在同时设置 V_LOCAL_KEY_PROVIDER_DEVELOPMENT=1 和 V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY=1 的隔离开发环境使用');
    }
    const localArtifacts = [{source: process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH, binary: selected.binary}];
    if (selected.helperBinary) {
      localArtifacts.push({
        source: process.env.V_LOCAL_KEY_PROVIDER_HELPER_BINARY_PATH || process.env.V_LOCAL_KEY_PROVIDER_BINARY_PATH,
        binary: selected.helperBinary,
      });
    }
    const replacements = [];
    try {
      for (const artifact of localArtifacts) {
        const destination = path.join(destinationDir, artifact.binary);
        const temporary = reserveSibling(destination, 'tmp', 0o700);
        replacements.push({temporary, destination});
        fs.copyFileSync(path.resolve(artifact.source), temporary);
        fs.chmodSync(temporary, 0o700);
      }
      replaceFiles(replacements);
    } finally {
      for (const replacement of replacements) {
        if (fs.existsSync(replacement.temporary)) fs.rmSync(replacement.temporary, {force: true});
      }
    }
    return path.join(destinationDir, selected.binary);
  }
  const packageInfo = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
  const checksums = parseChecksums(fs.readFileSync(path.join(packageRoot, 'checksums.txt'), 'utf8'));
  const artifacts = [{asset: selected.asset, binary: selected.binary}];
  if (selected.helperAsset && selected.helperBinary) {
    artifacts.push({asset: selected.helperAsset, binary: selected.helperBinary});
  }
  let allCurrent = true;
  for (const artifact of artifacts) {
    artifact.expected = checksums.get(artifact.asset);
    if (!artifact.expected) throw new Error(`发布包缺少 ${artifact.asset} 的 SHA-256`);
    artifact.destination = path.join(destinationDir, artifact.binary);
    if (!fs.existsSync(artifact.destination)) {
      allCurrent = false;
      continue;
    }
    try {
      verifyHash(artifact.destination, artifact.expected);
    } catch (_) {
      allCurrent = false;
    }
  }
  if (allCurrent) return path.join(destinationDir, selected.binary);

  const staged = [];
  try {
    // Provider 与 helper 是一个发行单元：任一成员缺失或不匹配时，先完整验证二者，再一次提交。
    for (const artifact of artifacts) {
      const reservation = reserveSiblingFile(artifact.destination, 'tmp', 0o700);
      const stage = {
        temporary: reservation.path,
        destination: artifact.destination,
        descriptor: reservation.descriptor,
      };
      staged.push(stage);
      const url = releaseUrl(packageInfo.version, artifact.asset);
      try {
        await download(url, stage.temporary, 0, stage.descriptor);
      } finally {
        if (stage.descriptor !== undefined) {
          fs.closeSync(stage.descriptor);
          stage.descriptor = undefined;
        }
      }
      verifyHash(stage.temporary, artifact.expected);
      fs.chmodSync(stage.temporary, 0o700);
    }
    replaceFiles(staged);
  } finally {
    for (const stage of staged) {
      if (stage.descriptor !== undefined) fs.closeSync(stage.descriptor);
      if (fs.existsSync(stage.temporary)) fs.rmSync(stage.temporary, {force: true});
    }
  }
  return path.join(destinationDir, selected.binary);
}

if (require.main === module) {
  install().catch(error => {
    process.stderr.write(`Provider 安装失败：${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  allowUnverifiedLocalBinary, assertDirectDirectory, assertDownloadUrl, download, install, installationBase,
  installationDirectory, installedBinaryPath, parseChecksums, releaseTag, releaseUrl, replaceFile,
  prepareInstallationDirectory, replaceFiles, reserveSibling, sameResolvedPath, target, verifyHash,
};
