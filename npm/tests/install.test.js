'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');
const {EventEmitter} = require('events');
const {PassThrough} = require('stream');

const installer = require('../scripts/install.js');

test('npm dual-use 声明随发布包持久存在', () => {
  const metadata = require('../package.json');
  assert.strictEqual(metadata.contentPolicy.class, 'dual-use');
  assert.ok(metadata.files.includes('DISCLOSURE'));
  assert.match(fs.readFileSync(path.resolve(__dirname, '..', 'DISCLOSURE'), 'utf8'), /explicit user authorization/i);
});

test('首发目标只覆盖 Windows amd64 与 macOS 双架构', () => {
  assert.deepStrictEqual(installer.target('win32', 'x64'), {
    platform: 'windows', arch: 'amd64',
    asset: 'v-local-key-provider-windows-amd64.exe',
    binary: 'v-local-key-provider.exe',
    helperAsset: null, helperBinary: null,
  });
  assert.deepStrictEqual(installer.target('darwin', 'arm64'), {
    platform: 'darwin', arch: 'arm64',
    asset: 'v-local-key-provider-darwin-arm64',
    binary: 'v-local-key-provider',
    helperAsset: 'v-local-key-provider-helper-darwin-arm64',
    helperBinary: 'v-local-key-provider-helper',
  });
  assert.deepStrictEqual(installer.target('darwin', 'x64'), {
    platform: 'darwin', arch: 'amd64',
    asset: 'v-local-key-provider-darwin-amd64',
    binary: 'v-local-key-provider',
    helperAsset: 'v-local-key-provider-helper-darwin-amd64',
    helperBinary: 'v-local-key-provider-helper',
  });
  assert.throws(() => installer.target('linux', 'x64'));
  assert.throws(() => installer.target('win32', 'arm64'));
  assert.throws(() => installer.target('darwin', 'ia32'));
});

test('校验和格式和文件摘要均被验证', () => {
  const digest = 'a'.repeat(64);
  const values = installer.parseChecksums(`${digest}  provider.exe\n`);
  assert.strictEqual(values.get('provider.exe'), digest);
  assert.throws(() => installer.parseChecksums('invalid'));
  assert.throws(() => installer.parseChecksums(`${digest}  ../provider.exe\n`));
  assert.throws(() => installer.parseChecksums(`${digest}  ..\\provider.exe\n`));
  assert.throws(() => installer.parseChecksums(`${digest}  provider.exe\n${'b'.repeat(64)}  provider.exe\n`));

  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v-local-key-provider-npm-'));
  const file = path.join(directory, 'provider');
  try {
    fs.writeFileSync(file, 'provider');
    const expected = crypto.createHash('sha256').update('provider').digest('hex');
    installer.verifyHash(file, expected);
    assert.throws(() => installer.verifyHash(file, '0'.repeat(64)));
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('下载地址限制在 GitHub 发布域名', () => {
  assert.doesNotThrow(() => installer.assertDownloadUrl(
    'https://github.com/zanescope/v-local-key-provider/releases/download/v1/a',
  ));
  assert.throws(() => installer.assertDownloadUrl('https://example.com/a'));
  assert.throws(() => installer.assertDownloadUrl('http://github.com/a'));
  assert.throws(() => installer.assertDownloadUrl('https://user@github.com/a'));
  assert.throws(() => installer.assertDownloadUrl('https://github.com:8443/a'));
});

test('本地未验证二进制必须由开发者二次显式授权', () => {
  assert.strictEqual(installer.allowUnverifiedLocalBinary({}), false);
  assert.strictEqual(installer.allowUnverifiedLocalBinary({V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY: '0'}), false);
  assert.strictEqual(installer.allowUnverifiedLocalBinary({V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY: '1'}), false);
  assert.strictEqual(installer.allowUnverifiedLocalBinary({
    V_LOCAL_KEY_PROVIDER_BINARY_PATH: 'provider-under-test',
    V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY: '1',
  }), false);
  assert.strictEqual(installer.allowUnverifiedLocalBinary({
    V_LOCAL_KEY_PROVIDER_BINARY_PATH: 'provider-under-test',
    V_LOCAL_KEY_PROVIDER_DEVELOPMENT: '1',
    V_LOCAL_KEY_PROVIDER_ALLOW_UNVERIFIED_LOCAL_BINARY: '1',
  }), true);
});

test('下载重定向保留已独占打开的目标描述符', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v-local-key-provider-npm-'));
  const destination = path.join(directory, 'provider.tmp');
  const descriptor = fs.openSync(destination, 'wx', 0o700);
  const requests = [];
  const requester = (url, _options, callback) => {
    requests.push(url.toString());
    const request = new EventEmitter();
    request.setTimeout = () => request;
    request.destroy = error => request.emit('error', error);
    process.nextTick(() => {
      const response = new PassThrough();
      if (requests.length === 1) {
        response.statusCode = 302;
        response.headers = {location: 'https://release-assets.githubusercontent.com/provider'};
        callback(response);
        response.end();
        return;
      }
      response.statusCode = 200;
      response.headers = {'content-length': '8'};
      callback(response);
      response.end('provider');
    });
    return request;
  };
  try {
    await installer.download(
      'https://github.com/zanescope/v-local-key-provider/releases/download/v1/provider',
      destination, 0, descriptor, requester,
    );
    assert.strictEqual(fs.readFileSync(destination, 'utf8'), 'provider');
    assert.strictEqual(requests.length, 2);
  } finally {
    fs.closeSync(descriptor);
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('正式安装目录固定在当前用户私有配置树且按架构隔离', () => {
  const windows = installer.target('win32', 'x64');
  assert.strictEqual(
    installer.installationDirectory(windows, 'C:\\Users\\tester\\AppData\\Local'),
    path.resolve('C:\\Users\\tester\\AppData\\Local', 'v-local', 'key-provider', 'windows-amd64'),
  );
  const darwin = installer.target('darwin', 'x64');
  assert.strictEqual(
    installer.installedBinaryPath(darwin, '/Users/tester/Library/Application Support'),
    path.resolve('/Users/tester/Library/Application Support', 'v-local', 'key-provider', 'darwin-amd64', 'v-local-key-provider'),
  );
});

test('固定安装目录逐层创建并拒绝符号链接或目录联接祖先', () => {
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'v-local-key-provider-install-root-'));
  const base = path.join(root, 'base');
  const direct = path.join(base, 'v-local', 'key-provider', 'test-arch');
  const external = path.join(root, 'external');
  const linked = path.join(base, 'linked', 'key-provider', 'test-arch');
  try {
    fs.mkdirSync(base, {mode: 0o700});
    fs.mkdirSync(external, {mode: 0o700});
    assert.strictEqual(installer.prepareInstallationDirectory(direct, base), path.resolve(direct));
    assert.strictEqual(fs.lstatSync(direct).isDirectory(), true);
    fs.symlinkSync(external, path.join(base, 'linked'), process.platform === 'win32' ? 'junction' : 'dir');
    assert.throws(
      () => installer.prepareInstallationDirectory(linked, base),
      /符号链接|目录联接/,
    );
  } finally {
    fs.rmSync(root, {recursive: true, force: true});
  }
});

test('安装临时文件随机独占且原子替换不覆盖可预测用户文件', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v-local-key-provider-npm-'));
  const destination = path.join(directory, 'provider');
  const predictable = `${destination}.${process.pid}.tmp`;
  try {
    fs.writeFileSync(destination, 'old');
    fs.writeFileSync(predictable, 'user-owned');
    const first = installer.reserveSibling(destination, 'tmp', 0o700);
    const second = installer.reserveSibling(destination, 'tmp', 0o700);
    assert.notStrictEqual(first, second);
    assert.notStrictEqual(first, predictable);
    fs.writeFileSync(first, 'new');
    fs.rmSync(second);
    installer.replaceFile(first, destination);
    assert.strictEqual(fs.readFileSync(destination, 'utf8'), 'new');
    assert.strictEqual(fs.readFileSync(predictable, 'utf8'), 'user-owned');
    assert.deepStrictEqual(fs.readdirSync(directory).filter(name => name.startsWith('.v-local-key-provider-')), []);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('Provider/helper 集合提交失败时完整回滚', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'v-local-key-provider-npm-'));
  const provider = path.join(directory, 'provider');
  const helper = path.join(directory, 'helper');
  const providerTemporary = path.join(directory, 'provider.tmp');
  const helperTemporary = path.join(directory, 'helper.tmp');
  try {
    fs.writeFileSync(provider, 'old-provider');
    fs.writeFileSync(helper, 'old-helper');
    fs.writeFileSync(providerTemporary, 'new-provider');
    fs.writeFileSync(helperTemporary, 'new-helper');
    let renameCount = 0;
    const filesystem = new Proxy(fs, {
      get(target, property) {
        if (property === 'renameSync') {
          return (source, destination) => {
            renameCount += 1;
            if (renameCount === 4) throw new Error('simulated second-member commit failure');
            return target.renameSync(source, destination);
          };
        }
        const value = target[property];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    assert.throws(() => installer.replaceFiles([
      {temporary: providerTemporary, destination: provider},
      {temporary: helperTemporary, destination: helper},
    ], filesystem), /simulated second-member commit failure/);
    assert.strictEqual(fs.readFileSync(provider, 'utf8'), 'old-provider');
    assert.strictEqual(fs.readFileSync(helper, 'utf8'), 'old-helper');
    assert.strictEqual(fs.readFileSync(providerTemporary, 'utf8'), 'new-provider');
    assert.strictEqual(fs.readFileSync(helperTemporary, 'utf8'), 'new-helper');
    assert.deepStrictEqual(fs.readdirSync(directory).filter(name => name.startsWith('.v-local-key-provider-')), []);
  } finally {
    fs.rmSync(directory, {recursive: true, force: true});
  }
});

test('预发布 npm 版本下载同版本 GitHub Release', () => {
  assert.strictEqual(installer.releaseTag('0.1.0-dev.0'), 'v0.1.0-dev.0');
  assert.strictEqual(
    installer.releaseUrl('0.1.0-dev.0', 'provider.exe'),
    'https://github.com/zanescope/v-local-key-provider/releases/download/v0.1.0-dev.0/provider.exe',
  );
  assert.throws(() => installer.releaseTag('latest'));
});
