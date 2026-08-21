'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const installer = require('../scripts/install.js');

test('npm dual-use 声明随发布包持久存在', () => {
  const metadata = require('../package.json');
  assert.strictEqual(metadata.contentPolicy.class, 'dual-use');
  assert.ok(metadata.files.includes('DISCLOSURE'));
  assert.match(fs.readFileSync(path.resolve(__dirname, '..', 'DISCLOSURE'), 'utf8'), /explicit user authorization/i);
});

test('发布目标覆盖 Windows amd64 与 macOS 双架构', () => {
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
  assert.throws(() => installer.target('darwin', 'ia32'));
});

test('校验和格式和文件摘要均被验证', () => {
  const digest = 'a'.repeat(64);
  const values = installer.parseChecksums(`${digest}  provider.exe\n`);
  assert.strictEqual(values.get('provider.exe'), digest);
  assert.throws(() => installer.parseChecksums('invalid'));

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
});

test('预发布 npm 版本下载同版本 GitHub Release', () => {
  assert.strictEqual(installer.releaseTag('0.1.0-dev.0'), 'v0.1.0-dev.0');
  assert.strictEqual(
    installer.releaseUrl('0.1.0-dev.0', 'provider.exe'),
    'https://github.com/zanescope/v-local-key-provider/releases/download/v0.1.0-dev.0/provider.exe',
  );
  assert.throws(() => installer.releaseTag('latest'));
});
