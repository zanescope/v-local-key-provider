#!/usr/bin/env node

'use strict';

const fs = require('fs');
const path = require('path');
const {spawnSync} = require('child_process');
const installer = require('./install.js');

async function main() {
  const packageRoot = path.resolve(__dirname, '..');
  if (process.argv[2] === 'install') {
    const packageInfo = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
    const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    const result = spawnSync(npm, [
      'install', '--global', `${packageInfo.name}@${packageInfo.version}`,
    ], {stdio: 'inherit', windowsHide: true});
    if (result.error) throw result.error;
    process.exitCode = result.status === null ? 1 : result.status;
    return;
  }
  const selected = installer.target();
  const binary = path.join(packageRoot, 'bin', `${selected.platform}-${selected.arch}`, selected.binary);
  if (!fs.existsSync(binary)) await installer.install();
  const result = spawnSync(binary, process.argv.slice(2), {
    stdio: 'inherit', windowsHide: true,
  });
  if (result.error) throw result.error;
  process.exitCode = result.status === null ? 1 : result.status;
}

main().catch(error => {
  process.stderr.write(`Provider 启动失败：${error.message}\n`);
  process.exitCode = 1;
});
