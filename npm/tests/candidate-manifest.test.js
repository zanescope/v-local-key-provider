'use strict';

const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const candidate = require('../scripts/candidate-manifest.js');
const metadata = require('../package.json');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'provider-candidate-manifest-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const dist = path.join(root, 'dist');
  fs.mkdirSync(dist);
  for (const target of candidate.expectedTargets) {
    fs.writeFileSync(path.join(dist, target.provider_artifact_name), `provider:${target.platform}/${target.architecture}`);
    if (target.helper_artifact_name) {
      fs.writeFileSync(path.join(dist, target.helper_artifact_name), `helper:${target.platform}/${target.architecture}`);
    }
  }
  return { root, dist };
}

function contentAddressedEvidence(root, value) {
  const payload = Buffer.from(JSON.stringify(value));
  const digest = crypto.createHash('sha256').update(payload).digest('hex');
  const output = path.join(root, `${digest}.json`);
  fs.writeFileSync(output, payload);
  return output;
}

test('候选清单精确绑定四个平台资产、来源提交和工作流运行', (t) => {
  const { root, dist } = fixture(t);
  const source = 'a'.repeat(40);
  const manifestPath = path.join(dist, 'candidate-manifest.json');
  const manifest = candidate.createCandidateManifest(dist, manifestPath, source, '12345');
  assert.equal(manifest.targets.length, 4);
  const verified = candidate.verifyCandidateManifest(manifestPath, dist, 'darwin', 'arm64', source, '12345');
  assert.equal(verified.selected.helper_artifact_name, 'v-local-key-provider-helper-darwin-arm64');

  fs.appendFileSync(path.join(dist, verified.selected.provider_artifact_name), 'tampered');
  assert.throws(
    () => candidate.verifyCandidateManifest(manifestPath, dist, 'darwin', 'arm64', source, '12345'),
    /digest mismatch/,
  );
});

test('promotion 清单只接受同一 attested 候选集合的内容寻址证据', (t) => {
  const { root, dist } = fixture(t);
  const source = 'b'.repeat(40);
  const manifestPath = path.join(dist, 'candidate-manifest.json');
  const manifest = candidate.createCandidateManifest(dist, manifestPath, source, '98765');
  const evidencePaths = manifest.targets.map((target) => contentAddressedEvidence(root, {
    schema_version: 2,
    provider_version: metadata.version,
    candidate_source_commit: source,
    candidate_workflow_run_id: '98765',
    candidate_attestation_workflow: candidate.attestationWorkflow,
    candidate_attestation_verified: true,
    candidate_artifact_name: target.provider_artifact_name,
    provider_binary_sha256: target.provider_sha256,
    provider_helper_sha256: target.helper_sha256 || '',
    runner_os: target.platform,
    runner_arch: target.architecture,
  }));
  const promotionPath = path.join(root, 'promotions', 'v-test.json');
  const promotion = candidate.createPromotion(manifestPath, promotionPath, evidencePaths);
  assert.equal(promotion.targets.length, 4);
  assert.ok(promotion.targets.every((target) => target.evidence_sha256.length === 1));
  candidate.validateManifest(JSON.parse(fs.readFileSync(promotionPath, 'utf8')), true);
  assert.deepEqual(candidate.promotionMetadata(promotionPath), { sourceCommit: source, runID: '98765' });
  assert.throws(
    () => candidate.createPromotion(manifestPath, promotionPath, [...evidencePaths, evidencePaths[0]]),
    /evidence file is repeated/,
  );

  const mismatched = JSON.parse(fs.readFileSync(evidencePaths[0], 'utf8'));
  mismatched.candidate_workflow_run_id = '11111';
  const mismatchedPath = contentAddressedEvidence(root, mismatched);
  assert.throws(
    () => candidate.createPromotion(manifestPath, promotionPath, [mismatchedPath, ...evidencePaths.slice(1)]),
    /does not match candidate/,
  );
});
