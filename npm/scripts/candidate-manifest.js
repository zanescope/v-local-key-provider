#!/usr/bin/env node

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const packageRoot = path.resolve(__dirname, '..');
const packageMetadata = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
const attestationWorkflow = 'zanescope/v-local-key-provider/.github/workflows/release-candidate.yml';

const expectedTargets = Object.freeze([
  { platform: 'windows', architecture: 'amd64', provider_artifact_name: 'v-local-key-provider-windows-amd64.exe' },
  { platform: 'windows', architecture: 'arm64', provider_artifact_name: 'v-local-key-provider-windows-arm64.exe' },
  {
    platform: 'darwin', architecture: 'amd64',
    provider_artifact_name: 'v-local-key-provider-darwin-amd64',
    helper_artifact_name: 'v-local-key-provider-helper-darwin-amd64',
  },
  {
    platform: 'darwin', architecture: 'arm64',
    provider_artifact_name: 'v-local-key-provider-darwin-arm64',
    helper_artifact_name: 'v-local-key-provider-helper-darwin-arm64',
  },
]);

function fail(message) {
  throw new Error(message);
}

function exactKeys(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail('manifest entry must be an object');
  const allowed = new Set([...required, ...optional]);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) fail(`manifest contains unknown field ${key}`);
  }
  for (const key of required) {
    if (!Object.prototype.hasOwnProperty.call(value, key)) fail(`manifest is missing ${key}`);
  }
}

function validDigest(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function validSourceCommit(value) {
  return typeof value === 'string' && (/^[0-9a-f]{40}$/.test(value) || /^[0-9a-f]{64}$/.test(value));
}

function validRunID(value) {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
}

function regularFile(file) {
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink()) fail(`candidate asset is not a regular file: ${file}`);
  return info;
}

function sha256File(file) {
  regularFile(file);
  return crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

function atomicJSON(output, value) {
  const directory = path.dirname(path.resolve(output));
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const temporary = path.join(directory, `.${path.basename(output)}.${process.pid}.${crypto.randomBytes(8).toString('hex')}.tmp`);
  fs.writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  fs.renameSync(temporary, output);
}

function targetKey(value) {
  return `${value.platform}/${value.architecture}`;
}

function validateTarget(value, expected, promotion) {
  const required = ['platform', 'architecture', 'provider_artifact_name', 'provider_sha256'];
  const optional = promotion ? ['helper_artifact_name', 'helper_sha256', 'evidence_sha256'] : ['helper_artifact_name', 'helper_sha256'];
  if (promotion) required.push('evidence_sha256');
  exactKeys(value, required, optional);
  if (value.platform !== expected.platform || value.architecture !== expected.architecture ||
      value.provider_artifact_name !== expected.provider_artifact_name || !validDigest(value.provider_sha256)) {
    fail(`invalid candidate target ${targetKey(expected)}`);
  }
  if (expected.helper_artifact_name) {
    if (value.helper_artifact_name !== expected.helper_artifact_name || !validDigest(value.helper_sha256)) {
      fail(`invalid helper target ${targetKey(expected)}`);
    }
  } else if (value.helper_artifact_name !== undefined || value.helper_sha256 !== undefined) {
    fail(`Windows target ${targetKey(expected)} unexpectedly contains a helper`);
  }
  if (promotion) {
    if (!Array.isArray(value.evidence_sha256) || value.evidence_sha256.length === 0 ||
        new Set(value.evidence_sha256).size !== value.evidence_sha256.length ||
        value.evidence_sha256.some((digest) => !validDigest(digest))) {
      fail(`invalid promotion evidence set for ${targetKey(expected)}`);
    }
  }
}

function validateManifest(value, promotion = false) {
  const common = [
    'schema_version', 'provider_version', 'candidate_source_commit', 'candidate_workflow_run_id',
    'candidate_attestation_workflow', 'targets',
  ];
  exactKeys(value, promotion ? common : [...common, 'build_mode']);
  if (value.schema_version !== 1 || value.provider_version !== packageMetadata.version ||
      !validSourceCommit(value.candidate_source_commit) || !validRunID(value.candidate_workflow_run_id) ||
      value.candidate_attestation_workflow !== attestationWorkflow ||
      (!promotion && value.build_mode !== 'candidate') || !Array.isArray(value.targets) ||
      value.targets.length !== expectedTargets.length) {
    fail('candidate manifest header is invalid');
  }
  const byKey = new Map();
  for (const target of value.targets) {
    const key = targetKey(target);
    if (byKey.has(key)) fail(`duplicate candidate target ${key}`);
    byKey.set(key, target);
  }
  const evidence = new Set();
  for (const expected of expectedTargets) {
    const target = byKey.get(targetKey(expected));
    if (!target) fail(`candidate manifest is missing ${targetKey(expected)}`);
    validateTarget(target, expected, promotion);
    if (promotion) {
      for (const digest of target.evidence_sha256) {
        if (evidence.has(digest)) fail(`evidence digest ${digest} is reused across promotion targets`);
        evidence.add(digest);
      }
    }
  }
  return value;
}

function readJSON(file) {
  regularFile(file);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function createCandidateManifest(distDirectory, output, sourceCommit, runID) {
  if (!validSourceCommit(sourceCommit) || !validRunID(runID)) fail('candidate source commit or workflow run id is invalid');
  const targets = expectedTargets.map((expected) => {
    const target = {
      platform: expected.platform,
      architecture: expected.architecture,
      provider_artifact_name: expected.provider_artifact_name,
      provider_sha256: sha256File(path.join(distDirectory, expected.provider_artifact_name)),
    };
    if (expected.helper_artifact_name) {
      target.helper_artifact_name = expected.helper_artifact_name;
      target.helper_sha256 = sha256File(path.join(distDirectory, expected.helper_artifact_name));
    }
    return target;
  });
  const manifest = validateManifest({
    schema_version: 1,
    provider_version: packageMetadata.version,
    build_mode: 'candidate',
    candidate_source_commit: sourceCommit,
    candidate_workflow_run_id: runID,
    candidate_attestation_workflow: attestationWorkflow,
    targets,
  });
  atomicJSON(output, manifest);
  return manifest;
}

function verifyCandidateManifest(manifestPath, distDirectory, platform, architecture, sourceCommit, runID) {
  const manifest = validateManifest(readJSON(manifestPath));
  if (manifest.candidate_source_commit !== sourceCommit || manifest.candidate_workflow_run_id !== runID) {
    fail('downloaded candidate provenance does not match the selected workflow run and source commit');
  }
  for (const target of manifest.targets) {
    if (sha256File(path.join(distDirectory, target.provider_artifact_name)) !== target.provider_sha256) {
      fail(`candidate Provider digest mismatch for ${targetKey(target)}`);
    }
    if (target.helper_artifact_name && sha256File(path.join(distDirectory, target.helper_artifact_name)) !== target.helper_sha256) {
      fail(`candidate helper digest mismatch for ${targetKey(target)}`);
    }
  }
  const selected = manifest.targets.find((target) => target.platform === platform && target.architecture === architecture);
  if (!selected) fail(`candidate target ${platform}/${architecture} is unavailable`);
  return { manifest, selected };
}

function createPromotion(candidateManifestPath, output, evidencePaths) {
  const candidate = validateManifest(readJSON(candidateManifestPath));
  const evidenceByTarget = new Map(expectedTargets.map((target) => [targetKey(target), []]));
  const seenEvidence = new Set();
  for (const evidencePath of evidencePaths) {
    regularFile(evidencePath);
    const payload = fs.readFileSync(evidencePath);
    const digest = crypto.createHash('sha256').update(payload).digest('hex');
    if (path.basename(evidencePath) !== `${digest}.json`) fail(`evidence file is not content addressed: ${evidencePath}`);
    if (seenEvidence.has(digest)) fail(`evidence file is repeated: ${digest}`);
    seenEvidence.add(digest);
    const evidence = JSON.parse(payload.toString('utf8'));
    const key = `${evidence.runner_os}/${evidence.runner_arch}`;
    const target = candidate.targets.find((entry) => targetKey(entry) === key);
    if (!target || evidence.schema_version !== 1 || evidence.provider_version !== candidate.provider_version ||
        evidence.candidate_source_commit !== candidate.candidate_source_commit ||
        evidence.candidate_workflow_run_id !== candidate.candidate_workflow_run_id ||
        evidence.candidate_attestation_workflow !== candidate.candidate_attestation_workflow ||
        evidence.candidate_attestation_verified !== true || evidence.candidate_artifact_name !== target.provider_artifact_name ||
        evidence.provider_binary_sha256 !== target.provider_sha256 ||
        (evidence.provider_helper_sha256 || '') !== (target.helper_sha256 || '')) {
      fail(`evidence does not match candidate target ${key}`);
    }
    evidenceByTarget.get(key).push(digest);
  }
  const targets = candidate.targets.map((target) => ({
    ...target,
    evidence_sha256: [...new Set(evidenceByTarget.get(targetKey(target)))].sort(),
  }));
  const promotion = validateManifest({
    schema_version: 1,
    provider_version: candidate.provider_version,
    candidate_source_commit: candidate.candidate_source_commit,
    candidate_workflow_run_id: candidate.candidate_workflow_run_id,
    candidate_attestation_workflow: candidate.candidate_attestation_workflow,
    targets,
  }, true);
  atomicJSON(output, promotion);
  return promotion;
}

function promotionMetadata(promotionPath) {
  const promotion = validateManifest(readJSON(promotionPath), true);
  return {
    sourceCommit: promotion.candidate_source_commit,
    runID: promotion.candidate_workflow_run_id,
  };
}

function appendGitHubOutput(values) {
  const output = process.env.GITHUB_OUTPUT;
  if (!output) return;
  const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
  fs.appendFileSync(output, `${lines.join('\n')}\n`, 'utf8');
}

function appendGitHubEnvironment(values) {
  const output = process.env.GITHUB_ENV;
  if (!output) return;
  const lines = Object.entries(values).map(([key, value]) => `${key}=${value}`);
  fs.appendFileSync(output, `${lines.join('\n')}\n`, 'utf8');
}

function main(argv) {
  const [command, ...args] = argv;
  if (command === 'create' && args.length === 4) {
    createCandidateManifest(...args);
    return;
  }
  if (command === 'verify' && args.length === 6) {
    const { manifest, selected } = verifyCandidateManifest(...args);
    const dist = path.resolve(args[1]);
    appendGitHubOutput({
      binary: path.join(dist, selected.provider_artifact_name),
      helper: selected.helper_artifact_name ? path.join(dist, selected.helper_artifact_name) : '',
      candidate_sha256: selected.provider_sha256,
      helper_sha256: selected.helper_sha256 || '',
      source_commit: manifest.candidate_source_commit,
      run_id: manifest.candidate_workflow_run_id,
      artifact_name: selected.provider_artifact_name,
      attestation_workflow: manifest.candidate_attestation_workflow,
    });
    appendGitHubEnvironment({
      V_LOCAL_KEY_PROVIDER_LIVE_BINARY: path.join(dist, selected.provider_artifact_name),
      V_LOCAL_KEY_PROVIDER_LIVE_HELPER_BINARY: selected.helper_artifact_name ? path.join(dist, selected.helper_artifact_name) : '',
      V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_SOURCE_COMMIT: manifest.candidate_source_commit,
      V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_RUN_ID: manifest.candidate_workflow_run_id,
      V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ARTIFACT: selected.provider_artifact_name,
      V_LOCAL_KEY_PROVIDER_LIVE_CANDIDATE_ATTESTATION_WORKFLOW: manifest.candidate_attestation_workflow,
    });
    return;
  }
  if (command === 'promote' && args.length >= 3) {
    createPromotion(args[0], args[1], args.slice(2));
    return;
  }
  if (command === 'promotion-source' && args.length === 1) {
    process.stdout.write(`${promotionMetadata(args[0]).sourceCommit}\n`);
    return;
  }
  if (command === 'promotion-run' && args.length === 1) {
    process.stdout.write(`${promotionMetadata(args[0]).runID}\n`);
    return;
  }
  fail('usage: candidate-manifest.js create <dist> <output> <source-commit> <run-id> | verify <manifest> <dist> <platform> <arch> <source-commit> <run-id> | promote <candidate-manifest> <output> <evidence...> | promotion-source <promotion> | promotion-run <promotion>');
}

module.exports = {
  attestationWorkflow,
  createCandidateManifest,
  createPromotion,
  expectedTargets,
  promotionMetadata,
  sha256File,
  validateManifest,
  verifyCandidateManifest,
};

if (require.main === module) {
  try {
    main(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
