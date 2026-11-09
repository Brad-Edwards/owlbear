import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import test from 'node:test';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
assert.ok(process.env.YAML_PACKAGE_ROOT, 'Set YAML_PACKAGE_ROOT to the public js-yaml package directory');
const require = createRequire(resolve(process.env.YAML_PACKAGE_ROOT, 'package.json'));
const { load } = require('js-yaml');
const read = (path) => readFileSync(resolve(root, path), 'utf8');
const configText = read('.ground-control.yaml');
const config = load(configText);
const workflowText = read('.github/workflows/ground-control-phase-e.yml');
const workflow = load(workflowText);
const job = workflow.jobs.finalize;

test('Owlbear uses its schema 1 configuration format', () => {
  assert.equal(config.schema_version, 1);
  assert.equal(config.github_repo, 'Brad-Edwards/owlbear');
  assert.equal(config.project, 'owlbear');
  assert.equal(config.workflow.base_branch, 'dev');
  assert.ok(!Object.hasOwn(config.workflow, 'design'));
  assert.ok(!Object.hasOwn(config.architecture, 'modules'));
  assert.ok(config.architecture.vocabulary);
  assert.ok(existsSync(resolve(root, config.docs.workflow_reference)));
});

test('Phase E handles merged delivery branches and maintainer repair only', () => {
  assert.deepEqual([...workflow.on.pull_request.branches].sort(), ['dev', 'main']);
  assert.deepEqual(Object.keys(workflow.on).sort(), ['pull_request', 'workflow_dispatch']);
  assert.deepEqual(workflow.on.pull_request.types, ['closed']);
  assert.equal(workflow.on.workflow_dispatch.inputs.pr.required, true);
  assert.equal(job.if, "${{ github.event.pull_request.merged == true || (github.event_name == 'workflow_dispatch' && (github.ref == 'refs/heads/main' || github.ref == 'refs/heads/dev')) }}");
  assert.equal(job.environment, 'ground-control');
  assert.equal(workflow.concurrency['cancel-in-progress'], false);
  for (const field of ['run-name', 'concurrency']) {
    const value = field === 'concurrency' ? workflow[field].group : workflow[field];
    assert.ok(value.includes('github.event.pull_request.number') && value.includes('inputs.pr'));
  }
});

test('Phase E grants only issue writes and checks out the merge revision', () => {
  assert.deepEqual(workflow.permissions, { contents: 'read', 'pull-requests': 'read', actions: 'read', issues: 'write' });
  assert.ok(!Object.hasOwn(job, 'permissions'));
  const checkout = job.steps.find((step) => step.uses?.startsWith('actions/checkout@'));
  assert.equal(checkout.with.ref, '${{ github.event.pull_request.merge_commit_sha || github.sha }}');
  assert.equal(checkout.with['persist-credentials'], false);
  assert.equal(checkout.with['fetch-depth'], 0);
  assert.ok(!/pull_request\.head\.(sha|ref)/.test(workflowText));
  for (const step of job.steps.filter((step) => step.uses)) assert.match(step.uses, /@[a-f0-9]{40}$/);
});

test('the private release is pinned and verified before installation without scripts', () => {
  const download = job.steps.find((step) => step.name === 'Download the pinned Ground Control release');
  const install = job.steps.find((step) => step.name === 'Install the verified Ground Control release');
  assert.ok(download.run.includes('gh release download v1.10.0 --repo autarchy-ai/Ground-Control'));
  assert.ok(download.run.includes('--pattern grndctl-1.10.0.tgz'));
  assert.ok(download.run.includes('if [ -z "$GH_TOKEN" ]'));
  assert.match(download.run, /[a-f0-9]{64} .*\| sha256sum --check/);
  assert.ok(install.run.includes('npm install --global --ignore-scripts --no-audit --no-fund'));
  assert.equal(install.env, undefined);
  assert.ok(job.steps.indexOf(download) < job.steps.indexOf(install));
});

test('pull-request CI uses only the public parser without release credentials', () => {
  const ci = load(read('.github/workflows/ci.yml'));
  const check = ci.jobs['ground-control'];
  assert.ok(JSON.stringify(check).includes('js-yaml@4.3.2'));
  assert.ok(!/secrets\.|Ground-Control|grndctl-/.test(JSON.stringify(check)));
  assert.equal(require('js-yaml/package.json').version, '4.3.2');
});

test('the finalizer and download use separate explicit token bindings', () => {
  const final = job.steps.at(-1);
  assert.equal(final.run, 'grndctl finalize-merged-pr --pr "$PR"');
  assert.deepEqual(final.env, { GH_TOKEN: '${{ github.token }}', PR: '${{ github.event.pull_request.number || inputs.pr }}' });
  const download = job.steps.find((step) => step.name === 'Download the pinned Ground Control release');
  assert.deepEqual(download.env, { GH_TOKEN: '${{ secrets.GROUND_CONTROL_RELEASE_TOKEN }}' });
  for (const step of job.steps.slice(0, -1).filter((step) => step !== download)) assert.equal(step.env, undefined);
  assert.ok(!Object.hasOwn(workflow, 'env'));
  assert.ok(!Object.hasOwn(job, 'env'));
  assert.ok(!/gh issue close|pull_request_target|\.\/scripts\//.test(workflowText));
});
