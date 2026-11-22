// Deploys the legatto-forms Worker from the signed release bundle to the
// office's own Cloudflare account (Workers Versions + Deployments API),
// verifies it through https://<site>/api/health and rolls back to the
// previous version when the new one is not healthy.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { CfApi, CfApiError, type Transport } from './http';

export const SECRET_NAMES = ['TURNSTILE_SECRET', 'IP_HASH_KEY', 'SIGNING_KEY'] as const;
export const VAR_NAMES = [
  'OFFICE_X25519_PUB',
  'OFFICE_KID',
  'SELFTEST_ED25519_PUB',
  'SITE_ORIGIN',
  'TURNSTILE_HOSTNAMES',
  'TURNSTILE_ACTION',
  'RELEASE',
] as const;

export interface RateLimitSpec {
  namespace_id: string;
  limit: number;
  period: 10 | 60;
}

/** /cfg/deploy.json, rendered by legatto-worker-deploy on the host (no secrets). */
export interface DeployConfig {
  account_id: string;
  zone_id: string;
  site_host: string;
  script_name: string;
  queue_name: string;
  compatibility_date: string;
  entry: string;
  entry_sha256: string;
  release: string;
  ratelimits: Record<'RL_IP' | 'RL_GLOBAL' | 'RL_SELFTEST', RateLimitSpec>;
  vars: Record<(typeof VAR_NAMES)[number], string>;
  expected_signer_kid: string;
  health_timeout_seconds: number;
}

export type WorkerSecrets = Record<(typeof SECRET_NAMES)[number], string>;

interface DeploymentVersion {
  version_id: string;
  percentage: number;
}

interface Deployment {
  id: string;
  versions: DeploymentVersion[];
}

export interface DeployResult {
  ok: boolean;
  version_id: string | null;
  previous_versions: DeploymentVersion[];
  rolled_back: boolean;
  health: HealthReport | null;
  error?: string;
}

export interface HealthReport {
  ok: boolean;
  release: string | null;
  office_kid: string | null;
  signer_kid: string | null;
  selftest_kid: string | null;
}

const NAME_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const ID_RE = /^[0-9a-f]{32}$/;

export function validateDeployConfig(raw: unknown): DeployConfig {
  if (typeof raw !== 'object' || raw === null) throw new Error('deploy config must be an object');
  const c = raw as DeployConfig;
  if (!ID_RE.test(c.account_id ?? '') || !ID_RE.test(c.zone_id ?? '')) throw new Error('account_id/zone_id must be 32 hex');
  if (!NAME_RE.test(c.script_name ?? '') || !NAME_RE.test(c.queue_name ?? '')) throw new Error('script_name/queue_name invalid');
  if (!/^[a-z0-9.-]+$/.test(c.site_host ?? '')) throw new Error('site_host invalid');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(c.compatibility_date ?? '')) throw new Error('compatibility_date invalid');
  if (!/^[a-z0-9][a-z0-9._-]*\.js$/.test(c.entry ?? '')) throw new Error('entry invalid');
  if (!/^[0-9a-f]{64}$/.test(c.entry_sha256 ?? '')) throw new Error('entry_sha256 invalid');
  if (!/^[0-9a-f]{16}$/.test(c.expected_signer_kid ?? '')) throw new Error('expected_signer_kid invalid');
  for (const name of VAR_NAMES) if (typeof c.vars?.[name] !== 'string') throw new Error(`vars.${name} missing`);
  if (c.vars.RELEASE !== c.release) throw new Error('vars.RELEASE must equal release');
  for (const name of ['RL_IP', 'RL_GLOBAL', 'RL_SELFTEST'] as const) {
    const rl = c.ratelimits?.[name];
    if (!rl || !/^[0-9]{1,10}$/.test(rl.namespace_id) || !(rl.period === 10 || rl.period === 60) || !(rl.limit >= 1)) {
      throw new Error(`ratelimits.${name} invalid`);
    }
  }
  if (!(c.health_timeout_seconds >= 10 && c.health_timeout_seconds <= 600)) throw new Error('health_timeout_seconds out of range');
  return c;
}

export function validateSecrets(raw: unknown): WorkerSecrets {
  if (typeof raw !== 'object' || raw === null) throw new Error('secrets must be an object');
  const s = raw as WorkerSecrets;
  for (const name of SECRET_NAMES) if (typeof s[name] !== 'string' || s[name] === '') throw new Error(`secret ${name} missing`);
  return s;
}

function bindings(config: DeployConfig, secrets: WorkerSecrets | null): unknown[] {
  const out: unknown[] = VAR_NAMES.map((name) => ({ type: 'plain_text', name, text: config.vars[name] }));
  out.push({ type: 'queue', name: 'FORMS', queue_name: config.queue_name });
  for (const [name, rl] of Object.entries(config.ratelimits)) {
    out.push({ type: 'ratelimit', name, namespace_id: rl.namespace_id, simple: { limit: rl.limit, period: rl.period } });
  }
  if (secrets) for (const name of SECRET_NAMES) out.push({ type: 'secret_text', name, text: secrets[name] });
  return out;
}

function uploadForm(config: DeployConfig, script: Buffer, secrets: WorkerSecrets | null, message: string): FormData {
  const metadata = {
    main_module: config.entry,
    compatibility_date: config.compatibility_date,
    bindings: bindings(config, secrets),
    // Without new secrets the existing ones are kept; vars are always replaced.
    ...(secrets ? {} : { keep_bindings: ['secret_text'] }),
    logpush: false,
    observability: { enabled: false },
    annotations: { 'workers/message': message, 'workers/tag': config.entry_sha256.slice(0, 16) },
  };
  const form = new FormData();
  form.set('metadata', JSON.stringify(metadata));
  form.set(config.entry, new File([new Uint8Array(script)], config.entry, { type: 'application/javascript+module' }));
  return form;
}

type ScriptRef = Pick<DeployConfig, 'account_id' | 'script_name'>;

/** Active deployment of the script, or null when the script does not exist. */
export async function currentDeployment(api: CfApi, config: ScriptRef): Promise<Deployment | null> {
  try {
    const result = await api.call<{ deployments: Deployment[] }>('GET', `/accounts/${config.account_id}/workers/scripts/${config.script_name}/deployments`);
    return result.deployments[0] ?? null;
  } catch (err) {
    if (err instanceof CfApiError && err.status === 404) return null;
    throw err;
  }
}

async function deployVersions(api: CfApi, config: ScriptRef, versions: DeploymentVersion[], message: string): Promise<void> {
  await api.call('POST', `/accounts/${config.account_id}/workers/scripts/${config.script_name}/deployments`, {
    json: { strategy: 'percentage', versions, annotations: { 'workers/message': message } },
  });
}

/** Route <site>/api/* -> script, workers.dev and preview URLs off, no logs. */
async function ensureSurface(api: CfApi, config: DeployConfig): Promise<void> {
  const base = `/accounts/${config.account_id}/workers/scripts/${config.script_name}`;
  await api.call('POST', `${base}/subdomain`, { json: { enabled: false, previews_enabled: false } });
  await api.call('PATCH', `${base}/script-settings`, { json: { logpush: false, observability: { enabled: false } } });
  const pattern = `${config.site_host}/api/*`;
  const routes = await api.call<{ id: string; pattern: string; script?: string }[]>('GET', `/zones/${config.zone_id}/workers/routes`);
  const route = routes.find((r) => r.pattern === pattern);
  if (!route) {
    await api.call('POST', `/zones/${config.zone_id}/workers/routes`, { json: { pattern, script: config.script_name } });
  } else if (route.script !== config.script_name) {
    await api.call('PUT', `/zones/${config.zone_id}/workers/routes/${route.id}`, { json: { pattern, script: config.script_name } });
  }
}

export async function checkHealth(transport: Transport, config: DeployConfig): Promise<HealthReport> {
  const empty: HealthReport = { ok: false, release: null, office_kid: null, signer_kid: null, selftest_kid: null };
  try {
    const res = await transport.request(`https://${config.site_host}/api/health`, {
      method: 'GET',
      headers: { Accept: 'application/json', 'Cache-Control': 'no-cache' },
      timeoutMs: 15_000,
    });
    if (res.status !== 200) return empty;
    const body = JSON.parse(res.body.toString('utf8')) as Partial<Record<keyof HealthReport, unknown>>;
    const report: HealthReport = {
      ok: false,
      release: typeof body.release === 'string' ? body.release : null,
      office_kid: typeof body.office_kid === 'string' ? body.office_kid : null,
      signer_kid: typeof body.signer_kid === 'string' ? body.signer_kid : null,
      selftest_kid: typeof body.selftest_kid === 'string' ? body.selftest_kid : null,
    };
    report.ok =
      report.release === config.release &&
      report.office_kid === config.vars.OFFICE_KID &&
      report.signer_kid === config.expected_signer_kid;
    return report;
  } catch {
    return empty;
  }
}

export interface DeployDeps {
  api: CfApi;
  transport: Transport;
  sleep: (ms: number) => Promise<void>;
  now: () => number;
}

export async function deployWorker(deps: DeployDeps, config: DeployConfig, bundleDir: string, secrets: WorkerSecrets | null): Promise<DeployResult> {
  const script = readFileSync(join(bundleDir, config.entry));
  const digest = createHash('sha256').update(script).digest('hex');
  if (digest !== config.entry_sha256) throw new Error(`entry sha256 ${digest} does not match the manifest`);
  const message = `legatto ${config.release} ${config.entry_sha256.slice(0, 16)}`;
  const previous = await currentDeployment(deps.api, config);
  const base = `/accounts/${config.account_id}/workers/scripts/${config.script_name}`;

  let versionId: string;
  if (previous === null) {
    // First deployment: the script does not exist yet, so it is created with
    // its secrets in one upload (the Versions API needs an existing script).
    if (!secrets) throw new Error('first deployment needs the Worker secrets (run cf_bootstrap)');
    await deps.api.call('PUT', base, { form: uploadForm(config, script, secrets, message) });
    const created = await currentDeployment(deps.api, config);
    const top = created?.versions.find((v) => v.percentage === 100);
    if (!top) throw new Error('script uploaded but no deployment reported');
    versionId = top.version_id;
  } else {
    const version = await deps.api.call<{ id: string }>('POST', `${base}/versions?bindings_inherit=strict`, {
      form: uploadForm(config, script, secrets, message),
    });
    versionId = version.id;
    await deployVersions(deps.api, config, [{ version_id: versionId, percentage: 100 }], message);
  }
  await ensureSurface(deps.api, config);

  const deadline = deps.now() + config.health_timeout_seconds * 1000;
  let health = await checkHealth(deps.transport, config);
  while (!health.ok && deps.now() < deadline) {
    await deps.sleep(5_000);
    health = await checkHealth(deps.transport, config);
  }
  if (health.ok) return { ok: true, version_id: versionId, previous_versions: previous?.versions ?? [], rolled_back: false, health };

  if (previous && previous.versions.length > 0) {
    await deployVersions(deps.api, config, previous.versions, `rollback: ${message} unhealthy`);
    return { ok: false, version_id: versionId, previous_versions: previous.versions, rolled_back: true, health, error: 'unhealthy' };
  }
  return { ok: false, version_id: versionId, previous_versions: [], rolled_back: false, health, error: 'unhealthy, no previous version' };
}

export async function rollbackWorker(api: CfApi, config: ScriptRef, versions: DeploymentVersion[], reason: string): Promise<void> {
  if (versions.length === 0) throw new Error('no versions to roll back to');
  await deployVersions(api, config, versions, `rollback: ${reason}`);
}
