import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CfApi, createTransport } from '../../tools/http';
import { collectSite, deployPages, hashAsset } from '../../tools/pages';
import { type DeployConfig, deployWorker, validateDeployConfig } from '../../tools/worker';
import { type Recorded, type TestProxy, type TestServer, cfError, cfOk, createPki, multipart, startHttps, startProxy } from './harness';

const API = 'https://api.cloudflare.com/client/v4';
const ACCOUNT = 'a'.repeat(32);
const ZONE = 'b'.repeat(32);
const SITE = 'posel-test.pl';
const TOKEN = 'test-pages-token-value';
const SECRETS = { TURNSTILE_SECRET: 'ts-secret', IP_HASH_KEY: 'aXA=', SIGNING_KEY: 'c2s=' };

/** In-memory Cloudflare account: Workers scripts, versions, deployments, routes, Pages. */
class FakeCloudflare {
  scriptExists = false;
  versions = new Map<string, { release: string; metadata: Record<string, unknown> }>();
  deployed: { version_id: string; percentage: number }[] = [];
  routes: { id: string; pattern: string; script: string }[] = [];
  unhealthyReleases = new Set<string>();
  pagesAssets = new Set<string>();
  pagesDeployments: Recorded[] = [];
  private seq = 0;

  private newVersion(metadata: Record<string, unknown>): string {
    this.seq += 1;
    const id = this.seq.toString(16).padStart(32, '0');
    const bindings = metadata.bindings as { name: string; text?: string }[];
    this.versions.set(id, { release: bindings.find((b) => b.name === 'RELEASE')?.text ?? '', metadata });
    return id;
  }

  handle = (req: Recorded): { status: number; body: unknown } => {
    if (req.host.startsWith(SITE)) {
      if (req.path !== '/api/health') return { status: 404, body: { error: 'not_found' } };
      const live = this.deployed.find((d) => d.percentage === 100);
      const release = live ? this.versions.get(live.version_id)?.release : undefined;
      if (!release || this.unhealthyReleases.has(release)) return { status: 503, body: { error: 'misconfigured' } };
      return { status: 200, body: { v: 1, release, office_kid: '0123456789abcdef', signer_kid: 'fedcba9876543210', selftest_kid: '1111111111111111' } };
    }
    if (req.headers.authorization !== `Bearer ${TOKEN}` && !req.path.startsWith('/client/v4/pages/assets/')) {
      return cfError(403, 10000, 'Authentication error');
    }
    const path = req.path.replace('/client/v4', '');
    const script = `/accounts/${ACCOUNT}/workers/scripts/legatto-forms`;
    if (req.method === 'GET' && path === `${script}/deployments`) {
      if (!this.scriptExists) return cfError(404, 10007, 'This Worker does not exist on your account.');
      return cfOk({ deployments: [{ id: `dep-${this.seq}`, versions: this.deployed }] });
    }
    if (req.method === 'PUT' && path === script) {
      const metadata = JSON.parse(multipart(req).metadata) as Record<string, unknown>;
      this.scriptExists = true;
      const id = this.newVersion(metadata);
      this.deployed = [{ version_id: id, percentage: 100 }];
      return cfOk({ id: 'legatto-forms' });
    }
    if (req.method === 'POST' && path === `${script}/versions?bindings_inherit=strict`) {
      return cfOk({ id: this.newVersion(JSON.parse(multipart(req).metadata) as Record<string, unknown>) });
    }
    if (req.method === 'POST' && path === `${script}/deployments`) {
      const request: { versions: { version_id: string; percentage: number }[] } = JSON.parse(req.body.toString());
      this.deployed = request.versions;
      return cfOk({ id: 'dep' });
    }
    if (req.method === 'POST' && path === `${script}/subdomain`) return cfOk({ enabled: false });
    if (req.method === 'PATCH' && path === `${script}/script-settings`) return cfOk({});
    if (req.method === 'GET' && path === `/zones/${ZONE}/workers/routes`) return cfOk(this.routes);
    if (req.method === 'POST' && path === `/zones/${ZONE}/workers/routes`) {
      const body = JSON.parse(req.body.toString()) as { pattern: string; script: string };
      this.routes.push({ id: `r${this.routes.length}`, ...body });
      return cfOk({ id: 'r' });
    }
    // Pages Direct Upload
    if (req.method === 'GET' && path === `/accounts/${ACCOUNT}/pages/projects/site-x/upload-token`) return cfOk({ jwt: 'upload-jwt' });
    if (path.startsWith('/pages/assets/')) {
      if (req.headers.authorization !== 'Bearer upload-jwt') return cfError(401, 8000013, 'bad jwt');
      const body = JSON.parse(req.body.toString()) as unknown;
      if (path === '/pages/assets/check-missing') {
        const { hashes }: { hashes: string[] } = JSON.parse(req.body.toString());
        return cfOk(hashes.filter((h) => !this.pagesAssets.has(h)));
      }
      if (path === '/pages/assets/upload') {
        for (const item of body as { key: string }[]) this.pagesAssets.add(item.key);
        return cfOk(null);
      }
      if (path === '/pages/assets/upsert-hashes') return cfOk(true);
    }
    if (req.method === 'POST' && path === `/accounts/${ACCOUNT}/pages/projects/site-x/deployments`) {
      this.pagesDeployments.push(req);
      return cfOk({ id: `pages-dep-${this.pagesDeployments.length}`, url: 'https://abc.site-x.pages.dev' });
    }
    return cfError(404, 7003, `no route ${req.method} ${path}`);
  };
}

const pki = createPki(['api.cloudflare.com', SITE]);
let fake: FakeCloudflare;
let server: TestServer;
let proxy: TestProxy;
const work = mkdtempSync(join(tmpdir(), 'legatto-deploy-'));

beforeAll(async () => {
  fake = new FakeCloudflare();
  server = await startHttps(pki.key, pki.cert, (req) => fake.handle(req));
  proxy = await startProxy(server.port, ['api.cloudflare.com:443', `${SITE}:443`]);
});

afterAll(async () => {
  await proxy.close();
  await server.close();
});

function bundle(release: string): { dir: string; config: DeployConfig } {
  const dir = join(work, release);
  mkdirSync(dir, { recursive: true });
  const script = `export default { fetch() { return new Response('${release}'); } };\n`;
  writeFileSync(join(dir, 'worker.js'), script);
  const config = validateDeployConfig({
    account_id: ACCOUNT,
    zone_id: ZONE,
    site_host: SITE,
    script_name: 'legatto-forms',
    queue_name: 'forms',
    compatibility_date: '2026-11-01',
    entry: 'worker.js',
    entry_sha256: createHash('sha256').update(script).digest('hex'),
    release,
    ratelimits: {
      RL_IP: { namespace_id: '1001', limit: 2, period: 60 },
      RL_GLOBAL: { namespace_id: '1002', limit: 30, period: 60 },
      RL_SELFTEST: { namespace_id: '1003', limit: 2, period: 60 },
    },
    vars: {
      OFFICE_X25519_PUB: 'b2ZmaWNl',
      OFFICE_KID: '0123456789abcdef',
      SELFTEST_ED25519_PUB: 'c2VsZg==',
      SITE_ORIGIN: `https://${SITE}`,
      TURNSTILE_HOSTNAMES: SITE,
      TURNSTILE_ACTION: 'submit_case',
      RELEASE: release,
    },
    expected_signer_kid: 'fedcba9876543210',
    health_timeout_seconds: 10,
  });
  return { dir, config };
}

function deps() {
  const transport = createTransport(pki.caFile, proxy.url);
  let clock = 0;
  return {
    api: new CfApi(transport, API, TOKEN),
    transport,
    sleep: async (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('transport: egress proxy and pinned CA', () => {
  it('tunnels through CONNECT and trusts only the pinned bundle (fail-closed)', async () => {
    const pinned = createTransport(pki.caFile, proxy.url);
    const ok = await pinned.request(`${API}/accounts/${ACCOUNT}/workers/scripts/legatto-forms/subdomain`, { method: 'GET', headers: { Authorization: `Bearer ${TOKEN}` } });
    expect(ok.status).toBe(404);
    expect(proxy.connects).toContain('api.cloudflare.com:443');

    const wrongCa = createTransport(pki.rogueCaFile, proxy.url);
    await expect(wrongCa.request(`${API}/`, { method: 'GET' })).rejects.toThrow();
    await expect(pinned.request('https://evil.example/', { method: 'GET' })).rejects.toThrow(/proxy refused CONNECT/);
    await expect(pinned.request('http://api.cloudflare.com/', { method: 'GET' })).rejects.toThrow(/non-HTTPS/);
  });
});

describe('worker deploy', () => {
  it('first deployment creates the script with secrets, route and no workers.dev', async () => {
    const { dir, config } = bundle('1.0.0');
    const result = await deployWorker(deps(), config, dir, SECRETS);
    expect(result).toMatchObject({ ok: true, rolled_back: false, previous_versions: [] });
    const put = server.requests.find((r) => r.method === 'PUT');
    const metadata = JSON.parse(multipart(put!).metadata) as { bindings: { type: string; name: string; text?: string }[]; keep_bindings?: string[]; observability: unknown; logpush: boolean };
    expect(metadata.bindings.filter((b) => b.type === 'secret_text').map((b) => b.name).sort()).toEqual(['IP_HASH_KEY', 'SIGNING_KEY', 'TURNSTILE_SECRET']);
    expect(metadata.bindings).toContainEqual({ type: 'queue', name: 'FORMS', queue_name: 'forms' });
    expect(metadata.bindings).toContainEqual({ type: 'ratelimit', name: 'RL_IP', namespace_id: '1001', simple: { limit: 2, period: 60 } });
    expect(metadata.keep_bindings).toBeUndefined();
    expect(metadata).toMatchObject({ logpush: false, observability: { enabled: false } });
    expect(fake.routes).toEqual([{ id: 'r0', pattern: `${SITE}/api/*`, script: 'legatto-forms' }]);
    expect(server.requests.some((r) => r.path.endsWith('/subdomain') && r.body.toString().includes('"enabled":false'))).toBe(true);
  });

  it('refuses an entry whose sha256 differs from the manifest', async () => {
    const { dir, config } = bundle('1.0.1');
    writeFileSync(join(dir, 'worker.js'), 'tampered');
    await expect(deployWorker(deps(), config, dir, null)).rejects.toThrow(/does not match the manifest/);
  });

  it('later releases go through Versions + Deployments and keep the secrets', async () => {
    const { dir, config } = bundle('1.1.0');
    const before = server.requests.length;
    const result = await deployWorker(deps(), config, dir, null);
    expect(result.ok).toBe(true);
    const upload = server.requests.slice(before).find((r) => r.path.includes('/versions'));
    const metadata = JSON.parse(multipart(upload!).metadata) as { bindings: { type: string }[]; keep_bindings: string[] };
    expect(metadata.keep_bindings).toEqual(['secret_text']);
    expect(metadata.bindings.some((b) => b.type === 'secret_text')).toBe(false);
    expect(fake.deployed).toEqual([{ version_id: result.version_id, percentage: 100 }]);
    expect(fake.routes).toHaveLength(1);
  });

  it('an unhealthy release is rolled back to the previous version (CLI exit 60)', async () => {
    const { dir, config } = bundle('1.2.0');
    const previous = fake.deployed;
    fake.unhealthyReleases.add('1.2.0');
    const configFile = join(work, 'deploy-1.2.0.json');
    writeFileSync(configFile, JSON.stringify(config));
    const run = await runTools(['worker-deploy', '--config', configFile, '--bundle', dir], { HTTPS_PROXY: proxy.url, LEGATTO_CF_API_BASE: API });
    expect(run.status).toBe(60);
    const out = JSON.parse(run.stdout) as { ok: boolean; rolled_back: boolean; previous_versions: unknown };
    expect(out).toMatchObject({ ok: false, rolled_back: true, previous_versions: previous });
    expect(fake.deployed).toEqual(previous);
    expect(run.stdout + run.stderr).not.toContain(TOKEN);
  }, 60_000);

  it('CLI rejects unknown commands with exit 2', async () => {
    const run = await runTools(['nope'], {});
    expect(run.status).toBe(2);
  });
});

/** Runs dist/tools.mjs without blocking the event loop (the fakes live in this process). */
async function runTools(args: string[], env: Record<string, string>): Promise<{ status: number | null; stdout: string; stderr: string }> {
  const tokenFile = join(work, 'token');
  writeFileSync(tokenFile, `${TOKEN}\n`);
  const child = spawn('node', [join(__dirname, '../../dist/tools.mjs'), ...args], {
    env: { PATH: process.env.PATH ?? '', LEGATTO_CF_CA_FILE: pki.caFile, LEGATTO_CF_TOKEN_FILE: tokenFile, ...env },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (chunk: Buffer) => (stdout += chunk.toString()));
  child.stderr.on('data', (chunk: Buffer) => (stderr += chunk.toString()));
  const { promise, resolve } = Promise.withResolvers<number | null>();
  child.on('close', resolve);
  return { status: await promise, stdout, stderr };
}

describe('pages direct upload', () => {
  function site(): string {
    const dir = mkdtempSync(join(tmpdir(), 'legatto-site-'));
    mkdirSync(join(dir, 'data'));
    writeFileSync(join(dir, 'index.html'), '<!doctype html><title>Poseł</title>');
    writeFileSync(join(dir, 'data', 'form-key.json'), '{"v":1}');
    writeFileSync(join(dir, '_headers'), '/*\n  X-Frame-Options: DENY\n');
    return dir;
  }

  it('hashes assets like wrangler (BLAKE3 of base64 + extension, 32 hex)', () => {
    const hash = hashAsset(Buffer.from('<!doctype html>'), 'index.html');
    expect(hash).toMatch(/^[0-9a-f]{32}$/);
    expect(hashAsset(Buffer.from('<!doctype html>'), 'index.htm')).not.toBe(hash);
  });

  it('uploads only missing assets with the upload JWT and deploys the manifest', async () => {
    const dir = site();
    const api = new CfApi(createTransport(pki.caFile, proxy.url), API, TOKEN);
    const first = await deployPages(api, ACCOUNT, 'site-x', dir, 'main');
    expect(first).toMatchObject({ ok: true, deployment_id: 'pages-dep-1', files: 2, uploaded: 2 });
    const form = multipart(fake.pagesDeployments[0]);
    expect(Object.keys(JSON.parse(form.manifest) as object).sort()).toEqual(['/data/form-key.json', '/index.html']);
    expect(form.branch).toBe('main');
    expect(form._headers).toContain('X-Frame-Options');
    const second = await deployPages(api, ACCOUNT, 'site-x', dir, 'main');
    expect(second.uploaded).toBe(0);
    const assetCalls = server.requests.filter((r) => r.path.startsWith('/client/v4/pages/assets/'));
    expect(assetCalls.every((r) => r.headers.authorization === 'Bearer upload-jwt')).toBe(true);
  });

  it('refuses Functions entry points and symlinks in the build output', () => {
    const worker = site();
    writeFileSync(join(worker, '_worker.js'), 'export default {}');
    expect(() => collectSite(worker)).toThrow(/forbidden _worker.js/);
    const fns = site();
    mkdirSync(join(fns, 'functions'));
    expect(() => collectSite(fns)).toThrow(/forbidden functions/);
    const link = site();
    symlinkSync('/etc/hosts', join(link, 'hosts.txt'));
    expect(() => collectSite(link)).toThrow(/symlink/);
  });
});
