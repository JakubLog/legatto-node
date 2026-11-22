// tools.mjs — server-side CLI shipped in the worker bundle and run by the
// host wrappers legatto-worker-deploy / legatto-site-publish inside the app
// image (node, uid 65532, read-only rootfs, network legatto-egress-publish).
//
//   worker-deploy   --config FILE --bundle DIR [--secrets FILE]
//   worker-rollback --config FILE --versions FILE
//   worker-state    --config FILE
//   pages-deploy    --config FILE --dir DIR
//   pages-state     --config FILE
//
// Exactly one JSON object on stdout; diagnostics on stderr; secrets never printed.
// Exit codes: 0 OK, 1 error, 2 usage, 60 Worker unhealthy and rolled back.
//
// Environment: LEGATTO_CF_TOKEN_FILE, LEGATTO_CF_CA_FILE, LEGATTO_CF_API_BASE,
// HTTPS_PROXY (the role's egress proxy).
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { setTimeout as sleep } from 'node:timers/promises';
import { CfApi, createTransport, readSecretFile } from './http';
import { deployPages, latestPagesDeployment } from './pages';
import { currentDeployment, deployWorker, rollbackWorker, validateDeployConfig, validateSecrets } from './worker';

const DEFAULT_TOKEN_FILE = '/run/credentials/legatto-cf-pages-token';
const DEFAULT_CA_FILE = '/etc/legatto/ca/cloudflare-api.pem';
const DEFAULT_API_BASE = 'https://api.cloudflare.com/client/v4';

class UsageError extends Error {}

interface PagesConfig {
  account_id: string;
  project: string;
  branch: string;
}

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function pagesConfig(path: string): PagesConfig {
  const raw = readJson(path) as Partial<PagesConfig>;
  if (!/^[0-9a-f]{32}$/.test(raw.account_id ?? '')) throw new Error('account_id invalid');
  if (!/^[a-z0-9][a-z0-9-]{0,57}$/.test(raw.project ?? '')) throw new Error('project invalid');
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(raw.branch ?? '')) throw new Error('branch invalid');
  return raw as PagesConfig;
}

function required(values: Record<string, string | undefined>, name: string): string {
  const value = values[name];
  if (!value) throw new UsageError(`--${name} is required`);
  return value;
}

async function run(argv: string[]): Promise<{ result: unknown; code: number }> {
  const [command, ...rest] = argv;
  const { values } = parseArgs({
    args: rest,
    options: {
      config: { type: 'string' },
      bundle: { type: 'string' },
      secrets: { type: 'string' },
      versions: { type: 'string' },
      dir: { type: 'string' },
    },
    strict: true,
  });
  const transport = createTransport(process.env.LEGATTO_CF_CA_FILE ?? DEFAULT_CA_FILE, process.env.HTTPS_PROXY ?? process.env.https_proxy ?? null);
  const api = new CfApi(transport, process.env.LEGATTO_CF_API_BASE ?? DEFAULT_API_BASE, readSecretFile(process.env.LEGATTO_CF_TOKEN_FILE ?? DEFAULT_TOKEN_FILE));

  switch (command) {
    case 'worker-deploy': {
      const config = validateDeployConfig(readJson(required(values, 'config')));
      const secrets = values.secrets ? validateSecrets(readJson(values.secrets)) : null;
      const result = await deployWorker({ api, transport, sleep, now: Date.now }, config, required(values, 'bundle'), secrets);
      return { result, code: result.ok ? 0 : result.rolled_back ? 60 : 1 };
    }
    case 'worker-rollback': {
      const config = validateDeployConfig(readJson(required(values, 'config')));
      const versions = readJson(required(values, 'versions'));
      if (!Array.isArray(versions)) throw new Error('--versions must hold a JSON array');
      await rollbackWorker(api, config, versions, 'selftest failed');
      return { result: { ok: true, versions }, code: 0 };
    }
    case 'worker-state': {
      const config = validateDeployConfig(readJson(required(values, 'config')));
      const deployment = await currentDeployment(api, config);
      return { result: { ok: true, deployment_id: deployment?.id ?? null, versions: deployment?.versions ?? [] }, code: 0 };
    }
    case 'pages-deploy': {
      const config = pagesConfig(required(values, 'config'));
      const result = await deployPages(api, config.account_id, config.project, required(values, 'dir'), config.branch);
      return { result, code: 0 };
    }
    case 'pages-state': {
      const config = pagesConfig(required(values, 'config'));
      return { result: { ok: true, latest: await latestPagesDeployment(api, config.account_id, config.project) }, code: 0 };
    }
    default:
      throw new UsageError(`unknown command ${command ?? '(none)'}`);
  }
}

try {
  const { result, code } = await run(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = code;
} catch (err) {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`tools: ${message}\n`);
  process.stdout.write(`${JSON.stringify({ ok: false, error: message })}\n`);
  process.exitCode = err instanceof UsageError || (err instanceof TypeError && 'code' in err && err.code === 'ERR_PARSE_ARGS_UNKNOWN_OPTION') ? 2 : 1;
}
