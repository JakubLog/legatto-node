// Cloudflare Pages Direct Upload of the generated public site, without
// wrangler (the same API sequence wrangler 4.x `pages deploy` uses):
//   upload-token (JWT) -> assets/check-missing -> assets/upload (buckets)
//   -> assets/upsert-hashes -> POST deployments (manifest + _headers/_redirects).
// Asset key = BLAKE3(base64(content) || extension) hex, first 32 chars.
import { readFileSync, readdirSync, lstatSync } from 'node:fs';
import { extname, join, relative, sep } from 'node:path';
import { blake3 } from '@noble/hashes/blake3.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { CfApi } from './http';

export const MAX_FILES = 20_000;
export const MAX_FILE_BYTES = 25 * 1024 * 1024;
const MAX_BUCKET_BYTES = 40 * 1024 * 1024;
const MAX_BUCKET_FILES = 2_000;
/** Control files sent as deployment form fields, never as assets. */
const CONTROL_FILES: Record<string, true> = { _headers: true, _redirects: true };
/** Never deployed: would turn the static site into Pages Functions / advanced mode. */
const FORBIDDEN: Record<string, true> = { '_worker.js': true, functions: true, '_routes.json': true };

const MIME: Record<string, string> = {
  html: 'text/html',
  htm: 'text/html',
  css: 'text/css',
  js: 'application/javascript',
  mjs: 'application/javascript',
  json: 'application/json',
  webmanifest: 'application/manifest+json',
  map: 'application/json',
  txt: 'text/plain',
  xml: 'application/xml',
  svg: 'image/svg+xml',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  webp: 'image/webp',
  avif: 'image/avif',
  gif: 'image/gif',
  ico: 'image/vnd.microsoft.icon',
  woff: 'font/woff',
  woff2: 'font/woff2',
  pdf: 'application/pdf',
  geojson: 'application/geo+json',
};

export interface SiteFile {
  name: string;
  path: string;
  size: number;
  hash: string;
  contentType: string;
}

export function hashAsset(content: Buffer, name: string): string {
  return bytesToHex(blake3(Buffer.from(content.toString('base64') + extname(name).slice(1)))).slice(0, 32);
}

/** Walks the build output; refuses symlinks, oversized files and Functions entry points. */
export function collectSite(root: string): { files: SiteFile[]; headers: string | null; redirects: string | null } {
  const files: SiteFile[] = [];
  let headers: string | null = null;
  let redirects: string | null = null;
  const walk = (dir: string): void => {
    for (const entry of readdirSync(dir).sort()) {
      const path = join(dir, entry);
      const name = relative(root, path).split(sep).join('/');
      if (dir === root && Object.hasOwn(FORBIDDEN, entry)) throw new Error(`build output contains forbidden ${entry}`);
      const stat = lstatSync(path);
      if (stat.isSymbolicLink()) throw new Error(`build output contains a symlink: ${name}`);
      if (stat.isDirectory()) {
        walk(path);
        continue;
      }
      if (!stat.isFile()) throw new Error(`build output contains a special file: ${name}`);
      if (dir === root && Object.hasOwn(CONTROL_FILES, entry)) {
        const text = readFileSync(path, 'utf8');
        if (entry === '_headers') headers = text;
        else redirects = text;
        continue;
      }
      if (stat.size > MAX_FILE_BYTES) throw new Error(`${name} exceeds the Pages per-file limit`);
      const content = readFileSync(path);
      const ext = extname(name).slice(1).toLowerCase();
      files.push({
        name,
        path,
        size: stat.size,
        hash: hashAsset(content, name),
        contentType: Object.hasOwn(MIME, ext) ? MIME[ext] : 'application/octet-stream',
      });
      if (files.length > MAX_FILES) throw new Error(`build output has more than ${MAX_FILES} files`);
    }
  };
  walk(root);
  return { files, headers, redirects };
}

function buckets(files: SiteFile[]): SiteFile[][] {
  const out: { files: SiteFile[]; bytes: number }[] = [];
  for (const file of [...files].sort((a, b) => b.size - a.size)) {
    let bucket = out.find((b) => b.bytes + file.size <= MAX_BUCKET_BYTES && b.files.length < MAX_BUCKET_FILES);
    if (!bucket) {
      bucket = { files: [], bytes: 0 };
      out.push(bucket);
    }
    bucket.files.push(file);
    bucket.bytes += file.size;
  }
  return out.map((b) => b.files);
}

export interface PagesDeployResult {
  ok: true;
  deployment_id: string;
  url: string | null;
  files: number;
  uploaded: number;
}

export async function deployPages(api: CfApi, accountId: string, project: string, root: string, branch: string): Promise<PagesDeployResult> {
  const site = collectSite(root);
  if (site.files.length === 0) throw new Error('build output is empty');
  const { jwt } = await api.call<{ jwt: string }>('GET', `/accounts/${accountId}/pages/projects/${project}/upload-token`);
  const hashes = [...new Set(site.files.map((f) => f.hash))];
  const missing = new Set(await api.call<string[]>('POST', '/pages/assets/check-missing', { json: { hashes }, bearer: jwt }));
  const queued = new Set<string>();
  const toUpload = site.files.filter((f) => {
    if (!missing.has(f.hash) || queued.has(f.hash)) return false;
    queued.add(f.hash);
    return true;
  });
  for (const bucket of buckets(toUpload)) {
    const payload = bucket.map((f) => ({
      key: f.hash,
      value: readFileSync(f.path).toString('base64'),
      metadata: { contentType: f.contentType },
      base64: true,
    }));
    await api.call('POST', '/pages/assets/upload', { json: payload, bearer: jwt });
  }
  await api.call('POST', '/pages/assets/upsert-hashes', { json: { hashes }, bearer: jwt });

  const manifest = Object.fromEntries(site.files.map((f) => [`/${f.name}`, f.hash]));
  const form = new FormData();
  form.set('manifest', JSON.stringify(manifest));
  form.set('branch', branch);
  form.set('commit_dirty', 'true');
  if (site.headers !== null) form.set('_headers', new File([site.headers], '_headers'));
  if (site.redirects !== null) form.set('_redirects', new File([site.redirects], '_redirects'));
  const deployment = await api.call<{ id: string; url?: string }>('POST', `/accounts/${accountId}/pages/projects/${project}/deployments`, { form });
  return { ok: true, deployment_id: deployment.id, url: deployment.url ?? null, files: site.files.length, uploaded: toUpload.length };
}

export interface PagesDeploymentInfo {
  id: string;
  created_on: string;
}

/** Latest production deployment of the project (drift check). */
export async function latestPagesDeployment(api: CfApi, accountId: string, project: string): Promise<PagesDeploymentInfo | null> {
  const list = await api.call<{ id: string; created_on: string; environment: string }[]>(
    'GET',
    `/accounts/${accountId}/pages/projects/${project}/deployments?env=production`,
  );
  const first = list.find((d) => d.environment === 'production');
  return first ? { id: first.id, created_on: first.created_on } : null;
}
