// HTTPS client for the office server tools: Cloudflare API and the site's
// own /api/* endpoints, always through the role's egress proxy (HTTP CONNECT,
// HTTPS_PROXY) and with a pinned CA bundle that REPLACES the default trust
// store (fail-closed: no fallback to Node's bundled roots).
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { Socket } from 'node:net';
import tls from 'node:tls';

export interface HttpResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

export interface HttpOptions {
  method: string;
  headers?: Record<string, string>;
  body?: Uint8Array;
  timeoutMs?: number;
}

export interface Transport {
  request(url: string, options: HttpOptions): Promise<HttpResponse>;
}

const MAX_RESPONSE_BYTES = 64 * 1024 * 1024;

function connectThroughProxy(proxy: URL, host: string, port: number, timeoutMs: number): Promise<Socket> {
  const { promise, resolve, reject } = Promise.withResolvers<Socket>();
  const req = http.request({
    host: proxy.hostname,
    port: Number(proxy.port || 80),
    method: 'CONNECT',
    path: `${host}:${port}`,
    headers: { Host: `${host}:${port}` },
    timeout: timeoutMs,
  });
  req.once('connect', (res, socket) => {
    if (res.statusCode === 200) {
      resolve(socket);
      return;
    }
    socket.destroy();
    reject(new Error(`proxy refused CONNECT ${host}:${port} (HTTP ${res.statusCode})`));
  });
  req.once('timeout', () => req.destroy(new Error(`proxy CONNECT ${host}:${port} timed out`)));
  req.once('error', reject);
  req.end();
  return promise;
}

/**
 * Transport with an explicit CA bundle and optional CONNECT proxy.
 * `proxyUrl` null = direct connection (only used when no proxy is configured,
 * e.g. the test harness).
 */
export function createTransport(caFile: string, proxyUrl: string | null): Transport {
  const ca = readFileSync(caFile, 'utf8');
  const proxy = proxyUrl ? new URL(proxyUrl) : null;
  if (proxy && proxy.protocol !== 'http:') throw new Error('HTTPS_PROXY must be an http:// URL');
  return {
    async request(url, options) {
      const target = new URL(url);
      if (target.protocol !== 'https:') throw new Error(`refusing non-HTTPS URL ${target.origin}`);
      const port = Number(target.port || 443);
      const timeoutMs = options.timeoutMs ?? 60_000;
      const socket = proxy ? await connectThroughProxy(proxy, target.hostname, port, timeoutMs) : undefined;
      const { promise, resolve, reject } = Promise.withResolvers<HttpResponse>();
      const req = https.request(
        {
          host: target.hostname,
          port,
          path: `${target.pathname}${target.search}`,
          method: options.method,
          headers: { ...options.headers, ...(options.body ? { 'Content-Length': String(options.body.length) } : {}) },
          // Node only honours createConnection when no agent is set; agent:false
          // would create a fresh Agent that dials the target directly.
          agent: socket ? undefined : false,
          timeout: timeoutMs,
          servername: target.hostname,
          ca,
          minVersion: 'TLSv1.2',
          ...(socket ? { createConnection: () => tls.connect({ socket, servername: target.hostname, ca, minVersion: 'TLSv1.2' }) } : {}),
        },
        (res) => {
          const chunks: Buffer[] = [];
          let size = 0;
          res.on('data', (chunk: Buffer) => {
            size += chunk.length;
            if (size > MAX_RESPONSE_BYTES) {
              req.destroy(new Error('response too large'));
              return;
            }
            chunks.push(chunk);
          });
          res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
          res.on('error', reject);
        },
      );
      req.once('timeout', () => req.destroy(new Error(`request to ${target.host} timed out`)));
      req.once('error', reject);
      if (options.body) req.write(options.body);
      req.end();
      return promise;
    },
  };
}

export class CfApiError extends Error {
  constructor(
    readonly status: number,
    readonly codes: number[],
    message: string,
  ) {
    super(message);
  }
}

interface CfEnvelope<T> {
  success?: boolean;
  errors?: { code?: number; message?: string }[];
  result?: T;
}

/** Cloudflare API v4 client (`Authorization: Bearer`, JSON envelope). */
export class CfApi {
  constructor(
    private readonly transport: Transport,
    private readonly base: string,
    private readonly token: string,
  ) {}

  async call<T>(method: string, path: string, init: { json?: unknown; form?: FormData; bearer?: string } = {}): Promise<T> {
    const headers: Record<string, string> = { Authorization: `Bearer ${init.bearer ?? this.token}`, Accept: 'application/json' };
    let body: Uint8Array | undefined;
    if (init.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = Buffer.from(JSON.stringify(init.json));
    } else if (init.form) {
      const encoded = new Response(init.form);
      headers['Content-Type'] = encoded.headers.get('Content-Type') ?? '';
      body = new Uint8Array(await encoded.arrayBuffer());
    }
    const res = await this.transport.request(`${this.base}${path}`, { method, headers, body });
    let parsed: CfEnvelope<T>;
    try {
      parsed = JSON.parse(res.body.toString('utf8')) as CfEnvelope<T>;
    } catch {
      throw new CfApiError(res.status, [], `${method} ${path}: HTTP ${res.status}, body is not JSON`);
    }
    if (res.status >= 400 || parsed.success !== true) {
      const errors = parsed.errors ?? [];
      const codes = errors.map((e) => e.code ?? 0);
      const text = errors.map((e) => `${e.code ?? '?'} ${e.message ?? ''}`.trim()).join('; ');
      throw new CfApiError(res.status, codes, `${method} ${path}: HTTP ${res.status} ${text}`);
    }
    return parsed.result as T;
  }
}

export function readSecretFile(path: string): string {
  const value = readFileSync(path, 'utf8').trim();
  if (value === '') throw new Error(`secret file ${path} is empty`);
  return value;
}
