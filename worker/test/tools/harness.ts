// Local stand-ins for the network the server tools talk to: an HTTP CONNECT
// proxy (the role's Smokescreen) and an HTTPS server answering for
// api.cloudflare.com and the site host, with certificates from a throwaway CA.
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export interface Pki {
  dir: string;
  caFile: string;
  rogueCaFile: string;
  key: string;
  cert: string;
  rogueKey: string;
  rogueCert: string;
}

function issue(dir: string, name: string, hosts: string[]): { key: string; cert: string; caFile: string } {
  const ca = join(dir, `${name}-ca`);
  const leaf = join(dir, `${name}-leaf`);
  const openssl = (...args: string[]) => execFileSync('openssl', args, { stdio: 'pipe' });
  // Explicit v3 extensions: LibreSSL's `req -x509` would not mark the CA as a CA.
  writeFileSync(`${ca}.ext`, 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${ca}.key`, '-out', `${ca}.csr`, '-subj', `/CN=${name} test CA`);
  openssl('x509', '-req', '-in', `${ca}.csr`, '-signkey', `${ca}.key`, '-sha256', '-out', `${ca}.pem`, '-days', '2', '-extfile', `${ca}.ext`);
  openssl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${leaf}.key`, '-out', `${leaf}.csr`, '-subj', `/CN=${hosts[0]}`);
  writeFileSync(`${leaf}.ext`, `subjectAltName=${hosts.map((h) => `DNS:${h}`).join(',')}\nextendedKeyUsage=serverAuth\n`);
  openssl('x509', '-req', '-in', `${leaf}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-CAcreateserial', '-sha256', '-out', `${leaf}.pem`, '-days', '2', '-extfile', `${leaf}.ext`);
  return { key: readFileSync(`${leaf}.key`, 'utf8'), cert: readFileSync(`${leaf}.pem`, 'utf8'), caFile: `${ca}.pem` };
}

export function createPki(hosts: string[]): Pki {
  const dir = mkdtempSync(join(tmpdir(), 'legatto-tools-'));
  const good = issue(dir, 'pinned', hosts);
  const rogue = issue(dir, 'rogue', hosts);
  return { dir, caFile: good.caFile, rogueCaFile: rogue.caFile, key: good.key, cert: good.cert, rogueKey: rogue.key, rogueCert: rogue.cert };
}

export interface Recorded {
  method: string;
  host: string;
  path: string;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
}

export type Handler = (req: Recorded) => { status: number; body: unknown; raw?: boolean };

export interface TestServer {
  port: number;
  requests: Recorded[];
  close: () => Promise<void>;
}

export interface TestProxy {
  url: string;
  connects: string[];
  close: () => Promise<void>;
}

/** Port of a server listening on TCP (address() is AddressInfo once listening). */
function listeningPort(server: net.Server): number {
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('server is not listening on TCP');
  return address.port;
}

export async function startHttps(key: string, cert: string, handler: Handler): Promise<TestServer> {
  const requests: Recorded[] = [];
  const server = https.createServer({ key, cert }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const recorded: Recorded = {
        method: req.method ?? '',
        host: String(req.headers.host ?? ''),
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks),
      };
      requests.push(recorded);
      const out = handler(recorded);
      res.writeHead(out.status, { 'Content-Type': 'application/json' });
      res.end(out.raw ? String(out.body) : JSON.stringify(out.body));
    });
  });
  const { promise, resolve } = Promise.withResolvers<void>();
  server.listen(0, '127.0.0.1', () => resolve());
  await promise;
  return {
    port: listeningPort(server),
    requests,
    close: () => {
      const done = Promise.withResolvers<void>();
      server.closeAllConnections();
      server.close(() => done.resolve());
      return done.promise;
    },
  };
}

/** CONNECT proxy that tunnels every allowed host:443 to the local HTTPS server. */
export async function startProxy(upstreamPort: number, allowed: string[]): Promise<TestProxy> {
  const connects: string[] = [];
  const tunnels = new Set<net.Socket>();
  const server = http.createServer((_req, res) => {
    res.writeHead(405);
    res.end();
  });
  server.on('connect', (req, clientSocket: net.Socket, head: Buffer) => {
    const target = req.url ?? '';
    connects.push(target);
    if (!allowed.includes(target)) {
      clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
      return;
    }
    tunnels.add(clientSocket);
    clientSocket.on('close', () => tunnels.delete(clientSocket));
    const upstream = net.connect(upstreamPort, '127.0.0.1', () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      upstream.write(head);
      upstream.pipe(clientSocket);
      clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });
  const { promise, resolve } = Promise.withResolvers<void>();
  server.listen(0, '127.0.0.1', () => resolve());
  await promise;
  return {
    url: `http://127.0.0.1:${listeningPort(server)}`,
    connects,
    close: () => {
      const done = Promise.withResolvers<void>();
      for (const socket of tunnels) socket.destroy();
      server.closeAllConnections();
      server.close(() => done.resolve());
      return done.promise;
    },
  };
}

export function cfOk(result: unknown): { status: number; body: unknown } {
  return { status: 200, body: { success: true, errors: [], messages: [], result } };
}

export function cfError(status: number, code: number, message: string): { status: number; body: unknown } {
  return { status, body: { success: false, errors: [{ code, message }], messages: [], result: null } };
}

/** Splits a multipart/form-data body into named parts (enough for assertions). */
export function multipart(req: Recorded): Record<string, string> {
  const type = String(req.headers['content-type'] ?? '');
  const boundary = /boundary=(.+)$/.exec(type)?.[1];
  if (!boundary) throw new Error('not multipart');
  const out: Record<string, string> = {};
  for (const part of req.body.toString('utf8').split(`--${boundary}`)) {
    const match = /name="([^"]+)"[\s\S]*?\r\n\r\n([\s\S]*)\r\n$/.exec(part);
    if (match) out[match[1]] = match[2];
  }
  return out;
}
