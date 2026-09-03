/* eslint-disable max-classes-per-file */
import crypto from 'crypto';
import http from 'http';
import { URL } from 'url';
import Queue from 'promise-queue';

import type { Logger } from '../logger';
import {
  handshake2SeedAuthHash,
  KlapEncryptionSession,
  matchHandshake1Auth,
  type Credentials,
} from './klap';

export class AuthenticationError extends Error {
  override readonly name = 'AuthenticationError';
}

export interface KlapHttpResponse {
  status: number;
  body: Buffer;
  cookies: Record<string, string>;
}

const SESSION_COOKIE_NAME = 'TP_SESSIONID';
const ONE_DAY_SECONDS = 86400;
const SESSION_EXPIRE_BUFFER_SECONDS = 60 * 20;

function parseCookies(
  setCookie: string | string[] | undefined,
): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (setCookie == null) return cookies;
  const list = Array.isArray(setCookie) ? setCookie : [setCookie];
  list.forEach((item) => {
    const pair = item.split(';')[0];
    if (pair == null || pair.length === 0) return;
    const eq = pair.indexOf('=');
    if (eq <= 0) return;
    cookies[pair.slice(0, eq).trim()] = pair.slice(eq + 1);
  });
  return cookies;
}

function cookieHeader(
  cookies: Record<string, string> | undefined,
): string | undefined {
  if (cookies == null) return undefined;
  const parts = Object.entries(cookies).map(
    ([name, value]) => `${name}=${value}`,
  );
  return parts.length > 0 ? parts.join('; ') : undefined;
}

async function httpPost(
  url: string,
  {
    body,
    cookies,
    timeout,
    params,
  }: {
    body: Buffer;
    cookies?: Record<string, string>;
    timeout: number;
    params?: Record<string, string | number>;
  },
): Promise<KlapHttpResponse> {
  const parsed = new URL(url);
  if (params != null) {
    Object.entries(params).forEach(([key, value]) => {
      parsed.searchParams.set(key, String(value));
    });
  }

  return new Promise((resolve, reject) => {
    const cookie = cookieHeader(cookies);
    const req = http.request(
      parsed,
      {
        method: 'POST',
        timeout,
        headers: {
          'Content-Type': 'application/octet-stream',
          'Content-Length': body.length,
          ...(cookie != null ? { Cookie: cookie } : {}),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => {
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks),
            cookies: parseCookies(res.headers['set-cookie']),
          });
        });
      },
    );

    req.on('timeout', () => {
      req.destroy(new Error(`KLAP HTTP timeout after ${timeout}ms: ${url}`));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/**
 * KLAP HTTP transport for IOT (Kasa) payloads.
 *
 * Handshake and AES session follow python-kasa's KlapTransport / KlapTransportV2.
 * After firmware that closes TCP 9999, IOT devices speak this on HTTP port 80.
 */
export default class KlapConnection {
  private queue = new Queue(1, Infinity);

  private handshakeDone = false;

  private sessionExpireAt: number | undefined;

  private sessionCookie: Record<string, string> | undefined;

  private encryptionSession: KlapEncryptionSession | undefined;

  constructor(
    public host: string,
    public port: number,
    readonly log: Logger,
    readonly credentials: Credentials,
  ) {}

  private get appUrl(): string {
    return `http://${this.host}:${this.port}/app`;
  }

  private get description(): string {
    return `KLAP ${this.host}:${this.port}`;
  }

  private handshakeSessionExpired(): boolean {
    return (
      this.sessionExpireAt == null ||
      this.sessionExpireAt - Date.now() / 1000 <= 0
    );
  }

  reset(): void {
    this.handshakeDone = false;
    this.sessionExpireAt = undefined;
    this.sessionCookie = undefined;
    this.encryptionSession = undefined;
  }

  close(): void {
    this.reset();
  }

  private async performHandshake1(timeout: number): Promise<{
    localSeed: Buffer;
    remoteSeed: Buffer;
    authHash: Buffer;
    version: 1 | 2;
  }> {
    const localSeed = crypto.randomBytes(16);
    const response = await httpPost(`${this.appUrl}/handshake1`, {
      body: localSeed,
      timeout,
    });

    if (response.status !== 200) {
      throw new Error(
        `Device ${this.host} responded with ${response.status} to handshake1`,
      );
    }

    if (response.body.length < 48) {
      throw new Error(
        `Device ${this.host} responded with unexpected klap response to handshake1`,
      );
    }

    const remoteSeed = response.body.subarray(0, 16);
    const serverHash = response.body.subarray(16, 48);

    const sessionId = response.cookies[SESSION_COOKIE_NAME];
    if (sessionId != null) {
      this.sessionCookie = {
        [SESSION_COOKIE_NAME]: sessionId,
      };
    }

    const timeoutCookie = response.cookies.TIMEOUT;
    const timeoutSeconds =
      timeoutCookie != null ? Number.parseInt(timeoutCookie, 10) : NaN;
    const sessionTimeout = Number.isFinite(timeoutSeconds)
      ? timeoutSeconds
      : ONE_DAY_SECONDS;
    this.sessionExpireAt =
      Date.now() / 1000 + sessionTimeout - SESSION_EXPIRE_BUFFER_SECONDS;

    const matched = matchHandshake1Auth(
      localSeed,
      remoteSeed,
      serverHash,
      this.credentials,
    );
    if (matched == null) {
      throw new AuthenticationError(
        `Device response did not match our challenge on ip ${this.host}, check that your e-mail and password (both case-sensitive) are correct.`,
      );
    }

    this.log.debug(
      `KlapConnection(${this.description}): handshake1 matched KLAP v${matched.version}`,
    );

    return {
      localSeed,
      remoteSeed,
      authHash: matched.authHash,
      version: matched.version,
    };
  }

  private async performHandshake2(
    localSeed: Buffer,
    remoteSeed: Buffer,
    authHash: Buffer,
    version: 1 | 2,
    timeout: number,
  ): Promise<KlapEncryptionSession> {
    const payload = handshake2SeedAuthHash(
      localSeed,
      remoteSeed,
      authHash,
      version,
    );
    const response = await httpPost(`${this.appUrl}/handshake2`, {
      body: payload,
      cookies: this.sessionCookie,
      timeout,
    });

    if (response.status !== 200) {
      throw new Error(
        `Device ${this.host} responded with ${response.status} to handshake2`,
      );
    }

    return new KlapEncryptionSession(localSeed, remoteSeed, authHash);
  }

  private async performHandshake(timeout: number): Promise<void> {
    this.log.debug(`KlapConnection(${this.description}): starting handshake`);
    this.reset();
    const { localSeed, remoteSeed, authHash, version } =
      await this.performHandshake1(timeout);
    this.encryptionSession = await this.performHandshake2(
      localSeed,
      remoteSeed,
      authHash,
      version,
      timeout,
    );
    this.handshakeDone = true;
    this.log.debug(`KlapConnection(${this.description}): handshake complete`);
  }

  async send(
    payload: string,
    port: number,
    host: string,
    { timeout }: { timeout: number },
  ): Promise<string> {
    this.port = port;
    this.host = host;

    return this.queue.add(async () => {
      if (!this.handshakeDone || this.handshakeSessionExpired()) {
        await this.performHandshake(timeout);
      }

      const session = this.encryptionSession;
      if (session == null) {
        throw new Error(
          `KLAP handshake did not establish a session with ${this.host}`,
        );
      }

      const { payload: encrypted, seq } = session.encrypt(payload);
      const response = await httpPost(`${this.appUrl}/request`, {
        body: encrypted,
        cookies: this.sessionCookie,
        timeout,
        params: { seq },
      });

      if (response.status !== 200) {
        if (response.status === 403) {
          this.handshakeDone = false;
        }
        throw new Error(
          `Device ${this.host} responded with ${response.status} to request with seq ${seq}`,
        );
      }

      try {
        return session.decrypt(response.body);
      } catch (err) {
        throw new Error(
          `Error trying to decrypt device ${this.host} response: ${String(
            err,
          )}`,
        );
      }
    });
  }
}
