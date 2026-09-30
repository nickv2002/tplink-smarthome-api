import { expect } from 'chai';
import http from 'http';
import type { AddressInfo } from 'net';

import {
  generateAuthHash,
  handshake1SeedAuthHash,
  KlapEncryptionSession,
} from '../../src/network/klap';
import KlapConnection from '../../src/network/klap-connection';

const credentials = { username: 'foo', password: 'bar' };
const noopLog = {
  debug() {},
  info() {},
  warn() {},
  error() {},
} as unknown as ConstructorParameters<typeof KlapConnection>[2];

interface FakeDevice {
  server: http.Server;
  port: number;
  counts: { handshake1: number; request: number };
}

/** Minimal KLAP v2 device; `requestStatuses` is consumed one entry per /request. */
function startFakeDevice(requestStatuses: number[]): Promise<FakeDevice> {
  const counts = { handshake1: 0, request: 0 };
  const authHash = generateAuthHash(credentials, 2);
  let localSeed = Buffer.alloc(0);
  const remoteSeed = Buffer.alloc(16, 0x22);
  let session: KlapEncryptionSession | undefined;

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      const path = (req.url ?? '').split('?')[0];
      if (path === '/app/handshake1') {
        counts.handshake1 += 1;
        localSeed = body;
        res.setHeader('Set-Cookie', 'TP_SESSIONID=abc;TIMEOUT=86400');
        res.end(
          Buffer.concat([
            remoteSeed,
            handshake1SeedAuthHash(localSeed, remoteSeed, authHash, 2),
          ]),
        );
      } else if (path === '/app/handshake2') {
        session = new KlapEncryptionSession(localSeed, remoteSeed, authHash);
        res.end();
      } else if (path === '/app/request') {
        counts.request += 1;
        // advance the device-side seq in lockstep with the client
        const { payload } = session?.encrypt('{"ok":1}') as { payload: Buffer };
        const status = requestStatuses.shift() ?? 200;
        res.statusCode = status;
        res.end(status === 200 ? payload : undefined);
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
  });

  return new Promise<FakeDevice>((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      resolve({ server, port: (server.address() as AddressInfo).port, counts });
    });
  });
}

describe('KlapConnection', function () {
  it('re-handshakes and retries once when an existing session gets a 403', async function () {
    const { server, port, counts } = await startFakeDevice([200, 403, 200]);
    const conn = new KlapConnection('127.0.0.1', port, noopLog, credentials);
    try {
      expect(
        await conn.send('{}', port, '127.0.0.1', { timeout: 1000 }),
      ).to.equal('{"ok":1}');
      expect(
        await conn.send('{}', port, '127.0.0.1', { timeout: 1000 }),
      ).to.equal('{"ok":1}');
      expect(counts.handshake1).to.equal(2);
      expect(counts.request).to.equal(3);
    } finally {
      conn.close();
      server.close();
    }
  });

  it('does not retry a 403 received on a session that was just established', async function () {
    const { server, port, counts } = await startFakeDevice([403, 200]);
    const conn = new KlapConnection('127.0.0.1', port, noopLog, credentials);
    try {
      let error: Error | undefined;
      try {
        await conn.send('{}', port, '127.0.0.1', { timeout: 1000 });
      } catch (err) {
        error = err as Error;
      }
      expect(error?.message).to.match(/responded with 403/);
      expect(counts.request).to.equal(1);
    } finally {
      conn.close();
      server.close();
    }
  });

  it('gives up if the retry after re-handshake is also a 403', async function () {
    const { server, port, counts } = await startFakeDevice([200, 403, 403]);
    const conn = new KlapConnection('127.0.0.1', port, noopLog, credentials);
    try {
      await conn.send('{}', port, '127.0.0.1', { timeout: 1000 });
      let error: Error | undefined;
      try {
        await conn.send('{}', port, '127.0.0.1', { timeout: 1000 });
      } catch (err) {
        error = err as Error;
      }
      expect(error?.message).to.match(/responded with 403/);
      expect(counts.request).to.equal(3);
    } finally {
      conn.close();
      server.close();
    }
  });
});
