import crypto from 'crypto';

export type KlapVersion = 1 | 2;

export interface Credentials {
  username: string;
  password: string;
}

export const BLANK_CREDENTIALS: Credentials = {
  username: '',
  password: '',
};

/**
 * Factory-default local credentials used by some Kasa devices.
 * Values are stored base64-encoded to match python-kasa.
 */
export function getDefaultKasaCredentials(): Credentials {
  return {
    username: Buffer.from('a2FzYUB0cC1saW5rLm5ldA==', 'base64').toString(
      'utf8',
    ),
    password: Buffer.from('a2FzYVNldHVw', 'base64').toString('utf8'),
  };
}

export function md5(data: Buffer | string): Buffer {
  return crypto.createHash('md5').update(data).digest();
}

export function sha1(data: Buffer | string): Buffer {
  return crypto.createHash('sha1').update(data).digest();
}

export function sha256(data: Buffer | string): Buffer {
  return crypto.createHash('sha256').update(data).digest();
}

export function generateAuthHash(
  creds: Credentials,
  version: KlapVersion,
): Buffer {
  const username = Buffer.from(creds.username, 'utf8');
  const password = Buffer.from(creds.password, 'utf8');
  if (version >= 2) {
    return sha256(Buffer.concat([sha1(username), sha1(password)]));
  }
  return md5(Buffer.concat([md5(username), md5(password)]));
}

export function handshake1SeedAuthHash(
  localSeed: Buffer,
  remoteSeed: Buffer,
  authHash: Buffer,
  version: KlapVersion,
): Buffer {
  if (version >= 2) {
    return sha256(Buffer.concat([localSeed, remoteSeed, authHash]));
  }
  return sha256(Buffer.concat([localSeed, authHash]));
}

export function handshake2SeedAuthHash(
  localSeed: Buffer,
  remoteSeed: Buffer,
  authHash: Buffer,
  version: KlapVersion,
): Buffer {
  if (version >= 2) {
    return sha256(Buffer.concat([remoteSeed, localSeed, authHash]));
  }
  return sha256(Buffer.concat([remoteSeed, authHash]));
}

export interface MatchedKlapAuth {
  authHash: Buffer;
  version: KlapVersion;
}

/**
 * Identify which credential/hash version produced handshake1's server hash.
 *
 * Firmware 1.1.1 IOT bulbs advertise KLAP v2 (SHA-256/SHA-1). Older KLAP IOT
 * firmware used v1 (MD5). Trying both against the same handshake1 response
 * avoids picking the wrong transport the way python-kasa did before #1692.
 */
export function matchHandshake1Auth(
  localSeed: Buffer,
  remoteSeed: Buffer,
  serverHash: Buffer,
  credentials: Credentials,
): MatchedKlapAuth | undefined {
  const candidates: Array<{ creds: Credentials; version: KlapVersion }> = [];
  const versions: KlapVersion[] = [2, 1];
  const credentialSets = [credentials];
  const defaults = getDefaultKasaCredentials();
  if (
    credentials.username !== defaults.username ||
    credentials.password !== defaults.password
  ) {
    credentialSets.push(defaults);
  }
  if (
    credentials.username !== BLANK_CREDENTIALS.username ||
    credentials.password !== BLANK_CREDENTIALS.password
  ) {
    credentialSets.push(BLANK_CREDENTIALS);
  }

  versions.forEach((version) => {
    credentialSets.forEach((creds) => {
      candidates.push({ creds, version });
    });
  });

  return candidates
    .map(({ creds, version }) => {
      const authHash = generateAuthHash(creds, version);
      const expected = handshake1SeedAuthHash(
        localSeed,
        remoteSeed,
        authHash,
        version,
      );
      return expected.equals(serverHash) ? { authHash, version } : undefined;
    })
    .find((match) => match !== undefined);
}

function packSignedInt32(value: number): Buffer {
  const buf = Buffer.alloc(4);
  buf.writeInt32BE(value);
  return buf;
}

/**
 * AES-128-CBC session derived from the KLAP handshake seeds.
 */
export class KlapEncryptionSession {
  private readonly key: Buffer;

  private readonly ivPrefix: Buffer;

  private seq: number;

  private readonly sig: Buffer;

  constructor(localSeed: Buffer, remoteSeed: Buffer, userHash: Buffer) {
    this.key = sha256(
      Buffer.concat([Buffer.from('lsk'), localSeed, remoteSeed, userHash]),
    ).subarray(0, 16);

    const fullIv = sha256(
      Buffer.concat([Buffer.from('iv'), localSeed, remoteSeed, userHash]),
    );
    this.ivPrefix = fullIv.subarray(0, 12);
    this.seq = fullIv.subarray(fullIv.length - 4).readInt32BE(0);

    this.sig = sha256(
      Buffer.concat([Buffer.from('ldk'), localSeed, remoteSeed, userHash]),
    ).subarray(0, 28);
  }

  encrypt(msg: Buffer | string): { payload: Buffer; seq: number } {
    this.seq += 1;
    const iv = Buffer.concat([this.ivPrefix, packSignedInt32(this.seq)]);
    const cipher = crypto.createCipheriv('aes-128-cbc', this.key, iv);
    const plaintext = typeof msg === 'string' ? Buffer.from(msg, 'utf8') : msg;
    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);
    const signature = sha256(
      Buffer.concat([this.sig, packSignedInt32(this.seq), ciphertext]),
    );
    return { payload: Buffer.concat([signature, ciphertext]), seq: this.seq };
  }

  decrypt(msg: Buffer): string {
    const iv = Buffer.concat([this.ivPrefix, packSignedInt32(this.seq)]);
    const decipher = crypto.createDecipheriv('aes-128-cbc', this.key, iv);
    const plaintext = Buffer.concat([
      decipher.update(msg.subarray(32)),
      decipher.final(),
    ]);
    return plaintext.toString('utf8');
  }
}
