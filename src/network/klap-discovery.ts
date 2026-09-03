import crypto from 'crypto';

import { isObjectLike } from '../utils';

export const DISCOVERY_PORT_2 = 20002;
export const DISCOVERY_PORT_3 = 20004;

export interface EncryptionScheme {
  is_support_https?: boolean;
  encrypt_type?: string;
  http_port?: number;
  lv?: number;
  new_klap?: number;
}

export interface NewDiscoveryResult {
  device_type: string;
  device_model: string;
  device_id: string;
  ip?: string;
  mac?: string;
  device_name?: string;
  firmware_version?: string;
  hardware_version?: string;
  hw_ver?: string;
  mgt_encrypt_schm?: EncryptionScheme;
  new_klap?: number;
}

let cachedDiscoveryQuery: Buffer | undefined;

/* eslint-disable no-bitwise */
function crc32Ieee(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc ^= buf[i] ?? 0;
    for (let j = 0; j < 8; j += 1) {
      crc = crc & 1 ? (crc >>> 1) ^ 0xedb88320 : crc >>> 1;
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}
/* eslint-enable no-bitwise */

/**
 * TDP probe used by python-kasa on UDP 20002/20004.
 *
 * Newer Kasa firmware (including KL125 1.1.1) no longer answers the legacy
 * XOR discovery packet on 9999. They respond to this probe instead and
 * advertise `encrypt_type=KLAP`.
 */
export function createNewDiscoveryQuery(): Buffer {
  if (cachedDiscoveryQuery) return cachedDiscoveryQuery;

  const { publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  const payload = Buffer.from(
    JSON.stringify({ params: { rsa_key: publicKey } }),
    'utf8',
  );

  const header = Buffer.alloc(16);
  header.writeUInt8(2, 0); // version
  header.writeUInt8(0, 1); // msg_type
  header.writeUInt16BE(1, 2); // op_code = probe
  header.writeUInt16BE(payload.length, 4);
  header.writeUInt8(17, 6); // flags
  header.writeUInt8(0, 7);
  header.writeUInt32BE(crypto.randomBytes(4).readUInt32BE(0), 8);
  header.writeUInt32BE(0x5a6b7c8d, 12);

  const query = Buffer.concat([header, payload]);
  query.writeUInt32BE(crc32Ieee(query), 12);
  cachedDiscoveryQuery = query;
  return query;
}

export function isNewDiscoveryPort(port: number): boolean {
  return port === DISCOVERY_PORT_2 || port === DISCOVERY_PORT_3;
}

function isNewDiscoveryResult(
  candidate: unknown,
): candidate is NewDiscoveryResult {
  return (
    isObjectLike(candidate) &&
    typeof candidate.device_type === 'string' &&
    typeof candidate.device_model === 'string' &&
    typeof candidate.device_id === 'string'
  );
}

export function parseNewDiscoveryMessage(
  msg: Buffer,
): NewDiscoveryResult | undefined {
  if (msg.length <= 16) return undefined;
  try {
    const parsed: unknown = JSON.parse(msg.subarray(16).toString('utf8'));
    if (
      isObjectLike(parsed) &&
      'result' in parsed &&
      isNewDiscoveryResult(parsed.result)
    ) {
      return parsed.result;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

export function isIotKlapDiscovery(result: NewDiscoveryResult): boolean {
  const family = result.device_type.split('.')[0];
  const encryptType = result.mgt_encrypt_schm?.encrypt_type;
  return family === 'IOT' && encryptType === 'KLAP';
}

export function getKlapHttpPort(result: NewDiscoveryResult): number {
  return result.mgt_encrypt_schm?.http_port ?? 80;
}

export function isKlapV2Scheme(scheme: EncryptionScheme | undefined): boolean {
  if (scheme == null) return true;
  if (scheme.new_klap) return true;
  return (scheme.lv ?? 1) >= 2;
}
